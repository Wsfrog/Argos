import csv
import io
import json
import os
import subprocess
import tempfile
import uuid
from collections import Counter, OrderedDict
from datetime import datetime
from xml.sax.saxutils import escape

from flask import Flask, Response, abort, render_template, request

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 2 * 1024 * 1024  

TRIVY_BIN = os.environ.get("TRIVY_BIN", "trivy")
TIMEOUT = 300
OFFLINE = os.environ.get("ARGOS_MAVEN_REMOTO") != "1"
SKIP_DB_UPDATE = os.environ.get("ARGOS_SKIP_DB_UPDATE") == "1"


MANIFESTOS = [
    "pom.xml", "requirements.txt", "package-lock.json", "yarn.lock",
    "gradle.lockfile", "composer.lock", "go.mod", "Gemfile.lock",
    "Cargo.lock", "poetry.lock", "Pipfile.lock",
]
ORDEM = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"]
ENV_OK = ["PATH", "SYSTEMROOT", "USERPROFILE", "LOCALAPPDATA", "APPDATA",
          "HOME", "TEMP", "TMP", "HTTP_PROXY", "HTTPS_PROXY", "NO_PROXY"]

RELATORIOS = OrderedDict()  # Apenas Guarde Na memoria Six Seven aura mais ego 


def env_limpo():
    """Passa ao Trivy só o necessário, sem chaves de API ou tokens."""
    return {k: v for k, v in os.environ.items() if k.upper() in ENV_OK}


def rodar_trivy(nome, conteudo):
    with tempfile.TemporaryDirectory() as tmp:
        if nome in MANIFESTOS:
            caminho = os.path.join(tmp, nome)
            modo, alvo = "fs", tmp
        else:  
            caminho = os.path.join(tmp, "bom.json")
            modo, alvo = "sbom", caminho
        with open(caminho, "wb") as f:
            f.write(conteudo)
        cmd = [TRIVY_BIN, modo, "--format", "json", "--quiet",
               "--scanners", "vuln"]
        if OFFLINE:
            cmd.append("--offline-scan")
        if SKIP_DB_UPDATE:
            cmd.append("--skip-db-update")
        cmd.append(alvo)
        r = subprocess.run(cmd, capture_output=True, text=True,
                           timeout=TIMEOUT, env=env_limpo())
    if r.returncode != 0:
        raise RuntimeError((r.stderr or "Erro desconhecido no Trivy.")[-600:])
    return json.loads(r.stdout or "{}")


def extrair(dados):
    vulns = []
    for res in dados.get("Results") or []:
        for v in res.get("Vulnerabilities") or []:
            url = v.get("PrimaryURL") or ""
            vulns.append({
                "pacote": v.get("PkgName", ""),
                "versao": v.get("InstalledVersion", ""),
                "cve": v.get("VulnerabilityID", ""),
                "sev": v.get("Severity", "UNKNOWN"),
                "correcao": v.get("FixedVersion") or "-",
                "titulo": v.get("Title") or "",
                "url": url if url.startswith("https://") else "",
            })
    vulns.sort(key=lambda x: (ORDEM.index(x["sev"]) if x["sev"] in ORDEM else 99,
                              x["pacote"]))
    return vulns


def guardar(nome, vulns):
    rid = uuid.uuid4().hex[:10]
    RELATORIOS[rid] = {"arquivo": nome, "vulns": vulns,
                       "resumo": Counter(v["sev"] for v in vulns)}
    while len(RELATORIOS) > 50:
        RELATORIOS.popitem(last=False)
    return rid


@app.get("/")
def index():
    return render_template("index.html", manifestos=MANIFESTOS, erro=None)


@app.post("/scan")
def scan():
    arq = request.files.get("arquivo")
    texto = (request.form.get("texto") or "").strip()
    try:
        if arq and arq.filename:
            nome = os.path.basename(arq.filename)
            conteudo = arq.read()
            if nome not in MANIFESTOS and not nome.lower().endswith(".json"):
                raise ValueError("Arquivo não suportado. Envie um dos manifestos "
                                 "da lista ou um SBOM em .json.")
        elif texto:
            nome = request.form.get("tipo", "")
            if nome not in MANIFESTOS:
                raise ValueError("Escolha o tipo do conteúdo colado.")
            conteudo = texto.encode("utf-8")
        else:
            raise ValueError("Envie um arquivo ou cole o conteúdo.")
        vulns = extrair(rodar_trivy(nome, conteudo))
    except FileNotFoundError:
        erro = "Trivy não encontrado. Ajuste o PATH ou defina TRIVY_BIN."
    except subprocess.TimeoutExpired:
        erro = "O Trivy demorou demais e foi interrompido."
    except (ValueError, RuntimeError, json.JSONDecodeError) as e:
        erro = str(e)
        if "429" in erro:
            erro = ("O Maven Central bloqueou seu IP temporariamente (429). "
                    "Aguarde cerca de 30 min sem tentar de novo (novas tentativas "
                    "estendem o bloqueio) ou desative ARGOS_MAVEN_REMOTO.")
    else:
        rid = guardar(nome, vulns)
        return render_template("relatorio.html", rid=rid, **RELATORIOS[rid],
                               ordem=ORDEM)
    return render_template("index.html", manifestos=MANIFESTOS, erro=erro), 400


@app.get("/relatorio/<rid>")
def ver(rid):
    r = RELATORIOS.get(rid) or abort(404)
    return render_template("relatorio.html", rid=rid, **r, ordem=ORDEM)


@app.get("/relatorio/<rid>.json")
def baixar_json(rid):
    r = RELATORIOS.get(rid) or abort(404)
    return Response(json.dumps(r["vulns"], ensure_ascii=False, indent=2),
                    mimetype="application/json",
                    headers={"Content-Disposition": f"attachment; filename=relatorio-{rid}.json"})


@app.get("/relatorio/<rid>.csv")
def baixar_csv(rid):
    r = RELATORIOS.get(rid) or abort(404)
    buf = io.StringIO()
    campos = ["pacote", "versao", "cve", "sev", "correcao", "titulo", "url"]
    w = csv.DictWriter(buf, fieldnames=campos)
    w.writeheader()
    w.writerows(r["vulns"])
    return Response(buf.getvalue(), mimetype="text/csv",
                    headers={"Content-Disposition": f"attachment; filename=relatorio-{rid}.csv"})


@app.get("/relatorio/<rid>.pdf")
def baixar_pdf(rid):
    from reportlab.lib import colors
    from reportlab.lib.pagesizes import A4, landscape
    from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
    from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle

    r = RELATORIOS.get(rid) or abort(404)
    cores = {"CRITICAL": "#b00020", "HIGH": "#c2410c", "MEDIUM": "#a16207"}
    base = getSampleStyleSheet()["Normal"]
    peq = ParagraphStyle("peq", parent=base, fontSize=8, leading=10)
    titulo = ParagraphStyle("t", parent=base, fontName="Helvetica-Bold", fontSize=16, leading=20)
    mudo = ParagraphStyle("m", parent=base, fontSize=9, textColor=colors.HexColor("#6b6b6b"))

    resumo = " · ".join(f"{r['resumo'][s]} {s.lower()}" for s in ORDEM if r["resumo"][s])
    story = [
        Paragraph("Relatório de vulnerabilidades", titulo),
        Paragraph(f"{escape(r['arquivo'])} · {datetime.now():%d/%m/%Y %H:%M}", mudo),
        Paragraph(escape(resumo) or "Nenhuma vulnerabilidade encontrada.", mudo),
        Spacer(1, 14),
    ]
    if r["vulns"]:
        linhas = [["Severidade", "Pacote", "Versão", "CVE", "Corrigir em"]]
        for v in r["vulns"]:
            cor = cores.get(v["sev"], "#6b6b6b")
            linhas.append([
                Paragraph(f'<font color="{cor}"><b>{escape(v["sev"].lower())}</b></font>', peq),
                Paragraph(escape(v["pacote"]), peq),
                Paragraph(escape(v["versao"]), peq),
                Paragraph(escape(v["cve"]), peq),
                Paragraph(escape(v["correcao"]), peq),
            ])
        t = Table(linhas, colWidths=[70, 210, 110, 120, 170], repeatRows=1)
        t.setStyle(TableStyle([
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, 0), 8),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.HexColor("#6b6b6b")),
            ("LINEBELOW", (0, 0), (-1, -1), 0.4, colors.HexColor("#e4e4e4")),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ]))
        story.append(t)

    buf = io.BytesIO()
    SimpleDocTemplate(buf, pagesize=landscape(A4), leftMargin=36, rightMargin=36,
                      topMargin=36, bottomMargin=36).build(story)
    return Response(buf.getvalue(), mimetype="application/pdf",
                    headers={"Content-Disposition": f"attachment; filename=relatorio-{rid}.pdf"})


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=False)
