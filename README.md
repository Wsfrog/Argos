# Argos

Aplicação web em Flask para Software Composition Analysis (SCA). Recebe um manifesto de dependências ou um SBOM, delega a análise ao [Trivy](https://github.com/aquasecurity/trivy) e apresenta o resultado em um relatório filtrável, com versão corrigida por vulnerabilidade e exportação em PDF, CSV e JSON.

## Escopo

- Entrada: manifesto de dependências (`pom.xml`, `requirements.txt` etc.) ou SBOM em JSON (CycloneDX/SPDX), via upload ou conteúdo colado.
- Processamento: execução do Trivy (`fs` ou `sbom`) com saída JSON, normalização dos resultados e ordenação por severidade.
- Saída: relatório HTML com filtros e busca, mais exportação em PDF, CSV e JSON.
- O Argos não implementa detecção própria. A qualidade do resultado depende do banco de vulnerabilidades do Trivy.

## Arquitetura

```
Navegador ──POST /scan──> Flask ──subprocess──> Trivy ──> banco de vulnerabilidades
                            │                      │
                            │<──── JSON (stdout) ──┘
                            │
                     normalização + ordenação
                            │
                  armazenamento em memória (id)
                            │
            HTML / PDF (reportlab) / CSV / JSON
```

Fluxo de uma análise:

1. O arquivo (ou texto) é validado contra uma lista fixa de nomes de manifesto.
2. O conteúdo é gravado em um diretório temporário, com o nome definido pelo servidor, e nunca pelo cliente.
3. O Trivy é invocado com lista de argumentos, sem shell:
   `trivy fs|sbom --format json --quiet --scanners vuln --offline-scan [--skip-db-update] <alvo>`
4. O JSON é percorrido em `Results[].Vulnerabilities[]` e cada item é reduzido aos campos `PkgName`, `InstalledVersion`, `VulnerabilityID`, `Severity`, `FixedVersion`, `Title` e `PrimaryURL`.
5. Os itens são ordenados por severidade (`CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `UNKNOWN`) e, como desempate, por nome de pacote.
6. O relatório recebe um identificador aleatório e fica disponível nas rotas de visualização e exportação.

## Requisitos

- Python 3.10 ou superior
- Trivy instalado e acessível no `PATH` (desenvolvido e testado com a versão 0.74.0)
- Acesso à internet no primeiro uso, para o download do banco de vulnerabilidades do Trivy. Depois disso, `ARGOS_SKIP_DB_UPDATE=1` permite operar sem rede (o banco deixa de ser atualizado)

Dependências Python: `Flask` e `reportlab`.

## Instalação

```
git clone https://github.com/Wsfrog/Argos-sca.git
cd Argos-sca
python -m venv .venv
.venv\Scripts\activate          # Linux/macOS: source .venv/bin/activate
pip install -r requirements.txt
python app.py
```

A aplicação escuta em `http://127.0.0.1:5000`.

Instalação do Trivy no Windows:

```
winget install AquaSecurity.Trivy
trivy --version
```

## Configuração

| Variável                | Padrão  | Descrição                                                        |
|-------------------------|---------|------------------------------------------------------------------|
| `TRIVY_BIN`             | `trivy` | Caminho do executável do Trivy                                   |
| `ARGOS_MAVEN_REMOTO`    | não definida | Com valor `1`, remove `--offline-scan` e permite ao Trivy resolver POMs no Maven Central |
| `ARGOS_SKIP_DB_UPDATE`  | não definida | Com valor `1`, adiciona `--skip-db-update` e usa apenas o banco de vulnerabilidades já baixado |

Constantes em `app.py`:

| Constante        | Valor       | Descrição                                     |
|------------------|-------------|-----------------------------------------------|
| `MAX_CONTENT_LENGTH` | 2 MB    | Tamanho máximo da requisição                  |
| `TIMEOUT`        | 300 s       | Tempo limite de execução do Trivy             |
| `MANIFESTOS`     | lista fixa  | Nomes de arquivo aceitos                      |

## Formatos suportados

Manifestos aceitos pelo nome exato: `pom.xml`, `requirements.txt`, `package-lock.json`, `yarn.lock`, `gradle.lockfile`, `composer.lock`, `go.mod`, `Gemfile.lock`, `Cargo.lock`, `poetry.lock`, `Pipfile.lock`.

Qualquer outro arquivo `.json` é tratado como SBOM e analisado com `trivy sbom`. Um SBOM CycloneDX para Python pode ser gerado com:

```
python -m cyclonedx_py requirements requirements.txt --output-format JSON --output-file bom.json
```

## Rotas

| Método | Rota                     | Descrição                                   |
|--------|--------------------------|---------------------------------------------|
| GET    | `/`                      | Formulário de envio                         |
| POST   | `/scan`                  | Executa a análise e renderiza o relatório   |
| GET    | `/relatorio/<id>`        | Relatório HTML                              |
| GET    | `/relatorio/<id>.pdf`    | Exportação em PDF                           |
| GET    | `/relatorio/<id>.csv`    | Exportação em CSV                           |
| GET    | `/relatorio/<id>.json`   | Exportação em JSON                          |

Parâmetros de `POST /scan` (`multipart/form-data`): `arquivo` (upload), ou `texto` mais `tipo` (conteúdo colado).

## Considerações de segurança

- Sem shell: o Trivy é chamado via `subprocess.run` com lista de argumentos. Não há concatenação de entrada do usuário em comandos.
- Nome de arquivo controlado pelo servidor: o arquivo é gravado com nome de uma lista fixa (ou `bom.json` para SBOM) dentro de um diretório temporário, o que elimina path traversal.
- Ambiente reduzido: o processo do Trivy recebe apenas as variáveis de ambiente necessárias (`PATH`, `SYSTEMROOT`, `USERPROFILE`, `LOCALAPPDATA`, `APPDATA`, `HOME`, `TEMP`, `TMP`, variáveis de proxy). Chaves de API e tokens presentes no ambiente do Flask não são repassados.
- Limites de recurso: tamanho máximo de requisição e timeout de execução.
- Saída escapada: o autoescape do Jinja2 está ativo e o PDF usa `xml.sax.saxutils.escape` antes de montar os parágrafos.
- Links externos: apenas URLs iniciadas por `https://` são renderizadas como link, com `rel="noopener noreferrer"`.
- Escuta local: o servidor é vinculado a `127.0.0.1`.
- Cadeia de suprimentos do Trivy: em março de 2026 houve um comprometimento de releases do Trivy (versões 0.69.4 a 0.69.6 e imagens associadas). Verifique a versão instalada com `trivy --version`, baixe apenas de fontes oficiais e fixe a versão em ambientes automatizados.

## Resolução de dependências Maven

A aplicação executa o Trivy com `--offline-scan` por padrão. Com essa flag o Trivy não consulta repositórios Maven remotos para resolver dependências. O banco de vulnerabilidades continua sendo baixado e atualizado normalmente.

Motivação: ao analisar um `pom.xml`, o Trivy resolve dependências transitivas baixando POMs do Maven Central quando eles não estão no cache local (`~/.m2`). Com o cache vazio, o limite de requisições por IP é atingido rapidamente e o Trivy encerra com `429 Too Many Requests` e um `Retry-After` (tipicamente cerca de 30 minutos, estendido por novas tentativas durante o bloqueio).

Consequência: com o cache local vazio, dependências transitivas de um `pom.xml` podem não ser resolvidas e o resultado pode ficar incompleto. Para cobertura completa sem acesso à rede:

1. Popular o cache local antes da análise, executando `mvn dependency:resolve` no projeto.
2. Ou analisar um SBOM gerado previamente, que já contém a árvore de dependências resolvida.

Essa configuração não afeta o banco de vulnerabilidades, que continua sendo atualizado pelo Trivy, exceto com `ARGOS_SKIP_DB_UPDATE=1`.

## Limitações conhecidas

- Sem autenticação e sem proteção CSRF. A aplicação não deve ser exposta fora de `localhost` sem esses controles.
- Os relatórios ficam em memória (os 50 mais recentes) e são perdidos ao reiniciar o processo.
- Apenas o scanner de vulnerabilidades do Trivy está habilitado (`--scanners vuln`). Licenças, misconfiguration e secrets não são analisados.
- Vulnerabilidades sem `FixedVersion` no banco do Trivy aparecem como "sem correção".
- A severidade reportada é a do banco de vulnerabilidades, sem ponderação por exploração real ou contexto da aplicação.

## Estrutura do projeto

```
.
├── app.py                  # rotas, execução do Trivy, normalização e exportações
├── requirements.txt
├── static/
│   └── style.css
└── templates/
    ├── base.html
    ├── index.html          # formulário de envio
    └── relatorio.html      # relatório com filtros e busca
```

## Licença

Distribuído sob a licença MIT.
