<div align="center">

<img src="https://capsule-render.vercel.app/api?type=waving&color=0:0f2027,50:203a43,100:2c5364&height=200&section=header&text=KubeGuard&fontSize=70&fontColor=ffffff&animation=fadeIn&fontAlignY=38&desc=Scan%20Docker%20images%20and%20Kubernetes%20manifests%20for%20misconfigurations%20and%20CVEs&descAlignY=58&descSize=16" />

<a href="https://github.com/Abdulgeni/kubeguard/actions/workflows/ci.yml">
  <img src="https://github.com/Abdulgeni/kubeguard/actions/workflows/ci.yml/badge.svg" alt="CI" />
</a>
<img src="https://img.shields.io/badge/python-3.11%20%7C%203.12%20%7C%203.13-blue?logo=python&logoColor=white" alt="Python" />
<img src="https://img.shields.io/badge/tests-361%20passing-brightgreen?logo=pytest&logoColor=white" alt="Tests" />
<img src="https://img.shields.io/badge/coverage-97%25-brightgreen" alt="Coverage" />
<img src="https://img.shields.io/badge/license-MIT-green" alt="License" />
<img src="https://img.shields.io/badge/rules-13-informational" alt="Rules" />

<br /><br />

<a href="#-installation">
  <img src="https://readme-typing-svg.demolab.com?font=Fira+Code&weight=600&size=20&pause=800&color=2C5364&center=true&vCenter=true&width=700&lines=Detects+root+containers+%26+missing+securityContext;Finds+CVEs+via+the+NVD+API+with+CPE+matching;Enforces+CIS+Kubernetes+Benchmark+rules;Outputs+table%2C+JSON%2C+or+SARIF+for+Code+Scanning" alt="Typing SVG" />
</a>

</div>

---

<div align="center">

### 🛡️ A production-grade security scanner you can run in one command

</div>

```bash
kubeguard scan image nginx:1.25 --output json
kubeguard scan k8s ./manifests --fail-on high
kubeguard scan all --config config.yaml --output sarif --output-file kubeguard.sarif
```

<div align="center">

_KubeGuard scans local Docker images and Kubernetes manifests, reports findings with severity and remediation advice, and exits non-zero so it drops straight into CI._

</div>

---

## ✨ Features

<table>
<tr>
<td width="50%" valign="top">

### 🐳 Docker Image Scanning

- **Root user detection** across `USER` instructions and image history
- **Secret exposure** in `Config.Env` (names only — values never leak)
- **Outdated base image** heuristic with configurable age threshold
- **Real CVE lookups** against the NVD API v2.0 via CPE matching
- **Static package enumeration** — reads dpkg/apk databases from layer tarballs *without ever running a container*

</td>
<td width="50%" valign="top">

### ☸️ Kubernetes Manifest Scanning

- **Pod security** — `runAsNonRoot`, `allowPrivilegeEscalation`, `privileged`
- **Resource limits** — CPU and memory enforcement
- **Volume safety** — `hostPath` detection
- **Secret hygiene** — literal values in env vars
- **RBAC audit** — wildcard verbs and resources
- **Offline** — pure YAML parsing, no cluster access, no `kubeconfig`

</td>
</tr>
<tr>
<td width="50%" valign="top">

### 📊 Three Output Formats

- **Table** — human-readable, color-coded by severity
- **JSON** — machine-parseable with summary and metadata
- **SARIF 2.1.0** — drop-in for GitHub Code Scanning

</td>
<td width="50%" valign="top">

### 🔌 Plugin Architecture

- Rules are auto-discovered from `kubeguard.rules`
- Drop a `Rule` subclass in — no registration code
- Enable/disable per rule, override severities, set per-rule options — all via YAML config

</td>
</tr>
<tr>
<td width="50%" valign="top">

### 🚀 CI-Ready

- Exit codes: `0` clean, `1` findings, `2` errors
- `--fail-on <severity>` gate for pipelines
- `--output-file` for artifacts
- SARIF works with `github/codeql-action/upload-sarif`

</td>
<td width="50%" valign="top">

### 🔒 Safe by Design

- Never executes untrusted images by default
- NVD rate limiting with exponential backoff
- SQLite cache with TTL
- `SafeLoader` YAML parsing (no arbitrary object construction)

</td>
</tr>
</table>

---

## 🚀 Installation

### Via pipx (recommended for CLI use)

```bash
pipx install git+https://github.com/Abdulgeni/kubeguard.git
```

### Via pip (development)

```bash
git clone https://github.com/Abdulgeni/kubeguard.git
cd kubeguard
python -m venv .venv
source .venv/Scripts/activate    # Windows Git Bash
# source .venv/bin/activate      # Linux / macOS
pip install -e ".[dev]"
```

**Requires Python 3.11 or newer.**

---

## 🎬 Usage

<table>
<tr>
<td width="50%">

### Scan a Docker image

```bash
kubeguard scan image nginx:1.25
```

Scans a local image (pull it first with `docker pull`). Produces findings for root user, env secrets, outdated base, and CVEs.

</td>
<td width="50%">

### Scan Kubernetes manifests

```bash
kubeguard scan k8s ./manifests
```

Reads a file or a directory tree of `.yaml`/`.yml`. Handles multi-document YAML and `kind: List`.

</td>
</tr>
<tr>
<td width="50%">

### Scan everything from config

```bash
kubeguard scan all --config config.yaml
```

Uses `docker.images` and `kubernetes.paths` from the config file. See `config.example.yaml`.

</td>
<td width="50%">

### List rules

```bash
kubeguard rules
```

Shows every rule, its severity, and whether it is currently enabled.

</td>
</tr>
</table>

### Command Options

| Flag | Description |
|:---|:---|
| `--output`, `-o` | `table` \| `json` \| `sarif` (default: table) |
| `--fail-on` | Exit with code `1` if any finding is at or above this severity |
| `--config`, `-c` | Path to a YAML config file |
| `--no-cache` | Bypass the NVD cache |
| `--output-file` | Write the report to a file instead of stdout |
| `--allow-container-exec` | **Opt-in.** List packages by running the image's own package manager (see security notes) |
| `--verbose`, `-v` | Verbose logging on stderr |

### Exit Codes

| Code | Meaning |
|:---:|:---|
| `0` | Clean scan |
| `1` | A finding at or above `--fail-on` |
| `2` | Usage error, config error, unreadable file, image not found, or a crashed rule |

_If findings and errors both occur, `1` wins. An error never causes a silent pass._

---

## 🧪 Rules

### Docker

| ID | Severity | Checks |
|:---|:---:|:---|
| `KG-DOCKER-001` | 🟠 High | Image runs as root |
| `KG-DOCKER-002` | 🟠 High | Credential-like env vars with baked-in values |
| `KG-DOCKER-003` | 🟡 Medium | Outdated base image (`max_age_days`, default 180) |
| `KG-DOCKER-004` | 🔴 from CVSS | Installed package has a known CVE |
| `KG-DOCKER-005` | 🔵 Info | Package inventory unavailable, so CVE checks did not run |
| `KG-DOCKER-006` | 🔵 Info | CVE results incomplete (cap reached or NVD lookups failed) |

### Kubernetes

| ID | Severity | Checks |
|:---|:---:|:---|
| `KG-K8S-001` | 🟡 Medium | `runAsNonRoot` is not true |
| `KG-K8S-002` | 🟡 Medium | `allowPrivilegeEscalation` is not false |
| `KG-K8S-003` | 🟢 Low | CPU or memory limits missing |
| `KG-K8S-004` | 🔴 Critical | Privileged container |
| `KG-K8S-005` | 🟠 High | `hostPath` volume mounted |
| `KG-K8S-006` | 🟠 High | Credential-like env var with a literal value |
| `KG-K8S-007` | 🟠 High | RBAC `*` verbs or resources |

**Severity mapping for CVEs:** CVSS ≥ 9.0 → Critical · ≥ 7.0 → High · ≥ 4.0 → Medium · > 0 → Low · unscored → Info.

**Supported K8s kinds:** Pod, Deployment, StatefulSet, DaemonSet, ReplicaSet, ReplicationController, Job, CronJob, Role, ClusterRole. Helm templates are not rendered.

---

## ⚙️ Configuration

Copy `config.example.yaml` and edit:

```yaml
disabled_rules: [KG-K8S-003]
severity_overrides: {KG-DOCKER-003: low}
rule_options:
  KG-DOCKER-003:
    max_age_days: 180
fail_on: high
output: table

cache:
  enabled: true
  ttl_hours: 24

docker:
  images: [alpine:3.19]
  allow_container_exec: false
  keyword_fallback: true
  max_cve_findings: 50

kubernetes:
  paths: [examples/k8s]

sarif:
  docker_artifact_uri: Dockerfile
```

Every key is validated. Typos fail loudly instead of being silently ignored.

---

## 🔒 Package Enumeration and `--allow-container-exec`

CVE checks need the packages installed in an image. **By default KubeGuard reads the package databases (dpkg, apk) straight out of the image's layer tarballs via `docker save`. It never creates or starts a container.** Extracted data stays in memory; the archive is spooled to a temp file that is deleted afterwards.

### Static limits

- **RPM databases** (BerkeleyDB/SQLite header blobs) are detected but not parsed.
- **zstd-compressed layers** are not supported by the stdlib tar reader.

When static enumeration cannot produce a package list, KubeGuard emits an **Info finding (`KG-DOCKER-005`)** explaining why. It never skips CVE checks silently.

### The security trade-off

`--allow-container-exec` runs `dpkg-query`, `apk info`, or `rpm -qa` **inside a container created from the image**, which executes binaries from the very image you're scanning. The container is hardened — no network, read-only filesystem, all capabilities dropped, `no-new-privileges`, memory/PID limits — but it is still untrusted code. **Use only on images you trust.**

---

## 🌐 NVD API and CVE Accuracy

| | |
|:---|:---|
| **Rate limits** | 5 req / 30 s without key · **50 req / 30 s** with key |
| **Get a key** | https://nvd.nist.gov/developers/request-an-api-key (free) |
| **Set it** | `export NVD_API_KEY=your-key-here` |
| **Cache location** | `~/.cache/kubeguard/nvd.db` (Linux/macOS) · `%LOCALAPPDATA%\kubeguard\nvd.db` (Windows) |
| **Override** | `export KUBEGUARD_CACHE_DIR=/custom/path` |
| **TTL** | 24 hours (configurable) |

**Matching strategy:**
1. **CPE-first.** Builds CPE 2.3 names from a curated package map (open the file at `src/kubeguard/integrations/cpe.py` to extend it). Marked `confidence: high`.
2. **Keyword fallback.** For unmapped packages, searches NVD by name + upstream version. Marked `confidence: low`.

**Caveats:**
- Matching uses **upstream versions**. Distro backports are not considered, so some findings may be false positives.
- Output is capped at **50 CVE findings per image** (highest CVSS first). The rest are summarized in `KG-DOCKER-006`.
- A circuit breaker stops after 3 consecutive NVD failures to avoid hanging on network issues.

---

## 🔁 CI / Code Scanning

```yaml
name: Security

on: [push, pull_request]

jobs:
  kubeguard:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      security-events: write
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: "3.12"
      - run: pip install git+https://github.com/Abdulgeni/kubeguard.git
      - name: Scan Kubernetes manifests
        run: |
          kubeguard scan k8s ./manifests \
            --output sarif \
            --output-file kubeguard.sarif \
            --fail-on high
      - uses: github/codeql-action/upload-sarif@v3
        if: always()
        with:
          sarif_file: kubeguard.sarif
```

Findings appear directly in the **Security** tab of your repository with severity, file, line, and remediation.

---

## 📐 Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                          CLI (typer)                        │
│   scan image · scan k8s · scan all · rules · --fail-on …    │
└──────────────────────────┬──────────────────────────────────┘
                           │ loads config, wires dependencies
        ┌──────────────────┼──────────────────┐
        ▼                  ▼                  ▼
   ┌─────────┐        ┌─────────┐       ┌──────────┐
   │ Docker  │        │   K8s   │       │ Reporters│
   │ Scanner │        │ Scanner │       │ table    │
   └────┬────┘        └────┬────┘       │ json     │
        │                  │            │ sarif    │
        │                  │            └──────────┘
        ▼                  ▼
   ┌──────────────────────────────────┐
   │         Rule Registry            │
   │  auto-discovery · enable/disable │
   │  severity overrides · options    │
   └──────────┬───────────────────────┘
              │
              ▼
   ┌──────────────────────────────────┐    ┌──────────────┐
   │            Rules/                │───▶│  NVD Client  │
   │  docker/  ·  k8s/                │    │  CPE matcher │
   │  one file per rule               │    │  SQLite cache│
   └──────────────────────────────────┘    └──────────────┘
```

---

## 🛠️ Development

```bash
# Clone and install
git clone https://github.com/Abdulgeni/kubeguard.git
cd kubeguard
python -m venv .venv && source .venv/Scripts/activate
pip install -e ".[dev]"

# Test
pytest --cov=kubeguard --cov-report=term-missing
ruff check .
mypy src
```

### Project Layout

```
src/kubeguard/
├── cli.py                 # Typer app and commands
├── core/                  # Models, rule ABC, registry, config
├── scanners/              # Docker and Kubernetes scanners
├── integrations/          # NVD client, CPE builder, cache
├── reporters/             # table, json, sarif
└── rules/                 # auto-discovered plugins
    ├── docker/
    └── k8s/

tests/                     # 361 tests, 97% coverage
examples/k8s/              # Insecure and secure sample manifests
```

### Adding a Rule

1. Create a file under `src/kubeguard/rules/<scanner>/`.
2. Subclass `kubeguard.core.rule.Rule`.
3. Set `id`, `name`, `severity`, `description`, `remediation`, `target_type`.
4. Implement `check(target) -> Finding | None`.
5. Add tests under `tests/rules/<scanner>/`.

Rule IDs follow `KG-<AREA>-<NNN>`, e.g. `KG-DOCKER-004`, `KG-K8S-007`. The registry discovers them automatically on import.

---

## 📜 License

MIT — see [LICENSE](LICENSE).

---

<div align="center">

<img src="https://capsule-render.vercel.app/api?type=waving&color=0:2c5364,50:203a43,100:0f2027&height=120&section=footer" />

**Built with 🐍 Python, ☸️ Kubernetes, and 🐳 Docker**

_If KubeGuard helped you ship safer containers, consider giving it a ⭐_

</div>