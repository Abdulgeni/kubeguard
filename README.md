# KubeGuard

Scans local Docker images and Kubernetes manifests for security misconfigurations and known CVEs.

## Install

```bash
pip install -e ".[dev]"      # Python 3.11+
```

## Usage

```bash
kubeguard scan image nginx:1.25 --output json
kubeguard scan k8s ./manifests --fail-on high
kubeguard scan all --config config.yaml --output sarif --output-file kubeguard.sarif
kubeguard rules                      # list rules and whether they are enabled
```

Options: `--output table|json|sarif`, `--fail-on <severity>`, `--config <file>`, `--no-cache`,
`--output-file <path>`, `--allow-container-exec` (images only), `-v/--verbose`.
See `config.example.yaml` for every config key.

**Exit codes:** `0` clean, `1` a finding at or above `--fail-on`, `2` usage or tool errors
(bad config, unreadable file, image not found, crashed rule). If both apply, `1` wins.
A target that could not be scanned never passes silently: it appears in the report's errors.

## Rules

| ID | Severity | Checks |
|---|---|---|
| KG-DOCKER-001 | High | Image runs as root |
| KG-DOCKER-002 | High | Credential-like env vars with baked-in values |
| KG-DOCKER-003 | Medium | Outdated base image (age heuristic, `max_age_days`) |
| KG-DOCKER-004 | from CVSS | Installed package has a known CVE (>=9 critical, >=7 high, >=4 medium, >0 low) |
| KG-DOCKER-005 | Info | Package inventory unavailable, so CVE checks did not run |
| KG-DOCKER-006 | Info | CVE results incomplete (cap reached or NVD lookups failed) |
| KG-K8S-001 | Medium | `runAsNonRoot` is not true |
| KG-K8S-002 | Medium | `allowPrivilegeEscalation` is not false |
| KG-K8S-003 | Low | CPU or memory limits missing |
| KG-K8S-004 | Critical | Privileged container |
| KG-K8S-005 | High | `hostPath` volume |
| KG-K8S-006 | High | Credential-like env var with a literal value |
| KG-K8S-007 | High | RBAC `*` verbs or resources |

Rules are plugins: drop a `Rule` subclass into `src/kubeguard/rules/` and it is discovered automatically.
K8s findings are aggregated per resource and list the affected containers.
Kubernetes scanning is offline (Pod, Deployment, StatefulSet, DaemonSet, ReplicaSet,
ReplicationController, Job, CronJob, Role, ClusterRole; multi-document YAML and `kind: List`).
Helm templates are not rendered.

## Package enumeration and `--allow-container-exec`

CVE checks need the packages installed in an image. By default KubeGuard reads the package databases
(dpkg, apk) straight out of the image's layer tarballs (`docker save`). It **never creates or starts a
container**. Extracted data stays in memory; the archive is spooled to a temporary file that is deleted
afterwards.

Static limits: RPM databases and zstd-compressed layers are unsupported. The scan then reports an Info
finding (`KG-DOCKER-005`) instead of silently skipping CVEs.

### Security trade-off

`--allow-container-exec` runs `dpkg-query`, `apk info` or `rpm -qa` **inside a container created from
the image**, which executes binaries from the image you are scanning. The container has no network, a
read-only filesystem, all capabilities dropped, `no-new-privileges`, and memory/PID limits, but it is
still untrusted code. Use the flag only on images you trust.

> **Portability note:** the opt-in runtime path relies on `entrypoint=[""]` in the Docker SDK to reset
> the image ENTRYPOINT. This is known to work with docker-py 7.x. Very old docker-py versions may
> require `entrypoint=""` instead.

## NVD API and CVE accuracy

Set `NVD_API_KEY` (free from NVD) for 50 requests per 30 s instead of 5. Results are cached for 24 h in
`~/.cache/kubeguard/nvd.db` (`%LOCALAPPDATA%\kubeguard\nvd.db` on Windows); override with
`KUBEGUARD_CACHE_DIR`.

Matching uses upstream versions and a CPE built from a curated package map; unmapped packages fall back to
keyword search and are marked `confidence: low`. Fixes backported by your distribution are not considered,
so some findings can be false positives. Output is capped at 50 CVE findings per image (highest CVSS first).

## CI / Code Scanning

```yaml
- run: kubeguard scan k8s manifests --output sarif --output-file kubeguard.sarif --fail-on high
- uses: github/codeql-action/upload-sarif@v3
  if: always()
  with: {sarif_file: kubeguard.sarif}
```

## Development

```bash
pytest --cov=kubeguard
ruff check .
mypy src
```