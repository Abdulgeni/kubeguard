# KubeGuard

Security scanner for Docker images and Kubernetes manifests.

## Package enumeration and `--allow-container-exec`

CVE checks need the list of packages installed in an image. By default KubeGuard reads
the package databases (dpkg, apk) straight out of the image's layer tarballs
(`docker save`). It **never creates or starts a container**, and extracted data is kept
in memory (the archive itself is spooled to a temporary file that is deleted afterwards).

Limits of static enumeration: RPM databases and zstd-compressed layers are unsupported;
the scan then reports an Info finding (`KG-DOCKER-005`) instead of silently skipping CVEs.

### Security trade-off

`--allow-container-exec` switches to runtime enumeration: KubeGuard runs `dpkg-query`,
`apk info` or `rpm -qa` **inside a container created from the image**. That executes
binaries from the image you are scanning. KubeGuard limits the container (no network,
read-only filesystem, all capabilities dropped, `no-new-privileges`, memory and PID
limits), but it is still untrusted code. Only use this flag on images you trust.

## NVD API

Set `NVD_API_KEY` (free from NVD) for 50 requests per 30 s instead of 5. Results are
cached in `~/.cache/kubeguard/nvd.db` (`%LOCALAPPDATA%\kubeguard\nvd.db` on Windows);
override the directory with `KUBEGUARD_CACHE_DIR`.

CVE matching uses upstream versions and does not account for fixes your distribution
backported, so some findings can be false positives.