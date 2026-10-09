"""Tests for package parsers and the static/runtime enumerators (no Docker needed)."""

import pytest

from kubeguard.core.exceptions import ContainerExecError, PackageEnumerationError
from kubeguard.scanners.package_enumerators import (
    RuntimePackageEnumerator,
    StaticPackageEnumerator,
)
from kubeguard.scanners.package_parsers import (
    ApkParser,
    DpkgParser,
    parse_apk_info,
    parse_dpkg_query,
    parse_rpm_qa,
)
from tests.conftest import FakeDockerAdapter
from tests.helpers import make_image_archive

DPKG_STATUS = b"""Package: libssl3
Status: install ok installed
Version: 3.0.11-1~deb12u2
Source: openssl (3.0.11-1~deb12u2)
Architecture: amd64

Package: removed-pkg
Status: deinstall ok config-files
Version: 1.0

Package: bash
Status: install ok installed
Version: 5.2.15-2+b2
Description: GNU Bourne Again SHell
 continuation line that must be ignored
"""

APK_DB = b"""C:Q1abc=
P:musl
V:1.2.4-r2
A:x86_64
o:musl

P:libssl3
V:3.1.4-r5
o:openssl

"""

DPKG = "var/lib/dpkg/status"


def enumerate_archive(archive: bytes):
    return StaticPackageEnumerator(FakeDockerAdapter(archive=archive)).list_packages("img")


def names(packages) -> set[str]:
    return {p.name for p in packages}


class TestParsers:
    def test_dpkg_only_installed_packages(self) -> None:
        packages = DpkgParser().parse({DPKG: DPKG_STATUS})
        assert names(packages) == {"libssl3", "bash"}
        by_name = {p.name: p for p in packages}
        assert by_name["libssl3"].source == "openssl"
        assert by_name["bash"].source is None
        assert by_name["bash"].version == "5.2.15-2+b2"

    def test_dpkg_status_d_and_md5sums_ignored(self) -> None:
        parser = DpkgParser()
        assert parser.wants("var/lib/dpkg/status.d/base-files")
        assert not parser.wants("var/lib/dpkg/status.d/base-files.md5sums")
        files = {"var/lib/dpkg/status.d/tzdata": b"Package: tzdata\nVersion: 2024a-0\nStatus: install ok installed\n"}
        assert names(parser.parse(files)) == {"tzdata"}

    def test_apk(self) -> None:
        packages = {p.name: p for p in ApkParser().parse({"lib/apk/db/installed": APK_DB})}
        assert set(packages) == {"musl", "libssl3"}
        assert packages["musl"].source is None
        assert packages["libssl3"].source == "openssl"
        assert packages["libssl3"].version == "3.1.4-r5"

    def test_runtime_output_parsers(self) -> None:
        deb = parse_dpkg_query("libssl3\t3.0.11-1\topenssl\tii \nbash\t5.2\tbash\tii \nold\t1\told\trc \n")
        assert {p.name: p.source for p in deb} == {"libssl3": "openssl", "bash": None}
        apk = parse_apk_info("busybox-1.36.1-r5\npy3-pip-23.1.2-r0\nca-certificates-bundle-20230506-r0\n")
        assert [(p.name, p.version) for p in apk] == [
            ("busybox", "1.36.1-r5"),
            ("py3-pip", "23.1.2-r0"),
            ("ca-certificates-bundle", "20230506-r0"),
        ]
        rpm = parse_rpm_qa("openssl\t3.0.7-24.el9\topenssl-3.0.7-24.el9.src.rpm\nfoo\t1-1\t(none)\n")
        assert [(p.name, p.source) for p in rpm] == [("openssl", "openssl"), ("foo", None)]


class TestStaticEnumerator:
    def test_reads_dpkg_from_layer(self) -> None:
        archive = make_image_archive([{"etc/os-release": b"x"}, {"./" + DPKG: DPKG_STATUS}])
        assert names(enumerate_archive(archive)) == {"libssl3", "bash"}

    def test_reads_apk_with_leading_slash_paths(self) -> None:
        archive = make_image_archive([{"/lib/apk/db/installed": APK_DB}])
        assert names(enumerate_archive(archive)) == {"musl", "libssl3"}

    def test_later_layer_replaces_database(self) -> None:
        new = b"Package: only-new\nStatus: install ok installed\nVersion: 2\n"
        archive = make_image_archive([{DPKG: DPKG_STATUS}, {DPKG: new}])
        assert names(enumerate_archive(archive)) == {"only-new"}

    def test_whiteout_deletes_database(self) -> None:
        archive = make_image_archive(
            [{DPKG: DPKG_STATUS, "lib/apk/db/installed": APK_DB}, {"var/lib/dpkg/.wh.status": b""}]
        )
        assert names(enumerate_archive(archive)) == {"musl", "libssl3"}

    def test_opaque_dir_removes_earlier_files_but_keeps_same_layer_files(self) -> None:
        old_extra = b"Package: old-extra\nVersion: 1\nStatus: install ok installed\n"
        new = b"Package: fresh\nVersion: 1\nStatus: install ok installed\n"
        archive = make_image_archive(
            [
                {DPKG: DPKG_STATUS, "var/lib/dpkg/status.d/old": old_extra},
                {"var/lib/dpkg/.wh..wh..opq": b"", DPKG: new},
            ]
        )
        assert names(enumerate_archive(archive)) == {"fresh"}

    def test_gzip_compressed_layers(self) -> None:
        archive = make_image_archive([{DPKG: DPKG_STATUS}], gzip_layers=True)
        assert names(enumerate_archive(archive)) == {"libssl3", "bash"}

    def test_zstd_layers_report_unsupported(self) -> None:
        archive = make_image_archive([{DPKG: DPKG_STATUS}], zstd_magic=True)
        with pytest.raises(PackageEnumerationError, match="zstd"):
            enumerate_archive(archive)

    def test_missing_manifest(self) -> None:
        archive = make_image_archive([{DPKG: DPKG_STATUS}], manifest=False)
        with pytest.raises(PackageEnumerationError, match="manifest.json"):
            enumerate_archive(archive)

    def test_garbage_archive(self) -> None:
        with pytest.raises(PackageEnumerationError, match="could not read image archive"):
            enumerate_archive(b"this is not a tar file" * 100)

    def test_no_database_is_an_error_not_an_empty_list(self) -> None:
        archive = make_image_archive([{"bin/app": b"\x7fELF"}])
        with pytest.raises(PackageEnumerationError, match="no supported package database"):
            enumerate_archive(archive)

    def test_rpm_is_reported_as_unsupported(self) -> None:
        archive = make_image_archive([{"var/lib/rpm/rpmdb.sqlite": b"SQLite format 3"}])
        with pytest.raises(PackageEnumerationError, match="RPM.*allow-container-exec"):
            enumerate_archive(archive)

    def test_rpm_alongside_dpkg_still_returns_dpkg_packages(self) -> None:
        archive = make_image_archive([{DPKG: DPKG_STATUS, "var/lib/rpm/Packages": b"x"}])
        assert names(enumerate_archive(archive)) == {"libssl3", "bash"}

    def test_never_runs_containers(self) -> None:
        adapter = FakeDockerAdapter(archive=make_image_archive([{DPKG: DPKG_STATUS}]))
        StaticPackageEnumerator(adapter).list_packages("img")
        assert adapter.save_calls == ["img"]
        assert adapter.run_calls == []


class TestRuntimeEnumerator:
    DPKG_OUT = "libssl3\t3.0.11-1\topenssl\tii \nbash\t5.2\tbash\tii \n"

    def test_dpkg_first(self) -> None:
        adapter = FakeDockerAdapter(commands={"dpkg-query": self.DPKG_OUT})
        packages = RuntimePackageEnumerator(adapter).list_packages("img")
        assert names(packages) == {"libssl3", "bash"}
        assert [c[0] for c in adapter.run_calls] == ["dpkg-query"]

    def test_falls_back_to_apk(self) -> None:
        adapter = FakeDockerAdapter(
            commands={"dpkg-query": ContainerExecError("not found", 127), "apk": "musl-1.2.4-r2\n"}
        )
        packages = RuntimePackageEnumerator(adapter).list_packages("img")
        assert names(packages) == {"musl"}
        assert [c[0] for c in adapter.run_calls] == ["dpkg-query", "apk"]

    def test_all_tools_failing_is_an_error(self) -> None:
        adapter = FakeDockerAdapter()  # every command raises ContainerExecError
        with pytest.raises(PackageEnumerationError, match="dpkg-query.*apk.*rpm"):
            RuntimePackageEnumerator(adapter).list_packages("img")

    def test_empty_output_counts_as_failure(self) -> None:
        adapter = FakeDockerAdapter(commands={"dpkg-query": "", "apk": "", "rpm": ""})
        with pytest.raises(PackageEnumerationError, match="no packages in output"):
            RuntimePackageEnumerator(adapter).list_packages("img")