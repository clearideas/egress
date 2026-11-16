"""Verify a GitHub release's distributions before uploading them to PyPI."""

from __future__ import annotations

import re
import sys
import tarfile
import tomllib
import zipfile
from email.parser import BytesParser
from pathlib import Path


def verify(tag: str, directory: Path) -> None:
    if not re.fullmatch(r"v[0-9]+\.[0-9]+\.[0-9]+", tag):
        raise ValueError(f"Expected a final release tag like v0.3.0: {tag!r}")

    version = tag[1:]
    stem = f"clearideas_egress-{version}"
    wheel = directory / f"{stem}-py3-none-any.whl"
    sdist = directory / f"{stem}.tar.gz"
    actual = {path.name for path in directory.iterdir() if path.is_file()}
    expected = {wheel.name, sdist.name}
    if actual != expected:
        raise ValueError(f"Expected exactly {sorted(expected)}; got {sorted(actual)}")

    with zipfile.ZipFile(wheel) as archive:
        metadata = BytesParser().parsebytes(
            archive.read(f"{stem}.dist-info/METADATA")
        )
        if metadata["Name"] != "clearideas-egress" or metadata["Version"] != version:
            raise ValueError("Wheel name or version does not match release tag")

    with tarfile.open(sdist, "r:gz") as archive:
        member = archive.extractfile(f"{stem}/pyproject.toml")
        if member is None:
            raise ValueError("Source distribution lacks pyproject.toml")
        project = tomllib.load(member)["project"]
        if project["name"] != "clearideas-egress" or project["version"] != version:
            raise ValueError("Source distribution name or version does not match release tag")

    print(f"Verified wheel and source distribution for clearideas-egress {version}")


if __name__ == "__main__":
    if len(sys.argv) != 3:
        raise SystemExit("usage: verify_release_dist.py TAG DIST_DIRECTORY")
    verify(sys.argv[1], Path(sys.argv[2]))
