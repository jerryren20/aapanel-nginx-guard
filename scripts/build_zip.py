#!/usr/bin/env python3
"""Build the aaPanel third-party plugin archive."""

from __future__ import annotations

import json
from pathlib import Path
import zipfile


ROOT = Path(__file__).resolve().parents[1]
PLUGIN = ROOT / "nginx_guard"
DIST = ROOT / "dist"


def main():
    manifest = json.loads((PLUGIN / "info.json").read_text(encoding="utf-8"))
    version = str(manifest["version"])
    output = DIST / ("nginx_guard-%s.zip" % version)
    DIST.mkdir(parents=True, exist_ok=True)
    if output.exists():
        output.unlink()
    with zipfile.ZipFile(str(output), "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9) as bundle:
        for path in sorted(PLUGIN.rglob("*")):
            if not path.is_file() or "__pycache__" in path.parts or path.suffix == ".pyc":
                continue
            relative = path.relative_to(ROOT).as_posix()
            info = zipfile.ZipInfo(relative, date_time=(2026, 1, 1, 0, 0, 0))
            info.compress_type = zipfile.ZIP_DEFLATED
            # Windows source checkouts do not carry POSIX executable bits.
            # aaPanel invokes the shell entry points after extraction, so keep
            # those bits explicit in the archive.
            mode = 0o100755 if path.suffix == ".sh" else 0o100644
            info.external_attr = mode << 16
            bundle.writestr(info, path.read_bytes())
    print(str(output))


if __name__ == "__main__":
    main()
