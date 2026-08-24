#!/usr/bin/python3.8
import os
import zipapp
from pathlib import Path


def include_member(path):
    return "__pycache__" not in path.parts and path.suffix not in (".pyc", ".pyo")


def main():
    project_root = Path(__file__).resolve().parents[1]
    source = project_root / "src"
    destination_dir = project_root / "dist"
    destination_dir.mkdir(exist_ok=True)
    destination = destination_dir / "kdiag.pyz"
    temporary = destination_dir / ".kdiag.pyz.part"
    if temporary.exists():
        temporary.unlink()
    zipapp.create_archive(
        str(source),
        str(temporary),
        interpreter="/usr/bin/python3.8",
        main="kdiag.cli:entrypoint",
        filter=include_member,
        compressed=True,
    )
    os.chmod(str(temporary), 0o755)
    os.replace(str(temporary), str(destination))
    print(destination)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
