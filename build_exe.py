"""Build in a new directory, without stopping apps or packaging local state."""
import argparse
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import zipfile

BASE_DIR = Path(__file__).resolve().parent


def build(output_dir):
    output_dir = Path(output_dir).resolve()
    output_dir.mkdir(parents=True, exist_ok=True)
    work = Path(tempfile.mkdtemp(prefix="gbf-build-", dir=output_dir))
    command = [sys.executable, "-m", "PyInstaller", "--noconfirm", "--onefile", "--windowed",
               "--name", "GBF_Accelerator", "--distpath", str(work / "dist"),
               "--workpath", str(work / "work"), "--specpath", str(work),
               "--paths", str(BASE_DIR), "--hidden-import", "socksio",
               "--hidden-import", "brotli", str(BASE_DIR / "app_main.py")]
    subprocess.run(command, cwd=BASE_DIR, check=True)
    executable = work / "dist/GBF_Accelerator.exe"
    if not executable.is_file() or not executable.stat().st_size:
        raise RuntimeError("PyInstaller did not produce an executable")
    revision = subprocess.run(["git", "rev-parse", "HEAD"], cwd=BASE_DIR, capture_output=True, text=True, check=True).stdout.strip()
    dirty = bool(subprocess.run(["git", "status", "--porcelain"], cwd=BASE_DIR, capture_output=True, text=True, check=True).stdout.strip())
    manifest = {"base_commit": revision, "working_tree_changes": dirty,
                "python": sys.version, "build_command": "python build_exe.py --output-dir <new-directory>"}
    (work / "build-info.json").write_text(json.dumps(manifest, ensure_ascii=False, indent=2), encoding="utf-8")
    package = work / "GBF_Accelerator_repaired.zip"
    with zipfile.ZipFile(package, "w", zipfile.ZIP_DEFLATED) as archive:
        archive.write(executable, "GBF_Accelerator.exe")
        archive.write(work / "build-info.json", "build-info.json")
        for name in ("README.md", "使用说明.txt", "proxy.pac", "SwitchyOmega_GBF.bak", "requirements-lock.txt"):
            archive.write(BASE_DIR / name, name)
    with zipfile.ZipFile(package) as archive:
        if archive.testzip() is not None:
            raise RuntimeError("Package validation failed")
    print(f"Executable: {executable}\nPackage: {package}")
    return package


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--output-dir", type=Path, default=BASE_DIR / "release")
    build(parser.parse_args().output_dir)
