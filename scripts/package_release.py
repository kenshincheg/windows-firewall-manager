"""Package a Windows x64 release and its committed sources without local data."""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
from pathlib import Path
import struct
import subprocess
import tomllib
import zipfile


ROOT = Path(__file__).resolve().parents[1]


def command(*args: str) -> str:
    return subprocess.check_output(args, cwd=ROOT, text=True, encoding="utf-8").strip()


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, default=ROOT / "target/release/firewall_windows.exe")
    parser.add_argument("--output", type=Path, default=ROOT / "target/publication/artifacts")
    args = parser.parse_args()

    if command("git", "status", "--porcelain"):
        raise SystemExit("Commit source changes before packaging a release")
    with (ROOT / "Cargo.toml").open("rb") as manifest:
        version = tomllib.load(manifest)["package"]["version"]
    commit = command("git", "rev-parse", "HEAD")
    tracked = set(command("git", "ls-files").splitlines())
    for filename in tracked:
        parts = Path(filename).parts
        if any(p in {"target", "backups", "package", "logs", ".git"} for p in parts):
            raise SystemExit(f"Local data tracked by Git: {filename}")
        if Path(filename).suffix.lower() in {".wfw", ".log", ".exe", ".pdb", ".zip"}:
            raise SystemExit(f"Unexpected tracked artifact: {filename}")

    binary = args.binary.resolve()
    image = binary.read_bytes()
    if image[:2] != b"MZ":
        raise SystemExit("Release binary is not a PE image")
    pe_offset = struct.unpack_from("<I", image, 0x3C)[0]
    if image[pe_offset:pe_offset + 4] != b"PE\0\0" or struct.unpack_from("<H", image, pe_offset + 4)[0] != 0x8664:
        raise SystemExit("Expected a Windows x64 executable")

    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=True)
    portable = output / f"WindowsFirewallManager-{version}-windows-x64.zip"
    sources = output / f"WindowsFirewallManager-{version}-source.zip"
    build_info = output / "BUILDINFO.txt"
    build_info.write_text(
        "Windows Firewall Manager\n"
        f"Version: {version}\nSource commit: {commit}\nSource tag: v{version}\n"
        "Target: x86_64-pc-windows-msvc\n"
        f"Rust: {command('rustc', '--version')}\n"
        f"Packaged UTC: {datetime.now(timezone.utc).isoformat(timespec='seconds')}\n"
        f"EXE SHA256: {sha256(binary)}\n"
        "Runtime: Windows 10/11 x64, DX12/WARP, Microsoft Visual C++ runtime\n",
        encoding="utf-8",
    )
    prefix = f"WindowsFirewallManager-{version}/"
    entries = {"firewall_windows.exe": binary, "BUILDINFO.txt": build_info, "icon.ico": ROOT / "assets/icon.ico"}
    for filename in tracked:
        if filename in {"README.md", "LICENSE", "DEVLOG.md"} or filename.startswith("docs/"):
            entries[filename] = ROOT / filename
    with zipfile.ZipFile(portable, "w", zipfile.ZIP_DEFLATED, compresslevel=9) as archive:
        for name, path in sorted(entries.items()):
            archive.write(path, prefix + name)
    subprocess.run(
        ["git", "archive", "--format=zip", f"--prefix=WindowsFirewallManager-{version}-source/", f"--output={sources}", commit],
        cwd=ROOT, check=True,
    )
    for path in [portable, sources]:
        with zipfile.ZipFile(path) as archive:
            if archive.testzip() is not None:
                raise SystemExit(f"Archive integrity failed: {path.name}")
        path.with_suffix(path.suffix + ".sha256").write_text(f"{sha256(path)}  {path.name}\n", encoding="utf-8")
    with zipfile.ZipFile(portable) as archive:
        if hashlib.sha256(archive.read(prefix + "firewall_windows.exe")).hexdigest() != sha256(binary):
            raise SystemExit("Packaged EXE hash differs from the release binary")
    (output / "SHA256SUMS.txt").write_text(
        "".join(f"{sha256(path)}  {path.name}\n" for path in [portable, sources, build_info]), encoding="utf-8"
    )
    print(f"Version: {version}\nCommit: {commit}\nPortable: {portable}\nSources: {sources}")


if __name__ == "__main__":
    main()
