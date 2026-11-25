"""MSVC + Ninja build; supports a project-local Windows SDK without registry changes."""
import argparse
import json
import os
from pathlib import Path
import subprocess
import re
import sys

parser = argparse.ArgumentParser()
parser.add_argument("--vs", type=Path, default=Path("D:/VisualStudioIDE"))
parser.add_argument("--sdk-root", type=Path)
parser.add_argument("--config", choices=["Release", "Debug"], default="Release")
parser.add_argument("--build-dir", type=Path, default=Path("build"))
parser.add_argument("--no-tests", action="store_true")
args = parser.parse_args()
root = Path(__file__).resolve().parents[1]
os.chdir(root)
sdk = args.sdk_root
if sdk is None:
    candidates = [Path(os.environ.get("WindowsSdkDir", "missing")), root / ".deps/winsdk/Windows Kits/10"]
    try:
        import winreg
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows Kits\Installed Roots") as key:
            candidates.insert(0, Path(winreg.QueryValueEx(key, "KitsRoot10")[0]))
    except OSError:
        pass
    sdk = next((path for path in candidates if (path / "Include").is_dir()), None)
if sdk is None:
    sys.exit("Windows SDK not found. Install the C++ Windows SDK or pass --sdk-root.")
sdk = sdk.resolve()
versions = sorted(p.name for p in (sdk / "Include").iterdir() if (p / "um/Windows.h").exists())
if not versions:
    sys.exit("Windows SDK headers not found")
version = versions[-1]
vc = sorted((args.vs / "VC/Tools/MSVC").iterdir())[-1]
env = os.environ.copy()
env["INCLUDE"] = ";".join(str(p) for p in [vc / "include", sdk / "Include" / version / "ucrt", sdk / "Include" / version / "shared", sdk / "Include" / version / "um", sdk / "Include" / version / "winrt"])
env["LIB"] = ";".join(str(p) for p in [vc / "lib/x64", sdk / "Lib" / version / "ucrt/x64", sdk / "Lib" / version / "um/x64"])
cmake_dir = args.vs / "Common7/IDE/CommonExtensions/Microsoft/CMake"
env["PATH"] = ";".join(str(p) for p in [vc / "bin/Hostx64/x64", sdk / "bin" / version / "x64", cmake_dir / "Ninja"]) + ";" + env["PATH"]
env["VSLANG"] = "1033"
cmake = cmake_dir / "CMake/bin/cmake.exe"
ctest = cmake_dir / "CMake/bin/ctest.exe"
args.build_dir.mkdir(parents=True, exist_ok=True)
commands = [
    [str(cmake), "-S", str(root), "-B", str(args.build_dir), "-G", "Ninja", f"-DCMAKE_BUILD_TYPE={args.config}", f"-DPython3_EXECUTABLE={sys.executable}", "-DBUILD_TESTS=" + ("OFF" if args.no_tests else "ON")],
    [str(cmake), "--build", str(args.build_dir), "-j", "4"],
]
if not args.no_tests:
    commands.append([str(ctest), "--test-dir", str(args.build_dir), "--output-on-failure"])
for name, command in zip(["configure", "build", "ctest"], commands):
    print(f"Running {name}: MSVC {vc.name}, SDK {version}", flush=True)
    result = subprocess.run(command, env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    try:
        log = result.stdout.decode("utf-8")
    except UnicodeDecodeError:
        log = result.stdout.decode("mbcs", errors="replace")
    (args.build_dir / (name + ".log")).write_text(log, encoding="utf-8")
    # /showIncludes is compiler-localized on this machine. Keep full output in logs.
    lines = [line for line in log.splitlines() if "包含文件:" not in line and "Note: including file:" not in line]
    print("\n".join(lines), flush=True)
    if result.returncode:
        sys.exit(result.returncode)
    if name == "configure":
        # Use the compiler's actual localized bytes for Ninja's /showIncludes
        # parser. This avoids missing header dependencies on zh-CN MSVC.
        probe=args.build_dir / 'include-probe.c'
        probe.write_text('#include <windows.h>\n',encoding='ascii')
        detected=subprocess.run([str(vc/'bin/Hostx64/x64/cl.exe'),'/nologo','/utf-8','/showIncludes','/P','/FiNUL',str(probe)],env=env,stdout=subprocess.PIPE,stderr=subprocess.STDOUT)
        probe.unlink()
        prefix=None
        for line in detected.stdout.splitlines():
            found=re.match(rb'^(.+?:\s+)(?=[A-Za-z]:[\\/])',line)
            if found:
                prefix=found.group(1)
                break
        rules=args.build_dir/'CMakeFiles/rules.ninja'
        if prefix and rules.exists():
            original=rules.read_bytes()
            corrected=re.sub(rb'^msvc_deps_prefix =[^\r\n]*',lambda _:b'msvc_deps_prefix = '+prefix,original,flags=re.M)
            if corrected != original:
                rules.write_bytes(corrected)
