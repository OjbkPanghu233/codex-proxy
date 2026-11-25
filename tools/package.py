"""Assemble a portable release exclusively inside the repository output directory."""
import argparse
import hashlib
import json
from pathlib import Path
import shutil
import zipfile

parser=argparse.ArgumentParser()
parser.add_argument('--build-dir',type=Path,required=True)
parser.add_argument('--config',choices=['Release','Debug'],default='Release')
args=parser.parse_args()
root=Path(__file__).resolve().parents[1]
output=(root/'output').resolve()
destination=(output/'codex-proxy-win-x64').resolve()
if destination.parent!=output or output.parent!=root:
    raise SystemExit('Package path escaped the workspace')
required=['codex-proxy.exe','CodexDesktopLauncher.exe','codex_proxy.dll','version.dll','tdh.dll']
for name in required:
    if not (args.build_dir/name).is_file():raise SystemExit('Missing binary: '+name)
if destination.exists():
    # Never recursively replace a directory not created by this packager.
    if not (destination/'.codex-proxy-package').is_file():raise SystemExit('Refusing to replace an unowned output directory')
    shutil.rmtree(destination)
destination.mkdir(parents=True)
(destination/'.codex-proxy-package').write_text('Codex-Proxy 0.2.0\n',encoding='utf-8')
for name in required:shutil.copy2(args.build_dir/name,destination/name)
for name in ['README.md','LICENSE.txt','AUTHORS.txt','UPSTREAM.txt','config.example.json','config-web.html']:
    shutil.copy2(root/name,destination/name)
for folder in ['scripts','docs']:
    shutil.copytree(root/folder,destination/folder)
for name in ['configure.log','build.log','ctest.log']:
    if (args.build_dir/name).is_file():
        (destination/'validation').mkdir(exist_ok=True)
        shutil.copy2(args.build_dir/name,destination/'validation'/name)
def digest(path):return hashlib.sha256(path.read_bytes()).hexdigest()
binary_manifest=[{'file':name,'bytes':(destination/name).stat().st_size,'sha256':digest(destination/name)} for name in required]
(destination/'manifest.json').write_text(json.dumps({'product':'Codex-Proxy','version':'0.2.0','configuration':args.config,'platform':'Windows x64','artifacts':binary_manifest},indent=2)+'\n',encoding='utf-8')
files=sorted(p for p in destination.rglob('*') if p.is_file())
(destination/'SHA256SUMS.txt').write_text(''.join(f'{digest(p)} *{p.relative_to(destination).as_posix()}\n' for p in files),encoding='utf-8')
archive=output/'codex-proxy-win-x64.zip'
with zipfile.ZipFile(archive,'w',zipfile.ZIP_DEFLATED) as zipped:
    for path in sorted(destination.rglob('*')):
        if path.is_file():zipped.write(path,path.relative_to(output))
all_files=sorted(p for p in destination.rglob('*') if p.is_file())+[archive]
(output/'SHA256SUMS.txt').write_text(''.join(f'{digest(p)} *{p.relative_to(output).as_posix()}\n' for p in all_files),encoding='utf-8')
print(f'Portable directory: {destination}')
print(f'ZIP: {archive} ({archive.stat().st_size:,} bytes)')
print(f'Checksums: {output / "SHA256SUMS.txt"}')
