"""Exercise installer/repair/uninstall only in a disposable directory."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import socket
import subprocess
import tempfile
import threading

parser=argparse.ArgumentParser();parser.add_argument('--root',type=Path,required=True);parser.add_argument('--build-dir',type=Path,required=True);args=parser.parse_args()
def digest(path):return hashlib.sha256(path.read_bytes()).hexdigest()
with tempfile.TemporaryDirectory(prefix='codex-proxy-install-test-') as temporary:
    base=Path(temporary);source=base/'portable';source.mkdir();destination=base/'installed';links=base/'shortcuts';native=base/'native';native.mkdir()
    for name in ['codex-proxy.exe','CodexDesktopLauncher.exe','codex_proxy.dll','version.dll','tdh.dll']:shutil.copy2(args.build_dir/name,source/name)
    for name in ['README.md','LICENSE.txt','AUTHORS.txt','UPSTREAM.txt','config.example.json','config-web.html']:shutil.copy2(args.root/name,source/name)
    shutil.copytree(args.root/'scripts',source/'scripts');shutil.copytree(args.root/'docs',source/'docs')
    # This fixture statically imports TDH just like the native Codex CLI.
    shutil.copy2(args.build_dir/'codex.exe',native/'codex.exe')
    original=b'original-tdh-before-Codex-Proxy';(native/'tdh.dll').write_bytes(original)
    listener=socket.socket();listener.bind(('127.0.0.1',0));listener.listen();listener.settimeout(.2);port=listener.getsockname()[1];stop=threading.Event()
    def server():
        while not stop.is_set():
            try:peer,_=listener.accept()
            except socket.timeout:continue
            except OSError:return
            with peer:
                peer.settimeout(2)
                try:
                    hello=peer.recv(100)
                    if hello.startswith(b'\x05'):peer.sendall(b'\x05\x00')
                except OSError:pass
    worker=threading.Thread(target=server,daemon=True);worker.start()
    def doctor(action,*extra):
        command=['powershell.exe','-NoProfile','-ExecutionPolicy','Bypass','-File',str(source/'scripts/doctor.ps1'),'-Action',action,'-Destination',str(destination),'-SourceDir',str(source),'-ShortcutRoot',str(links),'-CliExe',str(native/'codex.exe'),'-Yes',*extra]
        env=os.environ.copy();env.pop('CODEX_PROXY_CONFIG',None)
        completed=subprocess.run(command,env=env,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,timeout=35)
        text=completed.stdout.decode('utf-8',errors='replace')
        assert completed.returncode==0,text
        assert 'test-password-never-log' not in text
        return text
    try:
        doctor('Install','-ProxyHost','127.0.0.1','-ProxyPort',str(port))
        path=destination/'config.json';config=json.loads(path.read_text(encoding='utf-8-sig'))
        assert config['proxy']['port']==port and config['proxy']['type']=='socks5'
        assert config['desktop_host_network_hooks'] is True
        assert digest(native/'tdh.dll')==digest(source/'tdh.dll')
        assert digest(native/'codex_proxy.dll')==digest(source/'codex_proxy.dll')
        locator=native/'codex-proxy.config-path'
        assert locator.read_text(encoding='utf-8-sig').strip()==str(path)
        manifest=json.loads((destination/'install-manifest.json').read_text(encoding='utf-8-sig'))
        assert any(Path(entry['Path'])==locator and entry['External'] for entry in manifest['Files'])
        isolated=os.environ.copy();isolated.pop('CODEX_PROXY_CONFIG',None)
        isolated['LOCALAPPDATA']=str(base/'empty-local-data')
        loaded=subprocess.run([str(native/'codex.exe')],env=isolated,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=20)
        assert loaded.returncode==0 and not loaded.stdout,loaded.stderr.decode(errors='replace')
        assert len(list(links.rglob('*.lnk')))==2
        config['preserve_me']={'value':42};config['proxy']['password']='test-password-never-log';path.write_text(json.dumps(config),encoding='utf-8');before=path.read_bytes()
        doctor('Repair','-ProxyPort','1','-ProxyType','http','-SkipCliShim')
        assert path.read_bytes()==before
        snapshot={str(p):digest(p) for folder in [destination,native,links] for p in folder.rglob('*') if p.is_file()}
        checked=doctor('Check')
        assert 'CLI effective config: '+str(path) in checked
        assert snapshot=={str(p):digest(p) for folder in [destination,native,links] for p in folder.rglob('*') if p.is_file()}
        doctor('Uninstall')
        assert path.read_bytes()==before and (native/'tdh.dll').read_bytes()==original
        assert not (native/'codex_proxy.dll').exists() and not list(links.rglob('*.lnk'))
        assert not locator.exists()
        doctor('Uninstall','-Purge')
        assert not destination.exists() and (native/'tdh.dll').read_bytes()==original
        print('Installer: protocol detection, deploy, shortcuts, preserve config, read-only check, rollback and purge passed.')
    finally:
        stop.set();listener.close();worker.join(timeout=3)
