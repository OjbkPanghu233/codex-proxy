"""Offline browser QA; never attaches to the user's browser or desktop app."""
import argparse
import json
import os
from pathlib import Path
from playwright.sync_api import sync_playwright
parser=argparse.ArgumentParser();parser.add_argument('--root',type=Path);parser.add_argument('--evidence',type=Path);parser.add_argument('--check',action='store_true');args=parser.parse_args()
with sync_playwright() as playwright:
    candidates=[Path(playwright.chromium.executable_path),Path(os.environ.get('PROGRAMFILES','C:/Program Files'))/'Google/Chrome/Application/chrome.exe',Path(os.environ.get('PROGRAMFILES(X86)','C:/Program Files (x86)'))/'Microsoft/Edge/Application/msedge.exe']
    executable=next((p for p in candidates if p.is_file()),None)
    if args.check:raise SystemExit(0 if executable else 1)
    if not executable:raise RuntimeError('No Chromium/Chrome/Edge available for optional browser QA')
    args.evidence.mkdir(parents=True,exist_ok=True)
    browser=playwright.chromium.launch(executable_path=str(executable),headless=True,args=['--disable-background-networking','--disable-component-update'])
    page=browser.new_page(viewport={'width':1440,'height':1080},accept_downloads=True)
    errors=[];external=[]
    page.on('pageerror',lambda error:errors.append(str(error)))
    page.on('request',lambda request:external.append(request.url) if request.url.startswith(('http:','https:')) else None)
    page.goto((args.root/'config-web.html').resolve().as_uri());page.wait_for_load_state('networkidle')
    assert page.locator('#desktop').is_checked()
    page.locator('#language').click();assert page.locator('html').get_attribute('lang')=='en'
    page.locator('#host').fill('localhost');page.locator('#port').fill('7897');page.locator('#type').select_option('http');page.locator('#password').fill('sample-only-secret');page.locator('#ignore').uncheck();page.locator('#desktop').uncheck()
    page.locator('#addRule').click();page.locator('[data-rule="name"]').fill('Local services');page.locator('[data-rule="domains"]').fill('*.internal.test');page.locator('[data-rule="ports"]').fill('8000-9000');page.locator('[data-rule="action"]').select_option('direct')
    exported=json.loads(page.evaluate('CodexProxyEditor.exportConfig()'))
    assert exported['proxy']['type']=='http' and exported['proxy']['port']==7897
    assert exported['desktop_host_network_hooks'] is False and exported['proxy']['ignore_system_proxy'] is False
    assert exported['rules']['routing']['rules'][0]['ports']==['8000-9000']
    assert 'sample-only-secret' not in page.locator('#preview').inner_text()
    exported['future_option']={'preserved':True};exported['child_injection']=False
    page.evaluate('(value)=>CodexProxyEditor.importConfig(value)',json.dumps(exported))
    assert json.loads(page.evaluate('CodexProxyEditor.exportConfig()'))['future_option']['preserved'] is True
    for invalid in ['[]','null','{"__proto__":{"polluted":true}}']:
        assert page.evaluate('(value)=>{try{CodexProxyEditor.importConfig(value);return false}catch{return true}}',invalid)
    page.locator('#port').fill('70000');assert page.locator('#export').is_disabled()
    page.locator('#port').fill('7897');assert page.locator('#export').is_enabled()
    with page.expect_download() as pending:page.locator('#export').click()
    download=pending.value;download.save_as(args.evidence/'exported-test-config.json')
    actual=json.loads((args.evidence/'exported-test-config.json').read_text())
    assert actual['proxy']['password']=='sample-only-secret' and actual['future_option']['preserved'] is True
    legacy={'log_level':'debug','traffic_logging':True,'timeout':{'connect':12000},'proxy_rules':{'udp_mode':'block'}}
    migrated=page.evaluate('(value)=>CodexProxyEditor.importConfig(value)',json.dumps(legacy))
    assert migrated['logging']['level']=='debug' and migrated['traffic_monitor']['enabled'] is True
    assert migrated['timeout']['connect_ms']==12000 and migrated['rules']['udp_mode']=='block'
    page.evaluate('(value)=>CodexProxyEditor.importConfig(value)',json.dumps(actual))
    page.screenshot(path=str(args.evidence/'config-web-desktop.png'),full_page=True)
    page.set_viewport_size({'width':375,'height':812});page.locator('#language').click();page.wait_for_timeout(100)
    assert page.evaluate('document.documentElement.scrollWidth<=window.innerWidth')
    page.screenshot(path=str(args.evidence/'config-web-mobile.png'),full_page=True)
    assert not errors,errors
    assert not external,external
    browser.close()
print('Config editor: bilingual forms, rule editing, secret redaction, import/export, unknown fields, validation, desktop/mobile and offline behavior passed.')
