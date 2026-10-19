"""Escanea las dos variantes del laboratorio local y conserva los informes."""

from collections import Counter
import argparse
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.request

ROOT = Path(__file__).resolve().parent.parent
OUT = ROOT / 'fase_b' / 'evidencias'
IMAGE = 'ghcr.io/zaproxy/zaproxy@sha256:7aaa659b0d43078febd82e29bad112285c370727e86ab8340444220e17d9f0d2'


def functional_checks():
    from lab_app import create_app
    checks = []
    for secure in [False, True]:
        client = create_app(secure).test_client()
        payload = '<script>alert(1)</script>'
        comment = client.post('/comment', data={'comment': payload}, follow_redirects=True)
        error = client.get('/age?age=abc')
        valid = client.get('/age?age=25')
        result = {'mode': 'corregido' if secure else 'vulnerable',
                  'payload': payload, 'rawScript': payload in comment.get_data(as_text=True),
                  'escapedScript': '&lt;script&gt;' in comment.get_data(as_text=True),
                  'invalidAgeStatus': error.status_code,
                  'traceback': 'Traceback' in error.get_data(as_text=True),
                  'validAgeStatus': valid.status_code}
        assert result['rawScript'] == (not secure)
        assert result['escapedScript'] == secure
        assert result['invalidAgeStatus'] == (400 if secure else 500)
        assert result['traceback'] == (not secure)
        assert result['validAgeStatus'] == 200
        checks.append(result)
    (OUT / 'pruebas-funcionales.json').write_text(json.dumps(checks, indent=2), encoding='utf8')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--solo', choices=['vulnerable', 'corregido'])
    args = parser.parse_args()
    OUT.mkdir(parents=True, exist_ok=True)
    if not args.solo or not (OUT / 'pruebas-funcionales.json').exists():
        functional_checks()
    summary = {'target': 'http://host.docker.internal:5011/', 'image': IMAGE, 'results': []}
    for mode in ([args.solo] if args.solo else ['vulnerable', 'corregido']):
        with socket.socket() as probe:
            probe.settimeout(.5)
            if probe.connect_ex(('127.0.0.1', 5011)) == 0:
                raise RuntimeError('El puerto 5011 ya tiene un servidor activo.')
        command = [sys.executable, str(ROOT / 'fase_b' / 'lab_app.py')]
        if mode == 'corregido':
            command.append('--secure')
        app = subprocess.Popen(command, cwd=ROOT, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        try:
            for attempt in range(40):
                if app.poll() is not None:
                    raise RuntimeError('El laboratorio no pudo iniciar.')
                try:
                    with urllib.request.urlopen('http://127.0.0.1:5011/', timeout=2) as response:
                        if response.status == 200:
                            break
                except (urllib.error.URLError, TimeoutError):
                    time.sleep(.25)
            else:
                raise TimeoutError('El laboratorio no responde en 5011.')
            print('Escaneo activo: ' + mode, flush=True)
            name = 'cdss-zap-fase-b-' + mode
            docker = ['docker', 'run', '--rm', '--name', name,
                      '-e', 'ZAP_EVIDENCE_NAME=evidencias-' + mode + '.json',
                      '-v', str(ROOT / 'fase_b') + ':/zap/wrk/:rw', IMAGE,
                      'zap-full-scan.py', '-t', summary['target'],
                      '--hook=/zap/wrk/zap_hooks.py', '-m', '1',
                      '-r', 'evidencias/reporte-' + mode + '.html',
                      '-J', 'evidencias/reporte-' + mode + '.json']
            # El hook escribe dentro del montaje; se mueve el JSON junto al informe.
            with (OUT / ('zap-' + mode + '.log')).open('w', encoding='utf8') as log:
                scan = subprocess.Popen(docker, cwd=ROOT, stdout=log, stderr=subprocess.STDOUT)
                try:
                    code = scan.wait(timeout=900)
                except subprocess.TimeoutExpired:
                    subprocess.run(['docker', 'stop', name], capture_output=True)
                    raise
            report_path = OUT / ('reporte-' + mode + '.json')
            if code not in (0, 1, 2) or not report_path.exists():
                raise RuntimeError('ZAP no completo el informe de ' + mode)
            report = json.loads(report_path.read_text(encoding='utf-8-sig'))
            sites = report.get('site', [])
            if not sites or any(s.get('@name', '').rstrip('/') != summary['target'].rstrip('/') for s in sites):
                raise RuntimeError('El informe contiene un destino inesperado.')
            alerts = [a for site in sites for a in site.get('alerts', [])]
            evidence = ROOT / 'fase_b' / ('evidencias-' + mode + '.json')
            if not evidence.exists():
                raise RuntimeError('Falta la evidencia HTTP exportada por ZAP.')
            evidence.replace(OUT / evidence.name)
            result = {'mode': mode, 'version': report.get('@version'),
                      'severity': dict(Counter(a['riskcode'] for a in alerts)),
                      'alertTypes': len(alerts),
                      'rules': [{'id': a['pluginid'], 'name': a['name'],
                                 'risk': a['riskdesc'], 'instances': len(a.get('instances', []))} for a in alerts]}
            summary['results'].append(result)
            print(json.dumps(result, ensure_ascii=False), flush=True)
        finally:
            app.terminate()
            app.wait(timeout=10)
    # Permite reanudar un solo escaneo sin repetir el que ya termino.
    summary['results'] = []
    for mode in ['vulnerable', 'corregido']:
        report = json.loads((OUT / ('reporte-' + mode + '.json')).read_text(encoding='utf-8-sig'))
        alerts = [a for s in report['site'] for a in s['alerts']]
        summary['results'].append({'mode': mode, 'version': report.get('@version'),
            'severity': dict(Counter(a['riskcode'] for a in alerts)), 'alertTypes': len(alerts),
            'rules': [{'id': a['pluginid'], 'name': a['name'], 'risk': a['riskdesc'],
                       'instances': len(a.get('instances', []))} for a in alerts]})
    (OUT / 'comparacion.json').write_text(json.dumps(summary, ensure_ascii=False, indent=2), encoding='utf8')
    print('Informes y comparacion guardados.', flush=True)


if __name__ == '__main__':
    main()
