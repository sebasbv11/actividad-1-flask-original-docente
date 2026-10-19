"""Ejecuta SAST sin arrancar las aplicaciones y conserva la evidencia real.

Uso: definir SONAR_TOKEN y ejecutar python fase_a/ejecutar_analisis.py.
Las pruebas funcionales se ejecutan por separado, despues de los escaneos.
"""

import base64
import datetime
import hashlib
import json
import os
import re
from pathlib import Path
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request


ROOT = Path(__file__).resolve().parent.parent
EVIDENCE = ROOT / 'fase_a' / 'evidencias'
PROJECTS = [
    ('docente', 'actividad1-a-docente', 'app.py'),
    ('vulnerable', 'actividad1-a-casos-vulnerable', 'fase_a/login_sga_vulnerable.py'),
    ('corregido', 'actividad1-a-casos-corregido', 'fase_a/login_sga_refactorizado.py'),
]
SCANNER_IMAGE = 'sonarsource/sonar-scanner-cli@sha256:a3f4215076706c95a17a68c19322ee916e40a3acd081a8c1a1e839e0194afa57'


def main():
    token = os.environ['SONAR_TOKEN']
    base = os.environ.get('SONAR_HOST_URL', 'http://127.0.0.1:9000').rstrip('/')
    if urllib.parse.urlparse(base).hostname not in {'localhost', '127.0.0.1'}:
        raise ValueError('El procedimiento esta restringido al SonarQube local.')
    authorization = 'Basic ' + base64.b64encode((token + ':').encode()).decode()

    def api(path, params=None, post=False):
        query = urllib.parse.urlencode(params or {})
        url = base + '/api/' + path
        if query and not post:
            url += '?' + query
        request = urllib.request.Request(
            url, data=query.encode() if post else None,
            headers={'Authorization': authorization},
        )
        with urllib.request.urlopen(request, timeout=30) as response:
            return json.load(response)

    EVIDENCE.mkdir(parents=True, exist_ok=True)
    version = api('system/status')['version']
    manifest = {'createdUtc': datetime.datetime.now(datetime.timezone.utc).isoformat(),
                'sonarVersion': version, 'projects': [],
                'scope': 'Original docente y ejemplo complementario de autenticacion; no son el mismo programa.'}
    for label, key, source in PROJECTS:
        report = EVIDENCE / f'bandit-{label}.json'
        bandit = subprocess.run(
            [sys.executable, '-m', 'bandit', '-f', 'json', '-o', str(report), source],
            cwd=ROOT, capture_output=True, text=True,
        )
        if bandit.returncode not in (0, 1):
            raise RuntimeError('Bandit fallo: ' + bandit.stderr)
        data = json.loads(report.read_text(encoding='utf-8'))
        if data.get('errors'):
            raise RuntimeError('Bandit no pudo analizar todos los archivos.')
        # Conservar rutas relativas portables para su importacion desde Docker.
        for result in data['results']:
            result['filename'] = source
        report.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding='utf-8')
        existing = api('components/search', {'qualifiers': 'TRK', 'q': key})
        if not any(x['key'] == key for x in existing['components']):
            api('projects/create', {'project': key, 'name': key}, post=True)
        env = os.environ.copy()
        # El token solo viaja en el entorno del proceso; no se imprime ni se versiona.
        env['SONAR_SCANNER_OPTS'] = f'-Dproject.settings=fase_a/sonar-{label}.properties -Dsonar.login={token}'
        command = ['docker', 'run', '--rm', '-e', 'SONAR_SCANNER_OPTS',
                   '-e', 'SONAR_HOST_URL=http://host.docker.internal:9000',
                   '-v', str(ROOT) + ':/usr/src', SCANNER_IMAGE]
        scanner = subprocess.run(command, cwd=ROOT, env=env, capture_output=True, text=True, timeout=300)
        log = (scanner.stdout + scanner.stderr).replace(token, '[REDACTED]')
        (EVIDENCE / f'scanner-{label}.log').write_text(log, encoding='utf-8')
        if scanner.returncode:
            raise RuntimeError(f'SonarScanner fallo en {label}; consultar el log redactado.')
        # La imagen Docker guarda su directorio de trabajo en /tmp/.scannerwork.
        # La URL publica de la tarea tambien aparece en la salida del scanner.
        match = re.search(r'/api/ce/task\?id=([A-Za-z0-9_-]+)', log)
        if not match:
            raise RuntimeError('El scanner no devolvio un identificador de tarea.')
        deadline = time.monotonic() + 180
        while True:
            job = api('ce/task', {'id': match.group(1)})['task']
            if job['status'] in {'SUCCESS', 'FAILED', 'CANCELED'}:
                break
            if time.monotonic() > deadline:
                raise TimeoutError('SonarQube no completo el procesamiento en tres minutos.')
            time.sleep(2)
        if job['status'] != 'SUCCESS':
            raise RuntimeError(f'El servidor no completo el analisis de {label}.')
        result = {
            'project': key, 'source': source,
            'sha256': hashlib.sha256((ROOT / source).read_bytes()).hexdigest(),
            'analysisId': job['analysisId'],
            'generatedUtc': datetime.datetime.now(datetime.timezone.utc).isoformat(),
            'issues': api('issues/search', {'componentKeys': key, 'ps': 500}),
            'hotspots': api('hotspots/search', {'projectKey': key, 'ps': 500}),
            'measures': api('measures/component', {'component': key, 'metricKeys': 'vulnerabilities,bugs,code_smells,security_hotspots,ncloc,security_rating,duplicated_lines_density'}),
            'qualityGate': api('qualitygates/project_status', {'projectKey': key}),
        }
        (EVIDENCE / f'sonarqube-{label}.json').write_text(
            json.dumps(result, ensure_ascii=False, indent=2), encoding='utf-8')
        manifest['projects'].append({'label': label, 'project': key, 'source': source,
                                     'sha256': result['sha256'], 'analysisId': job['analysisId']})
        print(f'{label}: incidencias={result["issues"]["total"]}, hotspots={result["hotspots"]["paging"]["total"]}, Quality Gate={result["qualityGate"]["projectStatus"]["status"]}', flush=True)
    (EVIDENCE / 'manifest.json').write_text(json.dumps(manifest, ensure_ascii=False, indent=2), encoding='utf-8')


if __name__ == '__main__':
    main()
