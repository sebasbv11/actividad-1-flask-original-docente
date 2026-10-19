"""Visor local de solo lectura para las alertas y respuestas exportadas por ZAP."""

from collections import Counter
import hashlib
import html
from http.server import BaseHTTPRequestHandler, HTTPServer
import json
from pathlib import Path
import re
from urllib.parse import parse_qs, urlparse

OUT = Path(__file__).resolve().parent / 'evidencias'


def load(mode):
    raw = (OUT / ('reporte-' + mode + '.json')).read_bytes()
    data = json.loads(raw.decode('utf-8-sig'))
    evidence = json.loads((OUT / ('evidencias-' + mode + '.json')).read_text(encoding='utf8'))
    alerts = [a for s in data.get('site', []) for a in s.get('alerts', [])]
    return raw, data, evidence, alerts


def e(value):
    return html.escape(str(value))


def page(mode, case):
    raw, report, evidence, alerts = load(mode)
    counts = Counter(a['riskcode'] for a in alerts)
    wanted = {'40012', '40014'} if case == 'xss' else {'90022'}
    selected = next((a for a in alerts if a['pluginid'] == ('40014' if case == 'xss' else '90022')), None)
    if selected is None:
        selected = next((a for a in alerts if a['pluginid'] in wanted), None)
    result = '<h2>' + ('Caso 4 · XSS almacenado' if case == 'xss' else 'Caso 2 · Exposición de errores') + '</h2>'
    if selected:
        instance = selected.get('instances', [{}])[0]
        rows = [('Regla', selected['pluginid'] + ' · ' + selected['name']),
                ('Severidad / confianza', selected['riskdesc']),
                ('URL', instance.get('uri', '')),
                ('Parámetro', instance.get('param', '')),
                ('Carga / evidencia', instance.get('attack') or instance.get('evidence', ''))]
        result += '<table>' + ''.join('<tr><th>'+e(k)+'</th><td>'+e(v)+'</td></tr>' for k,v in rows) + '</table>'
    else:
        result += '<p class="ok">Sin alertas ' + e(', '.join(sorted(wanted))) + ' en este informe.</p>'
    if case == 'error':
        messages = evidence.get('error_responses') or evidence.get('age_requests') or []
        if messages:
            message = messages[0]
            body = message.get('responseBody', '')
            start = body.find('Traceback')
            if start >= 0:
                body = html.unescape(body[start:].split('</pre>')[0])
            else:
                body = html.unescape(re.sub('<[^>]+>', '', body)).strip()
            fragment = message.get('responseHeader', '').splitlines()[0] + '\n' + body[:900]
            result += '<h3>Fragmento de respuesta HTTP exportada por ZAP</h3><pre>'+e(fragment)+'</pre>'
    else:
        checks = json.loads((OUT/'pruebas-funcionales.json').read_text(encoding='utf8'))
        check = next(c for c in checks if c['mode'] == mode)
        result += '<p>Comprobación HTTP independiente: script sin escapar = <b>'+e(check['rawScript'])+'</b>; script escapado = <b>'+e(check['escapedScript'])+'</b>.</p>'
    risks = [('3', 'Alta'), ('2', 'Media'), ('1', 'Baja'), ('0', 'Informativa')]
    summary = '<table class="summary"><tr>' + ''.join('<th>'+name+'</th>' for _,name in risks) + '</tr><tr>' + ''.join('<td>'+str(counts[code])+'</td>' for code,_ in risks) + '</tr></table>'
    return '''<!doctype html><html lang="es"><meta charset="utf-8"><title>Resultados locales de ZAP</title>
<style>body{font:16px Arial;margin:30px auto;max-width:1220px;color:#172b3a;background:#fff}h1{font-size:27px;margin-bottom:10px}h2{font-size:21px;margin:22px 0 12px}h3{font-size:16px}nav{margin:16px 0}a{color:#075b9a;margin-right:20px}table{border-collapse:collapse;width:100%;margin:14px 0}th,td{border:1px solid #bccbd3;padding:9px;text-align:left}th{background:#edf3f6;width:180px}.summary th,.summary td{text-align:center;width:25%}.summary td{font-size:24px;font-weight:bold}pre{background:#f1f4f6;padding:14px;white-space:pre-wrap;font:14px Consolas;overflow-wrap:anywhere}.ok{background:#e4f6e7;padding:14px}footer{border-top:1px solid #ccd6dc;padding-top:14px;font-size:13px;color:#53636d}</style>
<h1>Resultados del escaneo ZAP · '''+e(mode)+'''</h1><p>Vista de apoyo basada en los archivos reales del análisis. Destino: http://host.docker.internal:5011/</p>
<nav><a href="/?modo=vulnerable&caso='''+case+'''">Antes de corregir</a><a href="/?modo=corregido&caso='''+case+'''">Después de corregir</a><a href="/?modo='''+mode+'''&caso=xss">Ver XSS</a><a href="/?modo='''+mode+'''&caso=error">Ver errores</a></nav>'''+summary+result+'''<footer>Fuente: reporte-'''+mode+'''.json · SHA-256: '''+hashlib.sha256(raw).hexdigest()[:16]+''' · <a href="/datos?modo='''+mode+'''">Abrir JSON original</a> · <a href="/http?modo='''+mode+'''">Abrir evidencia HTTP</a></footer></html>'''


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        query = urlparse(self.path)
        params = parse_qs(query.query)
        mode = params.get('modo', ['vulnerable'])[0]
        case = params.get('caso', ['xss'])[0]
        if mode not in {'vulnerable', 'corregido'} or case not in {'xss', 'error'} or query.path not in {'/', '/datos', '/http'}:
            self.send_error(404)
            return
        try:
            if query.path == '/datos':
                data = (OUT/('reporte-'+mode+'.json')).read_bytes()
                mime = 'application/json'
            elif query.path == '/http':
                data = (OUT/('evidencias-'+mode+'.json')).read_bytes()
                mime = 'application/json'
            else:
                data = page(mode, case).encode('utf8')
                mime = 'text/html'
        except FileNotFoundError:
            self.send_error(503, 'El escaneo aun no ha generado sus resultados.')
            return
        self.send_response(200)
        self.send_header('Content-Type', mime+'; charset=utf-8')
        self.send_header('Content-Length', str(len(data)))
        self.send_header('X-Content-Type-Options', 'nosniff')
        self.send_header('Content-Security-Policy', "default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; frame-ancestors 'none'")
        self.end_headers()
        self.wfile.write(data)


if __name__ == '__main__':
    print('Visor de resultados: http://127.0.0.1:5019/', flush=True)
    HTTPServer(('127.0.0.1', 5019), Handler).serve_forever()
