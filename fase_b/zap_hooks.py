"""Escaneo activo restringido al laboratorio de la fase B."""

import json
import os
from pathlib import Path


def start_zap(port, extra_zap_params):
    # Usar las reglas incluidas en la imagen estable para que el laboratorio
    # no dependa de descargas de complementos durante el arranque.
    params = ['-silent']
    iterator = iter(extra_zap_params)
    for value in iterator:
        if value == '-addonupdate':
            continue
        if value == '-addoninstall':
            next(iterator, None)
            continue
        params.append(value)
    return port, params


def zap_started(zap, target):
    if target.rstrip('/') != 'http://host.docker.internal:5011':
        raise ValueError('Este escaneo requiere el laboratorio local del puerto 5011.')
    zap.spider.set_option_process_form(True)
    zap.spider.set_option_post_form(True)
    # Simulacion dirigida del caso 2, enviada por ZAP antes del recorrido.
    # Permite conservar el intercambio HTTP incluso si no genera una alerta especifica.
    zap.urlopen(target.rstrip('/') + '/age?age=abc')
    print('FASE B: laboratorio local en 5011; pruebas de comentarios y edad habilitadas.')


def zap_pre_shutdown(zap):
    evidence = {'source': 'ZAP API', 'alerts': [], 'error_responses': [], 'age_requests': []}
    for alert in zap.core.alerts(baseurl='http://host.docker.internal:5011/'):
        if str(alert.get('pluginId')) in {'40012', '40014', '40026', '30001', '10023', '90022'}:
            evidence['alerts'].append({'alert': alert,
                                       'http': zap.core.message(alert['messageId'])})
    for message in zap.core.messages(baseurl='http://host.docker.internal:5011/age', count=1000):
        if '/age?age=abc ' in message.get('requestHeader', '') and len(evidence['age_requests']) < 2:
            evidence['age_requests'].append(message)
        if 'Traceback (most recent call last)' in message.get('responseBody', ''):
            evidence['error_responses'].append(message)
            if len(evidence['error_responses']) == 3:
                break
    evidence_name = os.environ.get('ZAP_EVIDENCE_NAME', 'evidencias-casos.json')
    if Path(evidence_name).name != evidence_name:
        raise ValueError('El nombre de evidencia debe ser un archivo sin directorios.')
    Path('/zap/wrk', evidence_name).write_text(
        json.dumps(evidence, ensure_ascii=False, indent=2), encoding='utf-8')
