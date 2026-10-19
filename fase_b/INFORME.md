# Fase B Análisis dinámico con OWASP ZAP

Se ejecutó ZAP 2.17.0 en Docker contra `http://host.docker.internal:5011/`,
con `zap-full-scan.py`, rastreo de formularios y escaneo activo. Se analizaron
por separado las variantes vulnerable y corregida del laboratorio.

`lab_app.py` añade comentarios y validación de edad para reproducir los casos
4 y 2. Son ejemplos complementarios; el `app.py` original del docente conserva
su código y comportamiento. No contiene esos formularios.

## Resultados

| Comprobación | Vulnerable | Corregido |
| --- | --- | --- |
| XSS almacenado 40014 | Alta, confianza media | No detectado |
| XSS reflejado 40012 | Alta, confianza media | No detectado |
| Exposición de errores 90022 | Baja, confianza media | No detectada |
| Tipos de alertas altas | 2 | 0 |
| Medias | 4 | 3 |
| Bajas | 3 | 2 |
| Informativas | 1 | 1 |

Son tipos de alerta, no cantidades de ataques distintos. Los dos avisos XSS
se relacionan con el flujo de comentarios; no se presentan como dos causas
independientes.

**Caso 4.** ZAP inyectó el campo `comment` mediante `POST /comment`. El informe
registró `</li><script>alert(1);</script><li>`. La variante vulnerable usa
`{{ comment | safe }}`; la mitigada usa `{{ comment }}` y conserva el escape
automático de Jinja. La prueba funcional independiente confirma que el script
se convierte en texto escapado después de corregirlo.

**Caso 2.** El hook envió, a través de ZAP, la petición dirigida
`GET /age?age=abc`. La variante vulnerable devolvió HTTP 500 con `ValueError`
y rutas internas. La mitigada devuelve HTTP 400 con un mensaje genérico sin
traza. Una edad válida continúa devolviendo HTTP 200.

La alerta 30001, denominada Buffer Overflow por ZAP, se asocia a una respuesta
de error: la evidencia no demuestra un desbordamiento de memoria. Los avisos
restantes corresponden a CSRF, CSP, clickjacking, versión del servidor y nosniff.
La comparación verifica los vectores ensayados, no la seguridad completa.

## Evidencia

- `evidencias/reporte-vulnerable.*` y `reporte-corregido.*`: HTML y JSON originales.
- `evidencias/evidencias-*.json`: intercambios HTTP exportados por la API de ZAP.
- `evidencias/pruebas-funcionales.json`: script escapado, edad inválida y válida.
- `evidencias/comparacion.json` y `zap-*.log`: resumen y registros del escaneo.
- `B1-xss.jpg`, `B2-error.jpg` y `B3-corregido.jpg`: capturas del visor local
  de los JSON; no son capturas de la interfaz nativa de ZAP ni imágenes generadas.
- `Informe_SAST_DAST.docx`: versión resumida del documento del equipo.

La alerta 40014 se encuentra en el informe final. El exportador HTTP recoge
las alertas disponibles antes del cierre y las respuestas de error; no contiene
necesariamente todos los avisos que incorpora el informe final.

## Reproducción

Desde esta rama, con Python y Docker disponibles:

```powershell
python -m pip install -r fase_b/requirements.txt
python fase_b/ejecutar_dast.py
python fase_b/ver_resultados.py
```

El escáner levanta cada variante en el puerto 5011 y la detiene al terminar.
La imagen de ZAP está fijada por digest en el script. El puerto debe estar
libre. `--solo vulnerable` o `--solo corregido` permiten repetir una variante
si ya existen los resultados de la otra.

El visor de consulta se abre en http://127.0.0.1:5019/. Sirve los datos
guardados y escapa las cargas para mostrarlas sin ejecutarlas. Los enlaces
JSON permiten verificar el archivo original y la evidencia HTTP. También se
pueden abrir manualmente los informes HTML desde la carpeta de evidencias.

Para practicar manualmente: `python fase_b/lab_app.py`; añadir `--secure`
activa las mitigaciones. La dirección local es http://127.0.0.1:5011/.

## Alcance del informe

La fase A y sus fuentes se conservan en la rama `sonarqube`, con servidor
local en el puerto 9000. Los ejemplos añadidos para los casos 1 a 4 deben
confirmarse como escenarios aceptados por el docente. `main` conserva el
original. Las fechas de los metadatos automáticos de los informes se mantienen
para preservar la evidencia; se retiraron de la portada y la redacción del Word.
