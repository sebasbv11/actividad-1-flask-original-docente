# Fase A Análisis estático con SonarQube

## Resumen ejecutivo y procedencia del código

El 19 de octubre de 2026 se ejecutaron tres análisis locales separados en
SonarQube Community Edition 9.9.8.100196, con SonarScanner CLI 8.1.0.6389 y
Bandit 1.7.5. El ejemplo de autenticación vulnerable registró tres incidencias
importadas y dos Security Hotspots nativos. Su versión corregida registró cero
incidencias y cero hotspots. Las cuatro pruebas funcionales posteriores pasaron.

Se distinguen dos fuentes. `app.py` reproduce la aplicación de clientes de
`Unidad2_AnalisisEsSAST.pdf`: formulario de nombre/correo, almacenamiento CSV y
ejecución de Bandit/pip-audit. No contiene consultas SQL ni contraseñas. El
ejemplo `login_sga_vulnerable.py` procede del material de trabajo del informe
anterior y de su ejemplo complementario de autenticación. Se reutilizó por
solicitud del equipo para reproducir los casos 1 y 3; no se afirma que haya sido
proporcionado por el docente ni que forme parte de la aplicación de clientes.
Las contraseñas de ese ejemplo son sintéticas.

La segunda guía exige código vulnerable del docente con los casos 1 y 3. El
archivo de clientes recibido no incluye esos casos. La ejecución técnica está
documentada, pero la correspondencia con ese requisito de procedencia queda
condicionada a confirmar o recibir el código vulnerable designado por el docente.

`main` conserva la versión original. Esta revisión pertenece a `sonarqube`;
`owasp-zap` está reservada para la fase B. No se reemplazó `app.py` por un login.
La etiqueta `main` de las capturas identifica la rama predeterminada de cada
proyecto local de SonarQube; no indica que se haya modificado la rama Git `main`.

## 1 Inicialización y análisis sin ejecutar la aplicación

El servidor local `cdss-sonarqube` estaba iniciado en Docker y su API confirmó
estado `UP` en `http://127.0.0.1:9000`. Se crearon tres proyectos nuevos:

| Proyecto | Archivo analizado | Origen |
| --- | --- | --- |
| actividad1-a-docente | app.py | Aplicación original del docente |
| actividad1-a-casos-vulnerable | fase_a/login_sga_vulnerable.py | Ejemplo complementario de los casos 1 y 3 |
| actividad1-a-casos-corregido | fase_a/login_sga_refactorizado.py | Refactorización del ejemplo |

Cada archivo `sonar-*.properties` limita el análisis a la fuente indicada;
excluye entornos virtuales, documentos y evidencias. El script
`ejecutar_analisis.py` genera los informes Bandit y los importa mediante
`sonar.python.bandit.reportPaths`. Espera a que la tarea del servidor termine y
exporta incidencias, hotspots, métricas y Quality Gate desde la API. Los SHA-256
y los identificadores de análisis están en `evidencias/manifest.json`.

No se inició Flask ni se ejecutó el login durante estos análisis. Las pruebas
funcionales se ejecutaron después, como verificación independiente. El entorno
de ejecución usa Python 3.13.3; SonarQube 9.9 declara en los logs que utiliza
compatibilidad de análisis Python 3.10 al recibir la versión 3.13.

La instalación es un entorno académico existente: su interfaz advierte que
9.9 ya no es una versión activa y utiliza la base integrada. No se presenta
como configuración de producción ni se confunde con SonarQube Cloud de GitHub.

## 2 Hallazgos reales y líneas exactas

### Código original del docente

| Regla | Línea en app.py | Severidad registrada | Interpretación |
| --- | ---: | --- | --- |
| Bandit B404 | 2 | MINOR | Revisar el uso de subprocess |
| Bandit B603 | 49 | MINOR | Revisar la ejecución interna de Bandit |
| Bandit B603 | 82 | MINOR | Revisar la ejecución interna de pip-audit |
| Bandit B104 | 108 | MAJOR | Escucha en todas las interfaces con 0.0.0.0 |
| python:S4502 | 9 | Hotspot pendiente de revisión | Revisar la protección CSRF de la aplicación Flask |

Las cuatro incidencias son importadas de Bandit. S4502 es una revisión nativa,
no una vulnerabilidad explotada. B404 y B603 no prueban inyección de comandos:
las listas de argumentos son internas y no incorporan entradas del formulario.
La escucha global requiere justificar el alcance de red. Estos avisos se
conservan como resultado de la línea base; no se atribuyen a los casos SQL y
contraseñas, que no existen en este archivo.

### Ejemplo complementario vulnerable

| Caso | Regla | Línea | Severidad registrada | Evidencia y efecto |
| --- | --- | ---: | --- | --- |
| 1 Inyección SQL | external_bandit:B608 | 53, bloque 52-55 | MAJOR | usuario y clave concatenados a la consulta |
| 3 Credencial incrustada | external_bandit:B105 | 13 | MINOR | PASSWORD_ESTUDIANTE en el archivo |
| 3 Credencial incrustada | external_bandit:B105 | 14 | MINOR | PASSWORD_DOCENTE en el archivo |
| 3 Revisión de credenciales | python:S2068 | 13 y 14 | Dos hotspots, prioridad HIGH | Detección nativa de credenciales potencialmente incrustadas |

Los B105 y B608 son resultados externos, visibles en SonarQube; no son
detecciones SQL nativas del motor Python de esta instalación. SonarQube no
ejecuta Bandit: el script genera el informe antes de importarlo. Ninguna
incidencia quedó clasificada como CRITICAL o BLOCKER. No se modificó su
severidad para ajustarla al texto de la guía. Los dos hotspots no se suman a
las tres incidencias como si fueran cinco vulnerabilidades independientes.

## 3 Resolución y sintaxis segura

En el caso 1, la versión vulnerable construye una consulta cuya estructura
puede alterarse con el usuario recibido. Su clasificación es CWE-89 y
A05:2025 Inyección. Afecta confidencialidad e integridad; la eliminación de
cuentas descrita por la guía afecta principalmente integridad y también la
disponibilidad de la cuenta. La prueba local usa un bypass de autenticación;
no ejecuta borrados ni afirma reproducir exactamente el DELETE de la guía.

```python
# Vulnerable: lineas 52-55 de login_sga_vulnerable.py
consulta = (
    "SELECT rol FROM usuarios "
    "WHERE login='" + usuario + "' AND clave='" + clave + "'"
)
```

La corrección, en las líneas 73-77 de `login_sga_refactorizado.py`, separa el
texto SQL de los datos. La contraseña se verifica contra el hash, no por
concatenación a una condición SQL.

```python
fila = conexion.execute(
    "SELECT clave_hash, rol FROM usuarios WHERE login = ?",
    (usuario,),
).fetchone()
```

En el caso 3 se eliminaron las contraseñas incrustadas del módulo corregido.
La función recibe usuarios y credenciales desde el llamador (líneas 37-40);
almacena hashes bcrypt con sal aleatoria y costo 12 (líneas 29-34 y 51-56) y
los verifica en las líneas 79-85. Credenciales incrustadas corresponden a
CWE-259/CWE-798 y A07:2025 Fallas de autenticación; almacenamiento en texto
claro se relaciona además con A04:2025 Fallas criptográficas. Las credenciales
sintéticas de las pruebas permanecen en el archivo de pruebas, fuera de la
fuente corregida analizada; no se afirma que todo el repositorio esté libre de
cadenas de ejemplo.

```python
return bcrypt.hashpw(
    clave.encode("utf-8"), bcrypt.gensalt(rounds=12)
).decode("utf-8")
```

Como defensa complementaria, `LimitadorIntentos` conserva fallos por usuario
(líneas 12-26) y se consulta en las líneas 69-71. El bloqueo requiere reutilizar
la misma instancia entre intentos. Es una demostración local en memoria, sin
expiración ni almacenamiento distribuido; no se presenta como solución final
de fuerza bruta. El módulo corregido devuelve resultados genéricos y no imprime
la consulta. La impresión del ejemplo vulnerable ocurre en consola y no se
presenta como una traza HTTP ni como evidencia DAST del caso 2.

## 4 Comparación y validación

| Medida total | Original docente | Ejemplo vulnerable | Ejemplo corregido |
| --- | ---: | ---: | ---: |
| Incidencias importadas como vulnerabilidades | 4 | 3 | 0 |
| Hotspots nativos pendientes | 1 | 2 | 0 |
| Bugs | 0 | 0 | 0 |
| Code smells | 0 | 0 | 0 |
| Líneas no comentadas | 86 | 44 | 67 |
| Security Rating | C | C | A |
| Quality Gate observado | OK | OK | OK |

El Quality Gate no demuestra ausencia de hallazgos: en los dos proyectos de
ejemplo el servidor devolvió una lista vacía de condiciones evaluadas; la línea
base del docente usa condiciones de código nuevo. Por eso se comparan los
totales y la evidencia de las reglas, no solo el color verde. No se ajustó la
puerta de calidad para forzar un resultado deseado.

Cuatro pruebas posteriores finalizaron con `OK`: las credenciales válidas
funcionan en ambas versiones; la carga `' OR '1'='1' --` obtiene acceso en la
vulnerable y es rechazada en la corregida; el valor almacenado es un hash bcrypt
y no la contraseña; y cinco fallos bloquean un acceso posterior con la misma
instancia del limitador. Se conserva el resumen en
`evidencias/pruebas-funcionales.json`.

La comparación acredita la corrección del vector ensayado en el ejemplo, no
la seguridad de toda la aplicación de clientes, todas las dependencias o un
despliegue de producción. La línea base original permanece sin modificaciones.

## 5 Capturas y evidencia verificable

- A1-docente.jpg: métricas totales del original; cuatro incidencias y un hotspot.
- A2-vulnerable-incidencias.jpg: B105 en 13/14 y B608 en 53, con sus severidades.
- A3-vulnerable-hotspots.jpg: dos hotspots nativos S2068 en el ejemplo.
- A4-corregido.jpg: cero incidencias y cero hotspots en el ejemplo corregido.
- bandit-*.json: resultados externos antes de importarlos.
- sonarqube-*.json: respuestas de la API con líneas, métricas e identificadores.
- scanner-*.log: salida real redactada para no guardar el token.
- manifest.json: procedencia de archivos, hashes y tareas de análisis.

Las capturas se tomaron de la interfaz local durante esta ejecución. No son
imágenes generadas ni reutilizadas como si fueran resultados nuevos.

## 6 Reproducción

Desde la raíz del repositorio, rama `sonarqube`, con Docker disponible y el
servidor local iniciado:

```powershell
.\venv\Scripts\python.exe -m pip install -r fase_a/requirements.txt
$env:SONAR_TOKEN = Read-Host 'Token del SonarQube local'
.\venv\Scripts\python.exe fase_a/ejecutar_analisis.py
Remove-Item Env:SONAR_TOKEN
.\venv\Scripts\python.exe -m unittest discover -s fase_a -p test_fase_a.py -v
```

El token debe tener permisos de crear proyectos y ejecutar análisis. No se
incluye en archivos versionados ni en la línea de comandos del contenedor.
Los análisis estáticos y las pruebas funcionales son pasos separados.
`requirements-lock.txt` conserva las versiones instaladas y el script fija la
imagen del scanner por digest. `evidencias/entorno.json` identifica las imágenes.

## 7 Correspondencia con la rúbrica y conclusión

| Criterio | Evidencia y alcance |
| --- | --- |
| Identificación teórica 30 % | El cuadro de los seis escenarios del documento distingue CIA, OWASP 2025 y SAST/DAST. Es teoría, no seis defectos confirmados en app.py. |
| Resultados de SonarQube 25 % | Tres proyectos locales, informes válidos, líneas exactas, cuatro capturas y correcciones. La procedencia docente del ejemplo de los casos 1/3 no se puede acreditar con el material recibido. |
| Resultados de ZAP 25 % | Corresponde a la fase B; no se ejecutó ni se revalidó ZAP en esta rama. La sección B del documento de origen es evidencia histórica del laboratorio anterior. |
| Precisión y mitigación 20 % | Consulta parametrizada, bcrypt, manejo genérico, límites del bloqueo, distinción entre motores y validación funcional. |

Se completó el análisis técnico de la fase A sobre fuentes identificadas y se
verificó la refactorización del ejemplo. El código original del docente no
contiene los casos SQL y contraseñas; su informe de cuatro advertencias y un
hotspot se conserva por separado. Para afirmar cumplimiento literal del punto
que exige código vulnerable entregado por el docente, debe confirmarse que el
ejemplo complementario es el escenario aceptado o recibirse la fuente designada.

## Referencias

- Unidad2_AnalisisEsSAST.pdf, aplicación original, páginas 1-11.
- Unidad 2 2_2 2_3 guia.pdf, seis casos, fase A y rúbrica, páginas 1-2.
- Informe del equipo entregado en ODT, material previo de autenticación.
- https://docs.sonarsource.com/sonarqube-server/9.9/analyzing-source-code/importing-external-issues/importing-third-party-issues
- https://top10.owasp.org/2025/A05_2025-Injection/
- https://top10.owasp.org/2025/A07_2025-Authentication_Failures/
- https://top10.owasp.org/2025/A04_2025-Cryptographic_Failures/
- https://github.com/sebasbv11/actividad-1-flask-original-docente/tree/sonarqube
