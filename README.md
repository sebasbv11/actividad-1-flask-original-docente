# Actividad 1 Aplicación Flask original del docente

## Trabajo de la fase A en la rama sonarqube

La aplicación original permanece en `app.py`, sin cambios respecto de `main`.
El análisis se documenta en [`fase_a/INFORME.md`](fase_a/INFORME.md), con tres
proyectos locales de SonarQube: original docente, ejemplo complementario
vulnerable y ejemplo corregido. Los casos SQL/contraseñas pertenecen al ejemplo
de autenticación, no a la aplicación original de clientes. Esta distinción y
el requisito de confirmar la fuente vulnerable designada por el docente se
explican en el informe.

Los reportes reales, las cuatro capturas nuevas y el resumen de cuatro pruebas
correctas están en `fase_a/evidencias/`. El documento Word revisado está en
[`fase_a/Informe_SAST_DAST_Fase_A_revisada.docx`](fase_a/Informe_SAST_DAST_Fase_A_revisada.docx).
Su sección B se conserva como evidencia histórica y no acredita una nueva
ejecución DAST en la rama `owasp-zap`.

## Código de la primera actividad

Transcripción del código de la guía **Unidad2_AnalisisEsSAST.pdf**, titulada
«Implementación de análisis estático de código», páginas 1 a 11.

Permite registrar nombre y correo de clientes en `clients.csv` y ejecutar
Bandit y pip-audit desde `/security_scan`.

## Fidelidad a la guía

Se reconstruyeron la indentación, los saltos de línea partidos por el PDF y los
identificadores `__name__` y `__main__`. Las carpetas se llaman `templates` y
`static`, como indica la guía. Los símbolos de estado de la interfaz se
representan con caracteres Unicode.

Se conserva el comportamiento original: comandos con `subprocess.run`, uso de
`os.getcwd()`, versiones de dependencias y escucha en `0.0.0.0:5000`.
No contiene las correcciones de seguridad ni los ejemplos de autenticación,
SonarQube o ZAP añadidos en la práctica posterior.

Se conserva también la clave `skips` duplicada de `.bandit.yml` de las páginas
10 y 11 y la referencia `dummy.py`, aunque la guía no proporciona ese archivo.
Estos son detalles del material de origen, pendientes de revisión. La salida
JSON de pip-audit puede requerir adaptar su lectura y la plantilla para mostrar
correctamente las vulnerabilidades; este repositorio conserva la versión del docente.

## Ejecutar desde CMD en Windows

```bat
python -m venv venv
venv\Scripts\activate
python -m pip install -r requirements.txt
python app.py
```

Abrir http://127.0.0.1:5000/. En PowerShell, activar con
`.\venv\Scripts\Activate.ps1`.

`clients.csv` se crea al guardar el primer cliente y no se incluye en Git.
Utilizar datos de prueba. Este material es una base académica sin endurecimiento
para producción; no constituye una versión corregida ni una auditoría aprobada.
