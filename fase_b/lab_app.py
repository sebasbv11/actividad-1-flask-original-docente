"""Fase B: escenarios intencionalmente vulnerables, solo para pruebas locales.

Ejecutar: python fase_b/lab_app.py
Comparar la mitigacion: python fase_b/lab_app.py --secure
No usar datos reales ni publicar esta aplicacion en Internet.
"""

import argparse
import traceback

from flask import Flask, redirect, render_template, request, url_for


def create_app(secure=False):
    app = Flask(__name__, template_folder='lab_templates')
    app.config.update(DEBUG=False, TESTING=False)
    comments = []  # Datos sinteticos en memoria; se borran al reiniciar.

    @app.route('/')
    def index():
        return render_template('index.html', comments=comments, secure=secure)

    @app.route('/comment', methods=['POST'])
    def comment():
        comments.append(request.form.get('comment', '')[:2000])
        # Acotar la memoria durante el escaneo automatizado.
        del comments[:-100]
        return redirect(url_for('index'))

    @app.route('/age')
    def age():
        raw_age = request.args.get('age', '20')
        try:
            age_value = int(raw_age)
            if not 0 <= age_value <= 120:
                raise ValueError('La edad debe estar entre 0 y 120.')
            return render_template('age.html', age=age_value, error=None), 200
        except ValueError:
            if secure:
                app.logger.warning('Entrada de edad invalida')
                return render_template('age.html', age=None,
                                       error='Ingrese una edad entera entre 0 y 120.'), 400
            # CASO 2: fallo intencional. La respuesta revela rutas y codigo internos.
            # Se expone texto de la traza; el depurador interactivo permanece apagado.
            return render_template('error.html', trace=traceback.format_exc()), 500

    return app


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--secure', action='store_true', help='Activar las mitigaciones')
    args = parser.parse_args()
    create_app(secure=args.secure).run(host='127.0.0.1', port=5011, debug=False)
