from flask import Blueprint, render_template, make_response, redirect, request
from middlewares.auth_middleware import token_requerido
from models.db import db, Session

views_bp = Blueprint('views', __name__)

# Al entrar a la raíz, se muestra la visual del Login
@views_bp.route('/')
def pagina_login():
    return render_template('login.html')

# Vista publica del formulario de auto-registro (siempre crea rol 'user')
@views_bp.route('/registro')
def pagina_registro():
    return render_template('registro.html')

# Al entrar a /admin/dashboard, usamos nuestro middleware para proteger la vista web
@views_bp.route('/admin/dashboard')
@token_requerido(rol_requerido='admin')
def pagina_dashboard(usuario_actual):
    # Pasamos el usuario dinámicamente al HTML usando Jinja2
    return render_template('dashboard.html', usuario=usuario_actual)

# Ruta para borrar las cookies y cerrar sesión de forma segura (revoca la sesion en BD)
@views_bp.route('/logout')
def logout():
    sid = request.cookies.get('session_cookie')
    if sid:
        sesion = Session.query.get(sid)
        if sesion:
            sesion.revocada = True
            db.session.commit()
    respuesta = make_response(redirect('/'))
    respuesta.delete_cookie('session_cookie')
    return respuesta

@views_bp.route('/perfil')
@token_requerido() # Cualquier usuario autenticado
def pagina_perfil(usuario_actual):
    return render_template('perfil.html', usuario=usuario_actual)