from flask import Blueprint, request, jsonify, make_response
from flask_wtf.csrf import generate_csrf, validate_csrf
from wtforms.validators import ValidationError
from controllers.auth_controller import registrar_usuario, autenticar_usuario
from middlewares.auth_middleware import token_requerido
from models.db import db, Session
import uuid
import datetime

auth_bp = Blueprint('auth', __name__) # Blueprint para las rutas de autenticación

def _validar_csrf_web():
    """
    Valida el token CSRF SOLO para clientes web (basados en cookies).
    Los clientes moviles usan el header 'Authorization: Bearer' y quedan exentos.
    Devuelve un dict de error si la validacion falla, o None si es valida/exenta.
    """
    if request.headers.get('Authorization'):
        return None  # Cliente movil (stateless): no requiere CSRF

    token = request.headers.get('X-CSRFToken')
    try:
        validate_csrf(token)
    except ValidationError:
        return {"error": "Token CSRF invalido o ausente"}
    return None

@auth_bp.route('/csrf-token', methods=['GET'])
def obtener_csrf_token():
    # El frontend web solicita este token al cargar y lo reenvia en el header X-CSRFToken
    return jsonify({"csrf_token": generate_csrf()}), 200

@auth_bp.route('/register', methods=['POST']) # Ruta de registro de usuario
def register(): # Solo se permite registro de usuarios web/moviles; no requiere token previo
    error_csrf = _validar_csrf_web()
    if error_csrf:
        return jsonify(error_csrf), 403

    datos = request.get_json()
    # Por seguridad el controlador ignora cualquier 'role' enviado por el cliente
    # y fuerza 'user' (prevencion de escalada de privilegios via auto-registro).
    resultado = registrar_usuario(
        datos.get('email'),
        datos.get('password')
    )
    status = resultado.pop("status", 200)
    return jsonify(resultado), status

@auth_bp.route('/login', methods=['POST']) # Ruta de login de usuario
def login():
    error_csrf = _validar_csrf_web()
    if error_csrf:
        return jsonify(error_csrf), 403

    datos = request.get_json()
    resultado = autenticar_usuario(datos.get('email'), datos.get('password'))
    status = resultado.pop("status", 200)

    if "error" in resultado:
        return jsonify(resultado), status

    # Flujo WEB (stateful): la cookie guarda un identificador de sesion OPACO (uuid),
    # no el JWT. El JWT sigue en el body para clientes moviles (Bearer).
    sid = uuid.uuid4().hex
    nueva_sesion = Session(
        id_session=sid,
        user_id=resultado["user_id"],
        expira_en=datetime.datetime.utcnow() + datetime.timedelta(hours=2)
    )
    db.session.add(nueva_sesion)
    db.session.commit()

    # Quitamos user_id del cuerpo (no debe regresar al cliente)
    resultado.pop("user_id", None)

    respuesta = make_response(jsonify(resultado))
    respuesta.set_cookie(
        'session_cookie',
        sid,
        httponly=True,  # Protege la cookie de accesos desde JS (XSS)
        secure=False,  # PRODUCCION: cambiar a True (servir sobre HTTPS)
        samesite='Lax', # Protege contra CSRF en navegadores modernos
        max_age=7200    # 2 horas de expiracion
    )
    return respuesta, status

# --- RUTAS PROTEGIDAS PARA PROBAR EL MIDDLEWARE ---

@auth_bp.route('/perfil', methods=['GET']) # Ruta protegida para ver el perfil del usuario logueado
@token_requerido() # Cualquier usuario logueado
def ver_perfil(usuario_actual):
    return jsonify({"mensaje": f"Bienvenido a tu perfil, {usuario_actual}"}), 200

@auth_bp.route('/admin/dashboard', methods=['GET']) # Ruta protegida para el panel de administrador
@token_requerido(rol_requerido='admin') # Solo administradores
def panel_administrador(usuario_actual):
    return jsonify({"mensaje": f"Hola Administrador {usuario_actual}"}), 200