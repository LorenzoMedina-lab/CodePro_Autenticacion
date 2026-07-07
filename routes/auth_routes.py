from flask import Blueprint, current_app, request, jsonify, make_response
from controllers.auth_controller import registrar_usuario, autenticar_usuario
from middlewares.auth_middleware import token_requerido

auth_bp = Blueprint('auth', __name__) # Blueprint para las rutas de autenticación

@auth_bp.route('/register', methods=['POST'])
def register():
    datos = request.get_json()
    resultado = registrar_usuario(
        datos.get('username'), 
        datos.get('password'), 
        datos.get('role', 'user')
    )
    return jsonify(resultado), resultado["status"]

@auth_bp.route('/login', methods=['POST'])
def login():
    # Obtenemos el limiter que configuramos en app.py
    limiter = current_app.config['LIMITER']
    
    # Decoramos esta función manualmente al vuelo para protegerla
    @limiter.limit("5 per minute")
    def ejecutar_login():
        datos = request.get_json()
        resultado = autenticar_usuario(datos.get('username'), datos.get('password'))
        
        if "error" in resultado:
            return jsonify(resultado), resultado["status"]

        respuesta = make_response(jsonify(resultado))
        respuesta.set_cookie(
            'session_cookie', 
            resultado["token"], 
            httponly=True, 
            secure=False, 
            samesite='Lax', 
            max_age=7200
        )
        return respuesta, resultado["status"]
    
    return ejecutar_login()

# --- RUTAS PROTEGIDAS PARA PROBAR EL MIDDLEWARE ---

@auth_bp.route('/perfil', methods=['GET'])
@token_requerido() # Cualquier usuario logueado
def ver_perfil(usuario_actual):
    return jsonify({"mensaje": f"Bienvenido a tu perfil, {usuario_actual}"}), 200

@auth_bp.route('/admin/dashboard', methods=['GET'])
@token_requerido(rol_requerido='admin') # Solo administradores
def panel_administrador(usuario_actual):
    return jsonify({"mensaje": f"Hola Administrador {usuario_actual}"}), 200