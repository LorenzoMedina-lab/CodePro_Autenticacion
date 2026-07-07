from functools import wraps
from flask import request, jsonify
import jwt
import os
from dotenv import load_dotenv

load_dotenv()
SECRET_KEY = os.getenv('SECRET_KEY')

def token_requerido(rol_requerido=None):
    def decorador(f):
        @wraps(f)
        def funcion_protegida(*args, **kwargs):
            token = None
            
            # 1. Buscar en Cookies (Web)
            if 'session_cookie' in request.cookies:
                token = request.cookies.get('session_cookie')
            
            # 2. Buscar en Headers (Móvil)
            if not token and 'Authorization' in request.headers:
                partes = request.headers['Authorization'].split()
                if len(partes) == 2 and partes[0] == 'Bearer':
                    token = partes[1]

            if not token:
                return jsonify({"error": "Acceso denegado. Falta el token"}), 401

            try:
                # 3. Validar Token
                payload = jwt.decode(token, SECRET_KEY, algorithms=['HS256'])
                usuario_actual = payload['username']
                rol_actual = payload['role']

                # 4. Validar Rol
                if rol_requerido and rol_actual != rol_requerido:
                    return jsonify({"error": "Prohibido. No tienes permisos."}), 403

            except jwt.ExpiredSignatureError:
                return jsonify({"error": "El token ha expirado."}), 401
            except jwt.InvalidTokenError:
                return jsonify({"error": "Token inválido."}), 401

            return f(usuario_actual, *args, **kwargs)
        return funcion_protegida
    return decorador