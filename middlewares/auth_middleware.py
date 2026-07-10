from functools import wraps
from flask import request, jsonify
import jwt
import os
import datetime
from dotenv import load_dotenv
from cryptography.fernet import InvalidToken
from utils.security import descifrar
from models.db import Session, User

load_dotenv()
SECRET_KEY = os.getenv('SECRET_KEY')

def token_requerido(rol_requerido=None):
    def decorador(f):
        @wraps(f)
        def funcion_protegida(*args, **kwargs):
            usuario_actual = None
            rol_actual = None

            # 1. Flujo MOVIL (stateless): header Authorization: Bearer <JWT>
            if 'Authorization' in request.headers:
                partes = request.headers['Authorization'].split()
                if len(partes) == 2 and partes[0] == 'Bearer':
                    token = partes[1]
                    try:
                        payload = jwt.decode(token, SECRET_KEY, algorithms=['HS256'])
                        try:
                            usuario_actual = descifrar(payload['email_cif'])
                        except InvalidToken:
                            return jsonify({"error": "Token inválido (payload corrupto)."}), 401
                        rol_actual = payload['role']
                    except jwt.ExpiredSignatureError:
                        return jsonify({"error": "El token ha expirado."}), 401
                    except jwt.InvalidTokenError:
                        return jsonify({"error": "Token inválido."}), 401

            # 2. Flujo WEB (stateful): cookie 'session_cookie' contiene un id de sesion opaco
            elif 'session_cookie' in request.cookies:
                sid = request.cookies.get('session_cookie')
                sesion = Session.query.get(sid)
                if not sesion or sesion.revocada or sesion.expira_en < datetime.datetime.utcnow():
                    return jsonify({"error": "Sesión inválida o expirada."}), 401
                usuario = User.query.get(sesion.user_id)
                if not usuario:
                    return jsonify({"error": "Sesión inválida."}), 401
                usuario_actual = usuario.email
                rol_actual = usuario.role

            else:
                return jsonify({"error": "Acceso denegado. Falta el token/sesión."}), 401

            # 3. Validar Rol
            if rol_requerido and rol_actual != rol_requerido:
                return jsonify({"error": "Prohibido. No tienes permisos."}), 403

            return f(usuario_actual, *args, **kwargs)
        return funcion_protegida
    return decorador