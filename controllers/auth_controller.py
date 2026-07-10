from models.db import db, User
from utils.security import hashear_password, verificar_password, generar_jwt
import re # libreria para expresiones regulares

# Validacion simple de formato de email.(email_validator).
_EMAIL_RE = re.compile(r'^[^@\s]+@[^@\s]+\.[^@\s]+$') # Expresion regular para validar un email simple

def registrar_usuario(email, password):
    """
    Registra un usuario NUEVO desde el endpoint publico de auto-registro.
    El identificador es el EMAIL (no username). El rol SIEMPRE se fuerza a 'user'
    (prevencion de escalada de privilegios via auto-registro).
    """
    if not email or not password:
        return {"error": "Faltan datos", "status": 400}

    if len(email) > 120 or not _EMAIL_RE.match(email):
        return {"error": "Correo electrónico inválido.", "status": 400}

    if len(password.encode('utf-8')) > 72:
        return {"error": "La contraseña es demasiado larga (máximo 72 bytes).", "status": 400}

    usuario_existente = User.query.filter_by(email=email).first()
    if usuario_existente:
        return {"error": "El usuario ya existe", "status": 409}

    nuevo_usuario = User(
        email=email,
        password_hash=hashear_password(password),
        role='user'
    )

    db.session.add(nuevo_usuario)
    db.session.commit()

    return {"mensaje": f"Usuario {email} registrado", "status": 201}

def autenticar_usuario(email, password):
    usuario = User.query.filter_by(email=email).first()

    if not usuario or not verificar_password(password, usuario.password_hash):
        return {"error": "Credenciales inválidas", "status": 401}

    token = generar_jwt(usuario.email, usuario.role)

    return {
        "mensaje": "Inicio de sesión exitoso",
        "token": token,
        "rol": usuario.role,
        "user_id": usuario.id,
        "status": 200
    }