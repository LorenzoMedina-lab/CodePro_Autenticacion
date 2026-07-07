from models.db import db, User
from utils.security import hashear_password, verificar_password, generar_jwt

def registrar_usuario(username, password, role="user"):
    if not username or not password:
        return {"error": "Faltan datos", "status": 400}
    
    if len(password.encode('utf-8')) > 72:
        return {"error": "La contraseña es demasiado larga (máximo 72 bytes).", "status": 400}
    
    usuario_existente = User.query.filter_by(username=username).first()
    if usuario_existente:
        return {"error": "El usuario ya existe", "status": 409}

    nuevo_usuario = User(
        username=username,
        password_hash=hashear_password(password),
        role=role
    )
    
    db.session.add(nuevo_usuario)
    db.session.commit()
    
    return {"mensaje": f"Usuario {username} registrado", "status": 201}

def autenticar_usuario(username, password):
    usuario = User.query.filter_by(username=username).first()
    
    if not usuario or not verificar_password(password, usuario.password_hash):
        return {"error": "Credenciales inválidas", "status": 401}

    token = generar_jwt(usuario.username, usuario.role)
    
    return {
        "mensaje": "Inicio de sesión exitoso", 
        "token": token, 
        "rol": usuario.role, 
        "status": 200
    }