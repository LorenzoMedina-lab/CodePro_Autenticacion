import os
import bcrypt
import jwt
import datetime
from dotenv import load_dotenv

load_dotenv()

SECRET_KEY = os.getenv('SECRET_KEY')
if not SECRET_KEY:
    raise ValueError("¡Falta la SECRET_KEY en el archivo .env!")

def hashear_password(password):
    """
    Usa bcrypt directamente. Requiere convertir los strings a bytes.
    """
    # 1. Generamos el Salt aleatorio
    salt = bcrypt.gensalt()
    # 2. Convertimos el texto a bytes y lo hasheamos
    hash_bytes = bcrypt.hashpw(password.encode('utf-8'), salt)
    # 3. Lo devolvemos como texto normal para guardarlo en la base de datos
    return hash_bytes.decode('utf-8')

def verificar_password(password_plano, password_hash):
    """
    Compara la contraseña en texto plano con el hash de la base de datos.
    """
    # bcrypt.checkpw requiere que ambos valores sean bytes
    return bcrypt.checkpw(
        password_plano.encode('utf-8'), 
        password_hash.encode('utf-8')
    )

def generar_jwt(username, role):
    payload = {
        'username': username,
        'role': role,
        'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=2)
    }
    return jwt.encode(payload, SECRET_KEY, algorithm='HS256')