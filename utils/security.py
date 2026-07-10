import os
import bcrypt
import jwt
import datetime
from dotenv import load_dotenv
from cryptography.fernet import Fernet, InvalidToken

load_dotenv()

SECRET_KEY = os.getenv('SECRET_KEY')
if not SECRET_KEY:
    raise ValueError("¡Falta la SECRET_KEY en el archivo .env!")

# Clave para CIFRADO (confidencialidad) del email dentro del payload del JWT.
# Es distinta de SECRET_KEY, que se usa exclusivamente para firmar (integridad).
ENCRYPTION_KEY = os.getenv('ENCRYPTION_KEY')
if not ENCRYPTION_KEY:
    raise ValueError("¡Falta ENCRYPTION_KEY en el archivo .env! Genérala con Fernet.generate_key().")

# Instancia unica de Fernet (AES-128-CBC + HMAC-SHA256). Reutilizable entre peticiones.
_fernet = Fernet(ENCRYPTION_KEY.encode('utf-8'))

def cifrar(texto_plano):
    """
    Cifra un texto plano (email) y devuelve un ciphertext en base64 url-safe.
    Cada llamada genera IV + timestamp aleatorios, por lo que el mismo texto
    produce salidas distintas (semantic secrecy).
    """
    return _fernet.encrypt(texto_plano.encode('utf-8')).decode('utf-8')

def descifrar(token_cifrado):
    """
    Descifra el ciphertext producido por cifrar(). Lanza cryptography.fernet.InvalidToken
    si la clave no coincide, el ciphertext fue manipulado o expiro (TTL de Fernet por defecto ilimitado).
    """
    return _fernet.decrypt(token_cifrado.encode('utf-8')).decode('utf-8')

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

def generar_jwt(email, role):
    payload = {
        'email_cif': cifrar(email),  # email cifrado (confidencialidad)
        'role': role,               # rol legible: el RBAC se valida sin descifrar
        'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=2)
    }
    return jwt.encode(payload, SECRET_KEY, algorithm='HS256')