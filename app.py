from flask import Flask
import os
from dotenv import load_dotenv
from models.db import db
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_wtf.csrf import CSRFProtect

load_dotenv()

app = Flask(__name__)

# SECRET_KEY es requerida por Flask-WTF (CSRF) para firmar los tokens de sesion
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY')
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URL')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["200 per day", "50 per hour"],
    storage_uri="memory://" # Guarda los conteos en memoria
)

# Proteccion CSRF global para peticiones de escritura (POST/PUT/PATCH/DELETE)
csrf = CSRFProtect(app)

db.init_app(app)

# Se importan los blueprints despues de definir 'limiter'/'csrf' para evitar imports circulares
from routes.auth_routes import auth_bp
from routes.view_routes import views_bp

with app.app_context():
    db.create_all()
    print("[OK] Tablas de base de datos sincronizadas.")

app.register_blueprint(auth_bp, url_prefix='/api/auth')
app.register_blueprint(views_bp)

# El blueprint de la API JSON se exime de la validacion CSRF automatica.
# La validacion se realiza manualmente en cada ruta segun el tipo de cliente
# (web con cookie -> se valida CSRF; movil con Bearer -> se omite).
csrf.exempt(auth_bp)

# Aplicamos el rate limit de login sobre el endpoint ya registrado (evita import circular)
app.view_functions['auth.login'] = limiter.limit("5 per minute")(app.view_functions['auth.login'])

if __name__ == '__main__':
    print("Servidor de PassPort Inc. iniciando en puerto 5000...")
    app.run(debug=True, port=5000)