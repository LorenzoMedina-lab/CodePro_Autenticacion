from flask import Flask
import os
from dotenv import load_dotenv
from models.db import db
from routes.auth_routes import auth_bp
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

load_dotenv()

app = Flask(__name__)

app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URL')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["200 per day", "50 per hour"],
    storage_uri="memory://" # Guarda los conteos en memoria
)
app.config['LIMITER'] = limiter # Permite acceder al limitador desde cualquier parte de la app

db.init_app(app)

with app.app_context():
    db.create_all()
    print("✅ Tablas de base de datos sincronizadas.")

app.register_blueprint(auth_bp, url_prefix='/api/auth')

if __name__ == '__main__':
    print("Servidor de PassPort Inc. iniciando en puerto 5000...")
    app.run(debug=True, port=5000)