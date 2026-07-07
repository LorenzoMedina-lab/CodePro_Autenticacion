from flask_sqlalchemy import SQLAlchemy

# Inicializamos la instancia de SQLAlchemy
db = SQLAlchemy()

# Definimos cómo se verá nuestra tabla en PostgreSQL
class User(db.Model):
    __tablename__ = 'users'
    
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(20), default='user')