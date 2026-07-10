from flask_sqlalchemy import SQLAlchemy

# Inicializamos la instancia de la base de datos
db = SQLAlchemy()

# Definimos el modelo de Usuario
class User(db.Model):
    __tablename__ = 'users'
    
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(20), default='user')

# Sesion stateful (flujos web). La cookie 'session_cookie' almacena solo el id
# opaco de esta fila, nunca el JWT. Permite revocacion real en /logout.
class Session(db.Model):
    __tablename__ = 'sessions'
    id_session = db.Column(db.String(64), primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    expira_en = db.Column(db.DateTime, nullable=False)
    revocada = db.Column(db.Boolean, default=False)