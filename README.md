# 🛂 PassPort Inc. - Autenticación y Gestión de Sesiones

Este repositorio contiene la solución técnica para el desafío de arquitectura de seguridad de **PassPort Inc.**, una plataforma diseñada para almacenar y gestionar identidades digitales de manera ultra segura.

El sistema implementa una API RESTful modular, escalable y tolerante a fallos, construida con Python (Flask) y respaldada por PostgreSQL.

## 🚀 Características Principales

* **Arquitectura Modular:** Separación estricta de responsabilidades (MVC adaptado: Routes, Controllers, Models, Middlewares y Utils) para facilitar la escalabilidad.
* **Gestión de Sesiones Híbrida:** * *Sin estado (Stateless):* Emisión de JSON Web Tokens (JWT) para consumo desde aplicaciones móviles.
  * *Con estado (Stateful):* La cookie HTTP-Only almacena un **identificador de sesión opaco** (UUID) referenciando una fila de la tabla `sessions` en PostgreSQL, lo que permite revocación real al cerrar sesión.
* **RBAC (Control de Acceso Basado en Roles):** Implementación de roles (`user`, `admin`) con protección de rutas a través de Middlewares personalizados.
* **Almacenamiento Persistente:** Base de datos PostgreSQL orquestada en contenedores Docker, integrada mediante SQLAlchemy (prevención de Inyección SQL).

## 🛡️ Auditoría de Seguridad y Mitigación de Vulnerabilidades

Este sistema fue diseñado bajo la premisa de "Zero Trust", mitigando las vulnerabilidades exigidas en el desafío:

1. **Protección de Credenciales (Base de Datos):** Las contraseñas NUNCA se guardan en texto plano. Se utiliza `bcrypt` nativo (con generación de *salts* aleatorios) para el hashing. Se implementó una validación de 72 bytes para evitar desbordamientos del algoritmo.
 2. **Mitigación de XSS (Cross-Site Scripting):** Los tokens de sesión web se almacenan en cookies con el flag `HttpOnly=True`, impidiendo que scripts maliciosos de JavaScript accedan a la sesión.
 3. **Mitigación de CSRF (Cross-Site Request Forgery):** Las cookies de sesión utilizan la directiva `SameSite='Lax'`, previniendo que sitios de terceros envíen peticiones fraudulentas en nombre del usuario.
 4. **Protección contra Fuerza Bruta:** Implementación de un Rate Limiter (`Flask-Limiter`). La ruta `/login` restringe temporalmente la dirección IP del atacante tras 5 intentos fallidos por minuto (Status `429 Too Many Requests`).
 5. **Gestión de Secretos:** Integración de `.env` (excluido en `.gitignore`) para prevenir la fuga de claves privadas y cadenas de conexión en repositorios públicos.
 6. **Cifrado de Datos Sensibles en el JWT:** El campo `email` viaja **cifrado** dentro del payload (AES-128-CBC + HMAC-SHA256 vía `Fernet`), de modo que la firma HS256 protege la integridad del token y el cifrado protege la confidencialidad del usuario. El `role` se mantiene legible para validar RBAC sin descifrar. La clave de cifrado `ENCRYPTION_KEY` es independiente de `SECRET_KEY` (separación de responsabilidades).
 7. **Sesiones Stateful Revocables:** La cookie web almacena un identificador opaco (UUID) que referencia la tabla `sessions`; al cerrar sesión la fila se marca como `revocada`, invalidando la cookie incluso si el cliente la retiene.
 8. **Prevención de Escalada de Privilegios:** El auto-registro ignora cualquier `role` enviado por el cliente y fuerza `role='user'`; los administradores solo pueden crearse por un canal de provisioning externo.
 9. **Validación de Entradas:** El correo electrónico se valida con expresión regular antes de persistirse; Jinja2 autoescapa la salida en las plantillas para prevenir XSS反射.

## 🏗️ Estructura del Proyecto

proyecto-passport/
 ┣ controllers/         # Lógica de negocio (Registro, validación de Login)
 ┣ middlewares/         # Decoradores de protección de rutas y lectura de JWT
 ┣ models/              # Modelos de SQLAlchemy (Tablas de PostgreSQL)
 ┣ routes/              # Endpoints de la API (Blueprints de Flask)
 ┣ utils/               # Herramientas criptográficas (bcrypt, PyJWT)
 ┣ .env.example         # Plantilla de variables de entorno
 ┣ docker-compose.yml   # Orquestación de la base de datos
 ┣ requirements.txt     # Dependencias de Python
 ┗ app.py               # Punto de entrada y configuración de Flask


## ⚙️ Instrucciones de Instalación y Uso

### 1. Requisitos Previos
* Python 3.10+
* Docker y Docker Compose instalados.

### 2. Configurar el Entorno
Clona el repositorio e instala las dependencias:

python -m venv env
source env/bin/activate  # En Windows: env\Scripts\activate
pip install -r requirements.txt


Crea un archivo `.env` en la raíz basado en la plantilla y añade tus secretos:

### 3. Levantar la Infraestructura
Inicia la base de datos PostgreSQL usando Docker:

docker-compose up -d


Inicia el servidor backend (las tablas se sincronizarán automáticamente):

python app.py

El servidor estará escuchando en `http://127.0.0.1:5000`.

## 📡 Referencia de la API (Endpoints)

| Método | Endpoint | Descripción | Requiere Auth | Rol |
|--------|----------|-------------|---------------|-----|
| `POST` | `/api/auth/register` | Registra un nuevo usuario | No | N/A |
| `POST` | `/api/auth/login` | Autentica y devuelve JWT/Cookie | No | N/A |
| `GET`  | `/api/auth/perfil` | Devuelve información del usuario | Sí | `user` o `admin` |
| `GET`  | `/api/auth/admin/dashboard` | Acceso exclusivo para administradores | Sí | `admin` |

---
*Desarrollado para el desafío de Backend de PassPort Inc.*