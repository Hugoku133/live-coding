import sqlite3
import bcrypt
import os
import secrets
from flask import Flask, request, jsonify, session, g
from flask_cors import CORS

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "dev_secret_cambiame")
CORS(app, supports_credentials=True, origins=["http://localhost:8080"])

DB_PATH = "/app/tienda.db"

# ─────────────────────────────────────────────
# UTILIDADES DE BASE DE DATOS
# ─────────────────────────────────────────────

def get_db():
    """Devuelve una conexión a SQLite para la petición actual."""
    if "db" not in g:
        g.db = sqlite3.connect(DB_PATH)
        g.db.row_factory = sqlite3.Row   # permite acceder por nombre de columna
        g.db.execute("PRAGMA foreign_keys = ON")
    return g.db

@app.teardown_appcontext
def close_db(exc):
    db = g.pop("db", None)
    if db:
        db.close()

def init_db():
    """Crea las tablas si no existen."""
    db = sqlite3.connect(DB_PATH)
    db.execute("PRAGMA foreign_keys = ON")
    db.executescript("""
        CREATE TABLE IF NOT EXISTS usuarios (
            id         INTEGER PRIMARY KEY AUTOINCREMENT,
            username   TEXT    NOT NULL UNIQUE,
            email      TEXT    NOT NULL UNIQUE,
            password   TEXT    NOT NULL,
            saldo      REAL    NOT NULL DEFAULT 100.0,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS productos (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id     INTEGER NOT NULL REFERENCES usuarios(id),
            nombre      TEXT    NOT NULL,
            descripcion TEXT    NOT NULL,
            precio      REAL    NOT NULL,
            activo      INTEGER NOT NULL DEFAULT 1,
            created_at  DATETIME DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS pedidos (
            id           INTEGER PRIMARY KEY AUTOINCREMENT,
            comprador_id INTEGER NOT NULL REFERENCES usuarios(id),
            producto_id  INTEGER NOT NULL REFERENCES productos(id),
            cantidad     INTEGER NOT NULL DEFAULT 1,
            precio_total REAL    NOT NULL,
            fecha        DATETIME DEFAULT CURRENT_TIMESTAMP
        );
    """)
    db.commit()
    db.close()
    print("✅ Base de datos inicializada.")

# ─────────────────────────────────────────────
# MIDDLEWARE: verificar sesión
# ─────────────────────────────────────────────

def login_requerido(f):
    from functools import wraps
    @wraps(f)
    def wrapper(*args, **kwargs):
        if "user_id" not in session:
            return jsonify({"error": "Debes iniciar sesión"}), 401
        return f(*args, **kwargs)
    return wrapper

# ─────────────────────────────────────────────
# AUTH: REGISTRO
# ─────────────────────────────────────────────

@app.route("/api/register", methods=["POST"])
def register():
    data = request.get_json(silent=True)
    if not data:
        return jsonify({"error": "JSON inválido"}), 400

    username = (data.get("username") or "").strip()
    email    = (data.get("email") or "").strip().lower()
    password = (data.get("password") or "")
    confirm  = (data.get("confirm_password") or "")

    # Validaciones básicas
    if not username or not email or not password:
        return jsonify({"error": "Todos los campos son obligatorios"}), 400
    if len(username) < 3 or len(username) > 30:
        return jsonify({"error": "El username debe tener entre 3 y 30 caracteres"}), 400
    if "@" not in email or len(email) > 120:
        return jsonify({"error": "Email inválido"}), 400
    if len(password) < 6:
        return jsonify({"error": "La contraseña debe tener al menos 6 caracteres"}), 400
    if password != confirm:
        return jsonify({"error": "Las contraseñas no coinciden"}), 400

    # Hash de la contraseña  ← NUNCA guardar texto plano
    hashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()

    db = get_db()
    try:
        db.execute(
            "INSERT INTO usuarios (username, email, password) VALUES (?, ?, ?)",
            (username, email, hashed)   # ← parámetros con ? → protección contra SQLi
        )
        db.commit()
        return jsonify({"mensaje": "Registro exitoso"}), 201
    except sqlite3.IntegrityError:
        return jsonify({"error": "El username o email ya está en uso"}), 409

# ─────────────────────────────────────────────
# AUTH: LOGIN
# ─────────────────────────────────────────────

@app.route("/api/login", methods=["POST"])
def login():
    data = request.get_json(silent=True)
    if not data:
        return jsonify({"error": "JSON inválido"}), 400

    email    = (data.get("email") or "").strip().lower()
    password = (data.get("password") or "")

    if not email or not password:
        return jsonify({"error": "Email y contraseña obligatorios"}), 400

    db = get_db()
    user = db.execute(
        "SELECT id, username, password, saldo FROM usuarios WHERE email = ?", (email,)
    ).fetchone()

    # Mismo mensaje para email no encontrado Y contraseña incorrecta → no dar pistas
    if not user or not bcrypt.checkpw(password.encode(), user["password"].encode()):
        return jsonify({"error": "Credenciales incorrectas"}), 401

    session.clear()
    session["user_id"]  = user["id"]
    session["username"] = user["username"]

    return jsonify({
        "mensaje":  "Login correcto",
        "username": user["username"],
        "saldo":    user["saldo"]
    }), 200

# ─────────────────────────────────────────────
# AUTH: LOGOUT / PERFIL
# ─────────────────────────────────────────────

@app.route("/api/logout", methods=["POST"])
def logout():
    session.clear()
    return jsonify({"mensaje": "Sesión cerrada"}), 200

@app.route("/api/me", methods=["GET"])
@login_requerido
def me():
    db = get_db()
    user = db.execute(
        "SELECT id, username, email, saldo, created_at FROM usuarios WHERE id = ?",
        (session["user_id"],)
    ).fetchone()
    if not user:
        return jsonify({"error": "Usuario no encontrado"}), 404
    return jsonify(dict(user)), 200   # ← NO devuelve el campo password

# ─────────────────────────────────────────────
# PRODUCTOS: CATÁLOGO (público)
# ─────────────────────────────────────────────

@app.route("/api/productos", methods=["GET"])
def catalogo():
    db = get_db()
    productos = db.execute("""
        SELECT p.id, p.nombre, p.descripcion, p.precio, p.created_at,
               u.username AS vendedor
        FROM productos p
        JOIN usuarios u ON u.id = p.user_id
        WHERE p.activo = 1
        ORDER BY p.created_at DESC
    """).fetchall()
    return jsonify([dict(p) for p in productos]), 200

# ─────────────────────────────────────────────
# PRODUCTOS: CREAR (solo autenticado)
# ─────────────────────────────────────────────

@app.route("/api/productos", methods=["POST"])
@login_requerido
def crear_producto():
    data = request.get_json(silent=True)
    if not data:
        return jsonify({"error": "JSON inválido"}), 400

    nombre      = (data.get("nombre") or "").strip()
    descripcion = (data.get("descripcion") or "").strip()
    precio_raw  = data.get("precio")

    if not nombre or not descripcion:
        return jsonify({"error": "Nombre y descripción son obligatorios"}), 400
    if len(nombre) > 100:
        return jsonify({"error": "Nombre demasiado largo (máx 100 caracteres)"}), 400
    if len(descripcion) > 500:
        return jsonify({"error": "Descripción demasiado larga (máx 500 caracteres)"}), 400

    try:
        precio = float(precio_raw)
        if precio <= 0:
            raise ValueError
    except (TypeError, ValueError):
        return jsonify({"error": "El precio debe ser un número positivo"}), 400

    db = get_db()
    cur = db.execute(
        "INSERT INTO productos (user_id, nombre, descripcion, precio) VALUES (?, ?, ?, ?)",
        (session["user_id"], nombre, descripcion, round(precio, 2))
    )
    db.commit()
    return jsonify({"mensaje": "Producto creado", "id": cur.lastrowid}), 201

# ─────────────────────────────────────────────
# PRODUCTOS: MIS PRODUCTOS
# ─────────────────────────────────────────────

@app.route("/api/mis-productos", methods=["GET"])
@login_requerido
def mis_productos():
    db = get_db()
    productos = db.execute(
        "SELECT id, nombre, descripcion, precio, activo, created_at FROM productos WHERE user_id = ? ORDER BY created_at DESC",
        (session["user_id"],)
    ).fetchall()
    return jsonify([dict(p) for p in productos]), 200

# ─────────────────────────────────────────────
# PRODUCTOS: ELIMINAR (solo el vendedor)
# ─────────────────────────────────────────────

@app.route("/api/productos/<int:producto_id>", methods=["DELETE"])
@login_requerido
def eliminar_producto(producto_id):
    db = get_db()
    producto = db.execute(
        "SELECT user_id FROM productos WHERE id = ?", (producto_id,)
    ).fetchone()

    if not producto:
        return jsonify({"error": "Producto no encontrado"}), 404
    if producto["user_id"] != session["user_id"]:
        return jsonify({"error": "No tienes permiso para eliminar este producto"}), 403

    db.execute("UPDATE productos SET activo = 0 WHERE id = ?", (producto_id,))
    db.commit()
    return jsonify({"mensaje": "Producto eliminado"}), 200

# ─────────────────────────────────────────────
# COMPRA: FINALIZAR
# ─────────────────────────────────────────────

@app.route("/api/comprar/<int:producto_id>", methods=["POST"])
@login_requerido
def comprar(producto_id):
    db = get_db()

    producto = db.execute(
        "SELECT id, user_id, precio, nombre, activo FROM productos WHERE id = ?",
        (producto_id,)
    ).fetchone()

    if not producto or not producto["activo"]:
        return jsonify({"error": "Producto no disponible"}), 404
    if producto["user_id"] == session["user_id"]:
        return jsonify({"error": "No puedes comprar tu propio producto"}), 400

    comprador = db.execute(
        "SELECT saldo FROM usuarios WHERE id = ?", (session["user_id"],)
    ).fetchone()

    if comprador["saldo"] < producto["precio"]:
        return jsonify({"error": "Saldo insuficiente"}), 400

    # Transacción: descontar al comprador, añadir al vendedor, registrar pedido
    try:
        db.execute("BEGIN")
        db.execute(
            "UPDATE usuarios SET saldo = saldo - ? WHERE id = ?",
            (producto["precio"], session["user_id"])
        )
        db.execute(
            "UPDATE usuarios SET saldo = saldo + ? WHERE id = ?",
            (producto["precio"], producto["user_id"])
        )
        db.execute(
            "INSERT INTO pedidos (comprador_id, producto_id, precio_total) VALUES (?, ?, ?)",
            (session["user_id"], producto_id, producto["precio"])
        )
        db.execute("UPDATE productos SET activo = 0 WHERE id = ?", (producto_id,))
        db.execute("COMMIT")
    except Exception:
        db.execute("ROLLBACK")
        return jsonify({"error": "Error al procesar la compra"}), 500

    return jsonify({"mensaje": f"¡Compra realizada! Has comprado '{producto['nombre']}'"}), 200

# ─────────────────────────────────────────────
# COMPRAS: MIS PEDIDOS
# ─────────────────────────────────────────────

@app.route("/api/mis-compras", methods=["GET"])
@login_requerido
def mis_compras():
    db = get_db()
    pedidos = db.execute("""
        SELECT pe.id, pe.precio_total, pe.fecha,
               pr.nombre AS producto, u.username AS vendedor
        FROM pedidos pe
        JOIN productos pr ON pr.id = pe.producto_id
        JOIN usuarios u   ON u.id  = pr.user_id
        WHERE pe.comprador_id = ?
        ORDER BY pe.fecha DESC
    """, (session["user_id"],)).fetchall()
    return jsonify([dict(p) for p in pedidos]), 200

# ─────────────────────────────────────────────
# ARRANQUE
# ─────────────────────────────────────────────

if __name__ == "__main__":
    init_db()
    app.run(host="0.0.0.0", port=5000, debug=True)