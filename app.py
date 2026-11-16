from flask import (
    Flask, render_template, request, session,
    redirect, url_for
)
from functools import wraps
from pypdf import PdfReader
from io import BytesIO
import os
import uuid
import sqlite3
import hashlib
import hmac
import time

app = Flask(__name__)

app.secret_key = os.environ.get(
    "FLASK_SECRET_KEY",
    "cambiar-esta-clave-secreta-antes-de-publicar"
)

CARPETA_PDF = "documentos"
os.makedirs(CARPETA_PDF, exist_ok=True)

BASE_DATOS = "impresora.db"

USUARIO_CORRECTO = "impresora26"

HASH_CONTRASENA = (
    "c5d6e4bfe508b9e0898ca703f0cd0374636092b140975301f95f7b535190c1d5"
)

SALT = b"impresora24h-login-salt-v1"

MAX_CARACTERES = 30
MAX_INTENTOS = 3
TIEMPO_BLOQUEO = 300

PRECIO_BLANCO_NEGRO = 100
PRECIO_COLOR = 200


def conectar():
    return sqlite3.connect(BASE_DATOS)


def crear_base_datos():
    conexion = conectar()

    conexion.execute("""
        CREATE TABLE IF NOT EXISTS pedidos (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            documento TEXT NOT NULL,
            paginas TEXT NOT NULL,
            cantidad INTEGER NOT NULL,
            precio_por_pagina REAL NOT NULL,
            total REAL NOT NULL,
            fecha TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)

    columnas = [
        columna[1]
        for columna in conexion.execute(
            "PRAGMA table_info(pedidos)"
        ).fetchall()
    ]

    if "tipo_impresion" not in columnas:
        conexion.execute("""
            ALTER TABLE pedidos
            ADD COLUMN tipo_impresion TEXT NOT NULL
            DEFAULT 'blanco y negro'
        """)

    if "forma_pago" not in columnas:
        conexion.execute("""
            ALTER TABLE pedidos
            ADD COLUMN forma_pago TEXT NOT NULL
            DEFAULT 'efectivo'
        """)

    if "estado_pago" not in columnas:
        conexion.execute("""
            ALTER TABLE pedidos
            ADD COLUMN estado_pago TEXT NOT NULL
            DEFAULT 'pendiente'
        """)

    conexion.execute("""
        CREATE TABLE IF NOT EXISTS intentos_login (
            ip TEXT PRIMARY KEY,
            intentos INTEGER DEFAULT 0,
            bloqueado_hasta REAL DEFAULT 0
        )
    """)

    conexion.commit()
    conexion.close()


crear_base_datos()


def requiere_login(funcion):
    @wraps(funcion)
    def decorada(*args, **kwargs):
        if not session.get("logueado"):
            return redirect(url_for("login"))
        return funcion(*args, **kwargs)

    return decorada


def calcular_hash(contrasena):
    return hashlib.pbkdf2_hmac(
        "sha256",
        contrasena.encode("utf-8"),
        SALT,
        600000
    ).hex()


@app.route("/", methods=["GET", "POST"])
@app.route("/login", methods=["GET", "POST"])
def login():
    if session.get("logueado"):
        return redirect(url_for("inicio"))

    ip = request.remote_addr or "desconocida"
    error = None

    conexion = conectar()

    registro = conexion.execute(
        """
        SELECT intentos, bloqueado_hasta
        FROM intentos_login
        WHERE ip = ?
        """,
        (ip,)
    ).fetchone()

    if registro and registro[1] <= time.time():
        conexion.execute(
            "DELETE FROM intentos_login WHERE ip = ?",
            (ip,)
        )
        conexion.commit()
        registro = None

    if registro and registro[1] > time.time():
        conexion.close()
        return render_template(
            "login.html",
            error="Demasiados intentos. Esperá 5 minutos."
        )

    if request.method == "POST":
        usuario = request.form.get("usuario", "").strip()
        contrasena = request.form.get("contrasena", "")

        if len(contrasena) > MAX_CARACTERES:
            error = "La contraseña no puede superar los 30 caracteres."
        else:
            hash_calculado = calcular_hash(contrasena)

            acceso_correcto = (
                usuario == USUARIO_CORRECTO
                and hmac.compare_digest(
                    hash_calculado,
                    HASH_CONTRASENA
                )
            )

            if acceso_correcto:
                conexion.execute(
                    "DELETE FROM intentos_login WHERE ip = ?",
                    (ip,)
                )
                conexion.commit()
                conexion.close()

                session.clear()
                session["logueado"] = True

                return redirect(url_for("inicio"))

            intentos = registro[0] + 1 if registro else 1
            bloqueado_hasta = 0

            if intentos >= MAX_INTENTOS:
                bloqueado_hasta = time.time() + TIEMPO_BLOQUEO
                error = "Llegaste a 3 intentos incorrectos. Esperá 5 minutos."
            else:
                error = "Usuario o contraseña incorrectos."

            conexion.execute("""
                INSERT OR REPLACE INTO intentos_login
                (ip, intentos, bloqueado_hasta)
                VALUES (?, ?, ?)
            """, (ip, intentos, bloqueado_hasta))

            conexion.commit()

    conexion.close()

    return render_template("login.html", error=error)


@app.route("/cerrar_sesion")
def cerrar_sesion():
    session.clear()
    return redirect(url_for("login"))


@app.route("/inicio")
@requiere_login
def inicio():
    return render_template("index.html")


@app.route("/cargar", methods=["POST"])
@requiere_login
def cargar():
    archivo = request.files.get("documento")

    if not archivo or archivo.filename == "":
        return "Por favor, seleccioná un archivo PDF."

    if not archivo.filename.lower().endswith(".pdf"):
        return "El archivo debe ser un PDF."

    try:
        contenido = archivo.read()
        pdf = PdfReader(BytesIO(contenido))
        cantidad = len(pdf.pages)

        if cantidad == 0:
            return "El PDF no tiene páginas."

        identificador = str(uuid.uuid4())
        ruta = os.path.join(
            CARPETA_PDF,
            identificador + ".pdf"
        )

        with open(ruta, "wb") as destino:
            destino.write(contenido)

        session["documento_id"] = identificador

        return render_template(
            "paginas.html",
            nombre=os.path.basename(archivo.filename),
            cantidad=cantidad
        )

    except Exception:
        return "No se pudo leer el PDF. Probá con otro archivo."


@app.route("/seleccionar", methods=["POST"])
@requiere_login
def seleccionar():
    identificador = session.get("documento_id")

    if not identificador:
        return "No hay un documento cargado. Volvé a cargar el PDF."

    ruta = os.path.join(
        CARPETA_PDF,
        identificador + ".pdf"
    )

    if not os.path.exists(ruta):
        return "No se encontró el documento. Volvé a cargarlo."

    try:
        pdf = PdfReader(ruta)
        cantidad = len(pdf.pages)

        paginas_elegidas = request.form.getlist("paginas")

        paginas_elegidas = sorted({
            int(p)
            for p in paginas_elegidas
            if p.isdigit() and 1 <= int(p) <= cantidad
        })

        if not paginas_elegidas:
            return "Tenés que seleccionar al menos una página."

        tipo_impresion = request.form.get(
            "tipo_impresion",
            "blanco y negro"
        )

        if tipo_impresion == "color":
            precio = PRECIO_COLOR
        else:
            tipo_impresion = "blanco y negro"
            precio = PRECIO_BLANCO_NEGRO

        forma_pago = request.form.get("forma_pago", "efectivo")

        if forma_pago not in ["efectivo", "qr"]:
            forma_pago = "efectivo"

        total = len(paginas_elegidas) * precio

        conexion = conectar()

        cursor = conexion.execute(
            """
            INSERT INTO pedidos (
                documento, paginas, cantidad,
                precio_por_pagina, total,
                tipo_impresion, forma_pago, estado_pago
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                os.path.basename(ruta),
                ", ".join(map(str, paginas_elegidas)),
                len(paginas_elegidas),
                precio,
                total,
                tipo_impresion,
                forma_pago,
                "pendiente"
            )
        )

        pedido_id = cursor.lastrowid

        conexion.commit()
        conexion.close()

        session.pop("documento_id", None)

        return render_template(
            "resumen.html",
            paginas=paginas_elegidas,
            cantidad=len(paginas_elegidas),
            precio=precio,
            total=total,
            tipo_impresion=tipo_impresion,
            forma_pago=forma_pago,
            pedido_id=pedido_id
        )

    except Exception as e:
        print("ERROR:", repr(e))
        return "Ocurrió un error al procesar el pedido."


@app.route("/pago/<int:pedido_id>")
@requiere_login
def pago(pedido_id):
    conexion = conectar()

    pedido = conexion.execute(
        """
        SELECT id, total, forma_pago, estado_pago
        FROM pedidos
        WHERE id = ?
        """,
        (pedido_id,)
    ).fetchone()

    conexion.close()

    if not pedido or pedido[2] != "qr":
        return "No se encontró el pedido."

    if pedido[3] == "pagado":
        return "Este pedido ya figura como pagado."

    return render_template(
        "pago.html",
        pedido_id=pedido[0],
        total=pedido[1]
    )


@app.route("/simular_pago/<int:pedido_id>")
def simular_pago(pedido_id):
    conexion = conectar()

    pedido = conexion.execute(
        """
        SELECT id, total, forma_pago, estado_pago
        FROM pedidos
        WHERE id = ?
        """,
        (pedido_id,)
    ).fetchone()

    conexion.close()

    if not pedido or pedido[2] != "qr":
        return "Pedido no válido."

    if pedido[3] == "pagado":
        return "Este pedido ya fue pagado."

    return render_template(
        "simular_pago.html",
        pedido_id=pedido[0],
        total=pedido[1]
    )


@app.route("/confirmar_pago/<int:pedido_id>", methods=["POST"])
def confirmar_pago(pedido_id):
    # Esta ruta permite confirmar desde el celular
    # sin iniciar sesión. Es una simulación educativa.

    conexion = conectar()

    pedido = conexion.execute(
        """
        SELECT id, total, forma_pago
        FROM pedidos
        WHERE id = ?
        """,
        (pedido_id,)
    ).fetchone()

    if not pedido or pedido[2] != "qr":
        conexion.close()
        return "No se pudo confirmar el pago."

    conexion.execute(
        """
        UPDATE pedidos
        SET estado_pago = 'pagado'
        WHERE id = ?
        AND forma_pago = 'qr'
        """,
        (pedido_id,)
    )

    conexion.commit()
    conexion.close()

    return render_template(
        "pago_exitoso.html",
        pedido_id=pedido_id,
        total=pedido[1]
    )


@app.route("/pedidos")
@requiere_login
def ver_pedidos():
    conexion = conectar()

    pedidos = conexion.execute(
        "SELECT * FROM pedidos ORDER BY id DESC"
    ).fetchall()

    conexion.close()

    return render_template(
        "pedidos.html",
        pedidos=pedidos
    )


if __name__ == "__main__":
    app.run(
        host="0.0.0.0",
        port=5000,
        debug=True
    )