# =====================================================================
#  API DE "MI TIENDA"  (la oficina central de la frutería 🍎)
#  Python + FastAPI + Supabase  ·  Publicada en Vercel
#
#  Ventanillas (endpoints):
#    GET    /                          -> revisar que la API está viva
#    GET    /users                     -> lista pública de usuarios (como fakestoreapi.com/users)
#    POST   /auth/register             -> registrarse (siempre con rol "usuario" = Cliente)
#    POST   /auth/login                -> iniciar sesión (devuelve token + rol)
#    GET    /usuarios                  -> lista de usuarios              (solo admin)
#    DELETE /usuarios/{id}             -> eliminar un usuario            (solo admin)
#    GET    /products                  -> catálogo completo              (US03)
#    GET    /products/categories       -> lista de categorías            (US04)
#    GET    /products/category/{cat}   -> productos de una categoría     (US04)
#    GET    /products/{id}             -> detalle de un producto         (US05)
#    PUT    /products/{id}             -> editar un producto             (solo admin)
#    DELETE /products/{id}             -> eliminar un producto           (solo admin)
#
#  Roles: admin (Administrador) · usuario (Cliente) · auditor (Auditor)
# =====================================================================
import os
from datetime import datetime, timedelta, timezone

import bcrypt
import httpx
import jwt
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

# --- Llaves (se ponen en Vercel -> Settings -> Environment Variables) ---
SUPABASE_URL = os.environ.get("SUPABASE_URL", "").rstrip("/")
SUPABASE_KEY = os.environ.get("SUPABASE_KEY", "")
JWT_SECRET = os.environ.get("JWT_SECRET", "")

app = FastAPI(title="API Mi Tienda")

# Permite que la app (web, celular, escritorio) hable con la API
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


# --- Ayudantes -------------------------------------------------------
def respuesta(codigo: int, mensaje: str):
    """Contesta siempre con {"mensaje": "..."} para que la app lo entienda."""
    return JSONResponse(status_code=codigo, content={"mensaje": mensaje})


def datos_publicos(u: dict) -> dict:
    """Lo que sí se puede enseñar de un usuario (NUNCA el password)."""
    return {"id": u["id"], "nombre": u["nombre"], "usuario": u["usuario"], "rol": u["rol"]}


def configurado() -> bool:
    return bool(SUPABASE_URL and SUPABASE_KEY and JWT_SECRET)


# --- Conexión con la base de datos (el archivero) ---------------------
def db(metodo: str, params: dict | None = None, json: dict | None = None, tabla: str = "usuarios"):
    """Habla con una tabla de Supabase ('usuarios' o 'productos')."""
    return httpx.request(
        metodo,
        f"{SUPABASE_URL}/rest/v1/{tabla}",
        params=params,
        json=json,
        headers={
            "apikey": SUPABASE_KEY,
            "Content-Type": "application/json",
            "Prefer": "return=representation",
        },
        timeout=20,
    )


def buscar_usuario(usuario: str):
    r = db("GET", params={"usuario": f"eq.{usuario}", "select": "*"})
    r.raise_for_status()
    filas = r.json()
    return filas[0] if filas else None


def listar_usuarios():
    r = db("GET", params={"select": "id,nombre,usuario,rol", "order": "id.asc"})
    r.raise_for_status()
    return r.json()


def crear_usuario(nombre: str, usuario: str, password_encriptado: str):
    return db("POST", json={"nombre": nombre, "usuario": usuario,
                            "password": password_encriptado, "rol": "usuario"})


def eliminar_usuario(id_usuario: int):
    r = db("DELETE", params={"id": f"eq.{id_usuario}"})
    r.raise_for_status()
    return r.json()


# --- Guardias de seguridad --------------------------------------------
def leer_token(request: Request):
    """Revisa la 'pulsera' (token). Devuelve sus datos o None."""
    encabezado = request.headers.get("authorization", "")
    if not encabezado.startswith("Bearer "):
        return None
    try:
        return jwt.decode(encabezado[7:], JWT_SECRET, algorithms=["HS256"])
    except jwt.PyJWTError:
        return None


def solo_admin(request: Request):
    """Devuelve (datos_token, None) si es admin; si no, (None, respuesta_de_error)."""
    datos = leer_token(request)
    if datos is None:
        return None, respuesta(401, "Token inválido o vencido")
    if datos.get("rol") != "admin":
        return None, respuesta(403, "Solo los administradores pueden hacer esto")
    return datos, None


# --- Ventanillas (endpoints) ------------------------------------------
@app.get("/")
def inicio():
    if not configurado():
        return respuesta(500, "Faltan variables: SUPABASE_URL, SUPABASE_KEY o JWT_SECRET")
    return {"mensaje": "API de Mi Tienda funcionando 🍎"}


@app.get("/users")
def users_publicos():
    """Lista en JSON, como fakestoreapi.com/users (sin contraseñas)."""
    try:
        return listar_usuarios()
    except Exception:
        return respuesta(500, "Error al obtener usuarios")


# --- Catálogo de productos (tabla "productos" en Supabase) -------------
CAMPOS_PRODUCTO = "id,title,price,description,category,image,rating_rate,rating_count"


def formato_producto(p: dict) -> dict:
    """Convierte una fila de la tabla al mismo formato que fakestoreapi.com."""
    return {
        "id": p["id"],
        "title": p["title"],
        "price": p["price"],
        "description": p["description"],
        "category": p["category"],
        "image": p["image"],
        "rating": {"rate": p.get("rating_rate", 0), "count": p.get("rating_count", 0)},
    }


def leer_productos(filtros: dict | None = None):
    params = {"select": CAMPOS_PRODUCTO, "order": "id.asc"}
    if filtros:
        params.update(filtros)
    r = db("GET", params=params, tabla="productos")
    r.raise_for_status()
    return [formato_producto(p) for p in r.json()]


@app.get("/products")
def productos():
    """US03 · Catálogo completo en JSON (como fakestoreapi.com/products)."""
    try:
        return leer_productos()
    except Exception:
        return respuesta(500, "Error al obtener productos")


@app.get("/products/categories")
def categorias():
    """US04 · Lista de categorías sin repetir: ["electronics", "jewelery", ...]."""
    try:
        r = db("GET", params={"select": "category", "order": "category.asc"}, tabla="productos")
        r.raise_for_status()
        lista = []
        for fila in r.json():
            if fila["category"] not in lista:
                lista.append(fila["category"])
        return lista
    except Exception:
        return respuesta(500, "Error al obtener categorías")


@app.get("/products/category/{categoria}")
def productos_por_categoria(categoria: str):
    """US04 · Solo los productos de una categoría."""
    try:
        return leer_productos({"category": f"eq.{categoria}"})
    except Exception:
        return respuesta(500, "Error al obtener productos")


@app.get("/products/{id_producto}")
def producto(id_producto: int):
    """US05 · Detalle de un producto."""
    try:
        lista = leer_productos({"id": f"eq.{id_producto}"})
    except Exception:
        return respuesta(500, "Error al obtener el producto")
    if not lista:
        return respuesta(404, "Producto no encontrado")
    return lista[0]


@app.put("/products/{id_producto}")
async def editar_producto(id_producto: int, request: Request):
    """US05 · Editar un producto (solo admin)."""
    _, error = solo_admin(request)
    if error:
        return error
    try:
        cuerpo = await request.json()
    except Exception:
        cuerpo = {}

    cambios = {}
    for campo in ("title", "description", "category", "image"):
        if campo in cuerpo:
            valor = str(cuerpo[campo] or "").strip()
            if campo in ("title", "category") and not valor:
                return respuesta(400, f"El campo {campo} no puede estar vacío")
            cambios[campo] = valor
    if "price" in cuerpo:
        try:
            precio = float(cuerpo["price"])
        except (TypeError, ValueError):
            return respuesta(400, "El precio debe ser un número")
        if precio < 0:
            return respuesta(400, "El precio no puede ser negativo")
        cambios["price"] = precio
    if not cambios:
        return respuesta(400, "No hay datos para actualizar")

    try:
        r = db("PATCH", params={"id": f"eq.{id_producto}"}, json=cambios, tabla="productos")
        r.raise_for_status()
        filas = r.json()
    except Exception:
        return respuesta(500, "Error al editar el producto")
    if not filas:
        return respuesta(404, "Producto no encontrado")
    return formato_producto(filas[0])


@app.delete("/products/{id_producto}")
def eliminar_producto(id_producto: int, request: Request):
    """US05 · Eliminar un producto (solo admin)."""
    _, error = solo_admin(request)
    if error:
        return error
    try:
        r = db("DELETE", params={"id": f"eq.{id_producto}"}, tabla="productos")
        r.raise_for_status()
        borrados = r.json()
    except Exception:
        return respuesta(500, "Error al eliminar el producto")
    if not borrados:
        return respuesta(404, "Producto no encontrado")
    return {"mensaje": "Producto eliminado"}


@app.post("/auth/register")
async def registrar(request: Request):
    try:
        cuerpo = await request.json()
    except Exception:
        cuerpo = {}
    nombre = str(cuerpo.get("nombre") or "").strip()
    usuario = str(cuerpo.get("usuario") or "").strip().lower()
    password = str(cuerpo.get("password") or "")

    if not nombre or not usuario or not password:
        return respuesta(400, "Nombre, usuario y contraseña son obligatorios")
    if len(password) < 4:
        return respuesta(400, "La contraseña debe tener al menos 4 caracteres")

    # Encriptamos la contraseña antes de guardarla
    encriptado = bcrypt.hashpw(password.encode(), bcrypt.gensalt(10)).decode()

    try:
        r = crear_usuario(nombre, usuario, encriptado)
    except Exception:
        return respuesta(500, "Error al registrar")

    if r.status_code == 409 or (r.status_code >= 400 and "23505" in r.text):
        return respuesta(409, "Ese usuario ya existe")
    if r.status_code >= 400:
        return respuesta(500, "Error al registrar")

    nuevo = r.json()[0]
    return JSONResponse(status_code=201, content={
        "mensaje": "Usuario registrado",
        "usuario": datos_publicos(nuevo),
    })


@app.post("/auth/login")
async def login(request: Request):
    try:
        cuerpo = await request.json()
    except Exception:
        cuerpo = {}
    usuario = str(cuerpo.get("usuario") or "").strip().lower()
    password = str(cuerpo.get("password") or "")

    if not usuario or not password:
        return respuesta(400, "Usuario y contraseña son obligatorios")

    try:
        u = buscar_usuario(usuario)
    except Exception:
        return respuesta(500, "Error del servidor")

    correcto = False
    if u:
        try:
            correcto = bcrypt.checkpw(password.encode(), u["password"].encode())
        except ValueError:
            correcto = False
    if not u or not correcto:
        return respuesta(401, "Usuario o contraseña inválidos")

    # La "pulsera": dura 8 horas
    token = jwt.encode(
        {
            "id": u["id"],
            "usuario": u["usuario"],
            "rol": u["rol"],
            "exp": datetime.now(timezone.utc) + timedelta(hours=8),
        },
        JWT_SECRET,
        algorithm="HS256",
    )
    return {"token": token, "usuario": datos_publicos(u)}


@app.get("/usuarios")
def usuarios_admin(request: Request):
    _, error = solo_admin(request)
    if error:
        return error
    try:
        return listar_usuarios()
    except Exception:
        return respuesta(500, "Error al obtener usuarios")


@app.delete("/usuarios/{id_usuario}")
def borrar_usuario(id_usuario: int, request: Request):
    datos, error = solo_admin(request)
    if error:
        return error
    if id_usuario == datos.get("id"):
        return respuesta(400, "No puedes eliminar tu propia cuenta")
    try:
        borrados = eliminar_usuario(id_usuario)
    except Exception:
        return respuesta(500, "Error al eliminar")
    if not borrados:
        return respuesta(404, "Usuario no encontrado")
    return {"mensaje": "Usuario eliminado"}
