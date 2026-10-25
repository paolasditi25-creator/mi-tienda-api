# =====================================================================
#  API DE "MI TIENDA"  (la oficina central de la frutería 🍎)
#  Python + FastAPI + Supabase  ·  Publicada en Vercel
#
#  Ventanillas (endpoints):
#    GET    /                -> revisar que la API está viva
#    GET    /users           -> lista pública de usuarios en JSON (como fakestoreapi.com/users)
#    GET    /products        -> catálogo de productos en JSON (como fakestoreapi.com/products)
#    GET    /products/{id}   -> un producto
#    POST   /auth/register   -> registrarse (siempre con rol "usuario")
#    POST   /auth/login      -> iniciar sesión (devuelve token + rol)
#    GET    /usuarios        -> lista de usuarios          (solo admin)
#    DELETE /usuarios/{id}   -> eliminar un usuario        (solo admin)
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
def db(metodo: str, params: dict | None = None, json: dict | None = None):
    """Habla con la tabla 'usuarios' de Supabase."""
    return httpx.request(
        metodo,
        f"{SUPABASE_URL}/rest/v1/usuarios",
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


# --- Catálogo de productos (la mercancía de la frutería) -----------------
# Ahora los productos viven en NUESTRA API, ya no dependemos de otra página.
PRODUCTOS = [
    {
        "id": 1,
        "title": "Fjallraven - Foldsack No. 1 Backpack, Fits 15 Laptops",
        "price": 109.95,
        "description": "Your perfect pack for everyday use and walks in the forest. Stash your laptop (up to 15 inches) in the padded sleeve, your everyday",
        "category": "men's clothing",
        "image": "https://fakestoreapi.com/img/81fPKd-2AYL._AC_SL1500_t.png",
        "rating": {
            "rate": 3.9,
            "count": 120
        }
    },
    {
        "id": 2,
        "title": "Mens Casual Premium Slim Fit T-Shirts ",
        "price": 22.3,
        "description": "Slim-fitting style, contrast raglan long sleeve, three-button henley placket, light weight & soft fabric for breathable and comfortable wearing. And Solid stitched shirts with round neck made for durability and a great fit for casual fashion wear and diehard baseball fans. The Henley style round neckline includes a three-button placket.",
        "category": "men's clothing",
        "image": "https://fakestoreapi.com/img/71-3HjGNDUL._AC_SY879._SX._UX._SY._UY_t.png",
        "rating": {
            "rate": 4.1,
            "count": 259
        }
    },
    {
        "id": 3,
        "title": "Mens Cotton Jacket",
        "price": 55.99,
        "description": "great outerwear jackets for Spring/Autumn/Winter, suitable for many occasions, such as working, hiking, camping, mountain/rock climbing, cycling, traveling or other outdoors. Good gift choice for you or your family member. A warm hearted love to Father, husband or son in this thanksgiving or Christmas Day.",
        "category": "men's clothing",
        "image": "https://fakestoreapi.com/img/71li-ujtlUL._AC_UX679_t.png",
        "rating": {
            "rate": 4.7,
            "count": 500
        }
    },
    {
        "id": 4,
        "title": "Mens Casual Slim Fit",
        "price": 15.99,
        "description": "The color could be slightly different between on the screen and in practice. / Please note that body builds vary by person, therefore, detailed size information should be reviewed below on the product description.",
        "category": "men's clothing",
        "image": "https://fakestoreapi.com/img/71YXzeOuslL._AC_UY879_t.png",
        "rating": {
            "rate": 2.1,
            "count": 430
        }
    },
    {
        "id": 5,
        "title": "John Hardy Women's Legends Naga Gold & Silver Dragon Station Chain Bracelet",
        "price": 695,
        "description": "From our Legends Collection, the Naga was inspired by the mythical water dragon that protects the ocean's pearl. Wear facing inward to be bestowed with love and abundance, or outward for protection.",
        "category": "jewelery",
        "image": "https://fakestoreapi.com/img/71pWzhdJNwL._AC_UL640_QL65_ML3_t.png",
        "rating": {
            "rate": 4.6,
            "count": 400
        }
    },
    {
        "id": 6,
        "title": "Solid Gold Petite Micropave ",
        "price": 168,
        "description": "Satisfaction Guaranteed. Return or exchange any order within 30 days.Designed and sold by Hafeez Center in the United States. Satisfaction Guaranteed. Return or exchange any order within 30 days.",
        "category": "jewelery",
        "image": "https://fakestoreapi.com/img/61sbMiUnoGL._AC_UL640_QL65_ML3_t.png",
        "rating": {
            "rate": 3.9,
            "count": 70
        }
    },
    {
        "id": 7,
        "title": "White Gold Plated Princess",
        "price": 9.99,
        "description": "Classic Created Wedding Engagement Solitaire Diamond Promise Ring for Her. Gifts to spoil your love more for Engagement, Wedding, Anniversary, Valentine's Day...",
        "category": "jewelery",
        "image": "https://fakestoreapi.com/img/71YAIFU48IL._AC_UL640_QL65_ML3_t.png",
        "rating": {
            "rate": 3,
            "count": 400
        }
    },
    {
        "id": 8,
        "title": "Pierced Owl Rose Gold Plated Stainless Steel Double",
        "price": 10.99,
        "description": "Rose Gold Plated Double Flared Tunnel Plug Earrings. Made of 316L Stainless Steel",
        "category": "jewelery",
        "image": "https://fakestoreapi.com/img/51UDEzMJVpL._AC_UL640_QL65_ML3_t.png",
        "rating": {
            "rate": 1.9,
            "count": 100
        }
    },
    {
        "id": 9,
        "title": "WD 2TB Elements Portable External Hard Drive - USB 3.0 ",
        "price": 64,
        "description": "USB 3.0 and USB 2.0 Compatibility Fast data transfers Improve PC Performance High Capacity; Compatibility Formatted NTFS for Windows 10, Windows 8.1, Windows 7; Reformatting may be required for other operating systems; Compatibility may vary depending on user's hardware configuration and operating system",
        "category": "electronics",
        "image": "https://fakestoreapi.com/img/61IBBVJvSDL._AC_SY879_t.png",
        "rating": {
            "rate": 3.3,
            "count": 203
        }
    },
    {
        "id": 10,
        "title": "SanDisk SSD PLUS 1TB Internal SSD - SATA III 6 Gb/s",
        "price": 109,
        "description": "Easy upgrade for faster boot up, shutdown, application load and response. Boosts burst write performance, making it ideal for typical PC workloads. The perfect balance of performance and reliability. Read/write speeds of up to 535MB/s/450MB/s.",
        "category": "electronics",
        "image": "https://fakestoreapi.com/img/61U7T1koQqL._AC_SX679_t.png",
        "rating": {
            "rate": 2.9,
            "count": 470
        }
    },
    {
        "id": 11,
        "title": "Silicon Power 256GB SSD 3D NAND A55 SLC Cache Performance Boost SATA III 2.5",
        "price": 109,
        "description": "3D NAND flash are applied to deliver high transfer speeds Remarkable transfer speeds that enable faster bootup and improved overall system performance. The advanced SLC Cache Technology allows performance boost and longer lifespan 7mm slim design suitable for Ultrabooks and Ultra-slim notebooks.",
        "category": "electronics",
        "image": "https://fakestoreapi.com/img/71kWymZ+c+L._AC_SX679_t.png",
        "rating": {
            "rate": 4.8,
            "count": 319
        }
    },
    {
        "id": 12,
        "title": "WD 4TB Gaming Drive Works with Playstation 4 Portable External Hard Drive",
        "price": 114,
        "description": "Expand your PS4 gaming experience, Play anywhere Fast and easy, setup Sleek design with high capacity, 3-year manufacturer's limited warranty",
        "category": "electronics",
        "image": "https://fakestoreapi.com/img/61mtL65D4cL._AC_SX679_t.png",
        "rating": {
            "rate": 4.8,
            "count": 400
        }
    },
    {
        "id": 13,
        "title": "Acer SB220Q bi 21.5 inches Full HD (1920 x 1080) IPS Ultra-Thin",
        "price": 599,
        "description": "21.5 inches Full HD (1920 x 1080) widescreen IPS display And Radeon free Sync technology. Zero-frame design, ultra-thin, 4ms response time, IPS panel. Aspect ratio 16:9. 75 hertz.",
        "category": "electronics",
        "image": "https://fakestoreapi.com/img/81QpkIctqPL._AC_SX679_t.png",
        "rating": {
            "rate": 2.9,
            "count": 250
        }
    },
    {
        "id": 14,
        "title": "Samsung 49-Inch CHG90 144Hz Curved Gaming Monitor (LC49HG90DMNXZA) - Super Ultrawide Screen QLED ",
        "price": 999.99,
        "description": "49 INCH SUPER ULTRAWIDE 32:9 CURVED GAMING MONITOR with dual 27 inch screen side by side QUANTUM DOT (QLED) TECHNOLOGY, HDR support and factory calibration provides stunningly realistic and accurate color and contrast 144HZ HIGH REFRESH RATE and 1ms ultra fast response time work to eliminate motion blur, ghosting, and reduce input lag",
        "category": "electronics",
        "image": "https://fakestoreapi.com/img/81Zt42ioCgL._AC_SX679_t.png",
        "rating": {
            "rate": 2.2,
            "count": 140
        }
    },
    {
        "id": 15,
        "title": "BIYLACLESEN Women's 3-in-1 Snowboard Jacket Winter Coats",
        "price": 56.99,
        "description": "Material: 100% Polyester; Detachable Liner Fabric: Warm Fleece. Stand Collar Liner jacket, keep you warm in cold weather. Zippered Pockets. Adjustable and Detachable Hood. 3 in 1 Detachable Design.",
        "category": "women's clothing",
        "image": "https://fakestoreapi.com/img/51Y5NI-I5jL._AC_UX679_t.png",
        "rating": {
            "rate": 2.6,
            "count": 235
        }
    },
    {
        "id": 16,
        "title": "Lock and Love Women's Removable Hooded Faux Leather Moto Biker Jacket",
        "price": 29.95,
        "description": "100% POLYURETHANE(shell) 100% POLYESTER(lining) 75% POLYESTER 25% COTTON (SWEATER), Faux leather material for style and comfort / 2 pockets of front, 2-For-One Hooded denim style faux leather jacket, Button detail on waist / Detail stitching at sides, HAND WASH ONLY / DO NOT BLEACH / LINE DRY / DO NOT IRON",
        "category": "women's clothing",
        "image": "https://fakestoreapi.com/img/81XH0e8fefL._AC_UY879_t.png",
        "rating": {
            "rate": 2.9,
            "count": 340
        }
    },
    {
        "id": 17,
        "title": "Rain Jacket Women Windbreaker Striped Climbing Raincoats",
        "price": 39.99,
        "description": "Lightweight perfet for trip or casual wear---Long sleeve with hooded, adjustable drawstring waist design. Button and zipper front closure raincoat, fully stripes Lined and The Raincoat has 2 side pockets are a good size to hold all kinds of things, it covers the hips, and the hood is generous but doesn't overdo it.",
        "category": "women's clothing",
        "image": "https://fakestoreapi.com/img/71HblAHs5xL._AC_UY879_-2t.png",
        "rating": {
            "rate": 3.8,
            "count": 679
        }
    },
    {
        "id": 18,
        "title": "MBJ Women's Solid Short Sleeve Boat Neck V ",
        "price": 9.85,
        "description": "95% RAYON 5% SPANDEX, Made in USA or Imported, Do Not Bleach, Lightweight fabric with great stretch for comfort, Ribbed on sleeves and neckline / Double stitching on bottom hem",
        "category": "women's clothing",
        "image": "https://fakestoreapi.com/img/71z3kpMAYsL._AC_UY879_t.png",
        "rating": {
            "rate": 4.7,
            "count": 130
        }
    },
    {
        "id": 19,
        "title": "Opna Women's Short Sleeve Moisture",
        "price": 7.95,
        "description": "100% Polyester, Machine wash, 100% cationic polyester interlock, Machine Wash & Pre Shrunk for a Great Fit, Lightweight, roomy and highly breathable with moisture wicking fabric which helps to keep moisture away.",
        "category": "women's clothing",
        "image": "https://fakestoreapi.com/img/51eg55uWmdL._AC_UX679_t.png",
        "rating": {
            "rate": 4.5,
            "count": 146
        }
    },
    {
        "id": 20,
        "title": "DANVOUY Womens T Shirt Casual Cotton Short",
        "price": 12.99,
        "description": "95%Cotton,5%Spandex, Features: Casual, Short Sleeve, Letter Print,V-Neck,Fashion Tees, The fabric is soft and has some stretch., Occasion: Casual/Office/Beach/School/Home/Street. Season: Spring,Summer,Autumn,Winter.",
        "category": "women's clothing",
        "image": "https://fakestoreapi.com/img/61pHAEJ4NML._AC_UX679_t.png",
        "rating": {
            "rate": 3.6,
            "count": 145
        }
    }
]


@app.get("/products")
def productos():
    """Catálogo en JSON, como fakestoreapi.com/products."""
    return PRODUCTOS


@app.get("/products/{id_producto}")
def producto(id_producto: int):
    for p in PRODUCTOS:
        if p["id"] == id_producto:
            return p
    return respuesta(404, "Producto no encontrado")


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
