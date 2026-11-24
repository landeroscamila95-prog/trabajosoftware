from fastapi import FastAPI, HTTPException, UploadFile, File, Header
from fastapi.responses import HTMLResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
from typing import List, Optional
import psycopg2
from psycopg2.extras import RealDictCursor
from decimal import Decimal
import hashlib
import csv
import io
import os

app = FastAPI(title="Sistema de Calificaciones Tributarias - SaaS")

DB_CONFIG = {
    "dbname": "calificaciones_db",
    "user": "postgres",
    "password": "1409",
    "host": "localhost",
    "port": "5432"
}

def get_db_connection():
    return psycopg2.connect(**DB_CONFIG)

def encriptar_password(password: str) -> str:
    """Encriptación SHA-256 para cumplir buenas prácticas OWASP"""
    return hashlib.sha256(password.encode("utf-8")).hexdigest()

def registrar_auditoria(cur, usuario: str, rol: str, accion: str, detalle: str):
    """Trazabilidad y registro de eventos según Ley 21.459"""
    cur.execute(
        "INSERT INTO log_auditoria (usuario, rol, accion, detalle) VALUES (%s, %s, %s, %s)",
        (usuario, rol, accion, detalle)
    )

@app.on_event("startup")
def inicializar_seguridad():
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute("""
            CREATE TABLE IF NOT EXISTS usuarios (
                id_usuario SERIAL PRIMARY KEY,
                username VARCHAR(50) UNIQUE NOT NULL,
                password VARCHAR(128) NOT NULL,
                rol VARCHAR(20) NOT NULL DEFAULT 'cliente'
            );
        """)
        pass_hash = encriptar_password("1234")
        cur.execute("""
            INSERT INTO usuarios (username, password, rol)
            VALUES ('admin', %s, 'admin'), ('cliente', %s, 'cliente')
            ON CONFLICT (username) DO UPDATE SET password = EXCLUDED.password;
        """, (pass_hash, pass_hash))
        conn.commit()
        cur.close()
        conn.close()
    except Exception as e:
        print(f"Aviso inicialización: {e}")

class LoginRequest(BaseModel):
    usuario: str
    password: str

class RegisterRequest(BaseModel):
    usuario: str
    password: str
    rol: str = "cliente"

class CalificacionCreate(BaseModel):
    origen: str
    mercado: str
    periodo_comercial: str
    factores: List[float]

if os.path.exists("static"):
    app.mount("/static", StaticFiles(directory="static"), name="static")

@app.get("/", response_class=HTMLResponse)
def read_root():
    for ruta in ["index.html", "static/index.html"]:
        if os.path.exists(ruta):
            with open(ruta, "r", encoding="utf-8") as f:
                return f.read()
    return "<h1>Error: No se encontró el archivo index.html</h1>"

# --- AUTENTICACIÓN CON HASH SHA-256 ---
@app.post("/api/login")
def api_login(credenciales: LoginRequest):
    conn = get_db_connection()
    cur = conn.cursor(cursor_factory=RealDictCursor)
    try:
        pass_encriptada = encriptar_password(credenciales.password)
        cur.execute(
            "SELECT id_usuario, username, rol FROM usuarios WHERE username = %s AND password = %s",
            (credenciales.usuario.strip(), pass_encriptada)
        )
        user = cur.fetchone()
        if user:
            registrar_auditoria(cur, user["username"], user["rol"], "INICIO_SESION", "Acceso exitoso al sistema")
            conn.commit()
            return {
                "status": "ok",
                "usuario": user["username"],
                "rol": user["rol"]
            }
        raise HTTPException(status_code=401, detail="Usuario o contraseña incorrectos")
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error en base de datos: {str(e)}")
    finally:
        cur.close()
        conn.close()

# --- REGISTRO DE NUEVO USUARIO ---
@app.post("/api/registro")
def api_registro(datos: RegisterRequest):
    username = datos.usuario.strip()
    password = datos.password.strip()
    rol = datos.rol.strip().lower()

    if len(username) < 3:
        raise HTTPException(status_code=400, detail="El nombre de usuario debe tener al menos 3 caracteres.")
    if len(password) < 4:
        raise HTTPException(status_code=400, detail="La contraseña debe tener al menos 4 caracteres.")
    if rol not in ("admin", "cliente"):
        rol = "cliente"

    conn = get_db_connection()
    cur = conn.cursor(cursor_factory=RealDictCursor)
    try:
        cur.execute("SELECT id_usuario FROM usuarios WHERE username = %s", (username,))
        if cur.fetchone():
            raise HTTPException(status_code=400, detail="Ese nombre de usuario ya existe.")

        pass_encriptada = encriptar_password(password)
        cur.execute(
            "INSERT INTO usuarios (username, password, rol) VALUES (%s, %s, %s) RETURNING id_usuario",
            (username, pass_encriptada, rol)
        )
        registrar_auditoria(cur, username, rol, "REGISTRO_USUARIO", f"Nuevo usuario registrado con rol '{rol}'")
        conn.commit()
        return {
            "status": "ok",
            "mensaje": f"Usuario '{username}' registrado correctamente con rol '{rol}'.",
            "usuario": username,
            "rol": rol
        }
    except HTTPException:
        raise
    except Exception as e:
        conn.rollback()
        raise HTTPException(status_code=500, detail=f"Error al registrar usuario: {str(e)}")
    finally:
        cur.close()
        conn.close()

@app.get("/api/calificaciones")
def listar_calificaciones(mercado: Optional[str] = "TODOS"):
    conn = get_db_connection()
    cur = conn.cursor(cursor_factory=RealDictCursor)
    try:
        if mercado and mercado != "TODOS":
            cur.execute(
                "SELECT * FROM calificacion_tributaria WHERE mercado = %s ORDER BY id_calificacion DESC",
                (mercado,)
            )
        else:
            cur.execute("SELECT * FROM calificacion_tributaria ORDER BY id_calificacion DESC")
        
        registros = cur.fetchall()
        for r in registros:
            r["periodo_comercial"] = str(r["periodo_comercial"])
            r["fecha_creacion"] = str(r["fecha_creacion"])
            r["usuario_registro"] = r.get("usuario_registro") or "admin"
        return registros
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error al consultar PostgreSQL: {str(e)}")
    finally:
        cur.close()
        conn.close()

@app.get("/api/calificaciones/{id_calificacion}")
def obtener_detalle(id_calificacion: int):
    conn = get_db_connection()
    cur = conn.cursor(cursor_factory=RealDictCursor)
    try:
        cur.execute("SELECT * FROM calificacion_tributaria WHERE id_calificacion = %s", (id_calificacion,))
        cabecera = cur.fetchone()
        if not cabecera:
            raise HTTPException(status_code=404, detail="Calificación no encontrada")
        
        cabecera["periodo_comercial"] = str(cabecera["periodo_comercial"])
        cabecera["fecha_creacion"] = str(cabecera["fecha_creacion"])

        cur.execute(
            "SELECT numero_factor, valor_calculado FROM detalle_factores WHERE id_calificacion = %s ORDER BY numero_factor ASC",
            (id_calificacion,)
        )
        factores = cur.fetchall()
        for f in factores:
            f["valor_calculado"] = float(f["valor_calculado"])

        return {"cabecera": cabecera, "factores": factores}
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        cur.close()
        conn.close()

@app.post("/api/calificaciones")
def crear_calificacion(
    data: CalificacionCreate,
    x_usuario: Optional[str] = Header(default="anonimo"),
    x_rol: Optional[str] = Header(default="cliente")
):
    if not data.periodo_comercial or not data.periodo_comercial.strip():
        raise HTTPException(status_code=400, detail="El período comercial (fecha) es obligatorio.")

    if len(data.factores) != 29:
        raise HTTPException(status_code=400, detail=f"Se requieren exactamente 29 factores (recibidos: {len(data.factores)})")

    factores_dec = [round(Decimal(str(f)), 8) for f in data.factores]
    suma_8_16 = sum(factores_dec[7:16])
    if suma_8_16 > Decimal("1.00000000"):
        raise HTTPException(
            status_code=400,
            detail=f"Regla incumplida: La suma de los factores 8 al 16 es {suma_8_16} y supera 1.00000000"
        )

    conn = get_db_connection()
    cur = conn.cursor()
    try:
        cur.execute(
            """
            INSERT INTO calificacion_tributaria (origen, mercado, periodo_comercial, usuario_registro)
            VALUES (%s, %s, %s, %s) RETURNING id_calificacion
            """,
            (data.origen, data.mercado, data.periodo_comercial.strip(), x_usuario)
        )
        nuevo_id = cur.fetchone()[0]

        for idx, valor in enumerate(factores_dec, start=1):
            cur.execute(
                """
                INSERT INTO detalle_factores (id_calificacion, numero_factor, valor_calculado)
                VALUES (%s, %s, %s)
                """,
                (nuevo_id, idx, valor)
            )

        registrar_auditoria(cur, x_usuario, x_rol, "CREAR_CALIFICACION", f"Registro #{nuevo_id} ({data.origen} - {data.mercado})")
        conn.commit()
        return {"mensaje": "Calificación registrada con éxito y auditada", "id_calificacion": nuevo_id}
    except Exception as e:
        conn.rollback()
        raise HTTPException(status_code=500, detail=f"Error al guardar en PostgreSQL: {str(e)}")
    finally:
        cur.close()
        conn.close()

@app.put("/api/calificaciones/{id_calificacion}")
def actualizar_calificacion(
    id_calificacion: int,
    data: CalificacionCreate,
    x_usuario: Optional[str] = Header(default="anonimo"),
    x_rol: Optional[str] = Header(default="cliente")
):
    if x_rol != "admin":
        raise HTTPException(status_code=403, detail="Acceso denegado (Ley 21.459 / RBAC): Solo el administrador puede editar registros.")

    if not data.periodo_comercial or not data.periodo_comercial.strip():
        raise HTTPException(status_code=400, detail="El período comercial (fecha) es obligatorio.")

    if len(data.factores) != 29:
        raise HTTPException(status_code=400, detail="Se requieren exactamente 29 factores")

    factores_dec = [round(Decimal(str(f)), 8) for f in data.factores]
    suma_8_16 = sum(factores_dec[7:16])
    if suma_8_16 > Decimal("1.00000000"):
        raise HTTPException(
            status_code=400,
            detail=f"Regla incumplida: La suma de los factores 8 al 16 es {suma_8_16} y supera 1.00000000"
        )

    conn = get_db_connection()
    cur = conn.cursor()
    try:
        cur.execute(
            """
            UPDATE calificacion_tributaria
            SET origen = %s, mercado = %s, periodo_comercial = %s
            WHERE id_calificacion = %s
            """,
            (data.origen, data.mercado, data.periodo_comercial.strip(), id_calificacion)
        )
        if cur.rowcount == 0:
            raise HTTPException(status_code=404, detail="Calificación no encontrada")

        cur.execute("DELETE FROM detalle_factores WHERE id_calificacion = %s", (id_calificacion,))
        for idx, valor in enumerate(factores_dec, start=1):
            cur.execute(
                """
                INSERT INTO detalle_factores (id_calificacion, numero_factor, valor_calculado)
                VALUES (%s, %s, %s)
                """,
                (id_calificacion, idx, valor)
            )

        registrar_auditoria(cur, x_usuario, x_rol, "EDITAR_CALIFICACION", f"Modificación en registro #{id_calificacion}")
        conn.commit()
        return {"mensaje": f"Calificación #{id_calificacion} actualizada correctamente"}
    except HTTPException:
        raise
    except Exception as e:
        conn.rollback()
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        cur.close()
        conn.close()

@app.delete("/api/calificaciones/{id_calificacion}")
def eliminar_calificacion(
    id_calificacion: int,
    x_usuario: Optional[str] = Header(default="anonimo"),
    x_rol: Optional[str] = Header(default="cliente")
):
    if x_rol != "admin":
        raise HTTPException(status_code=403, detail="Acceso denegado (Ley 21.459 / RBAC): Solo el administrador puede eliminar registros.")

    conn = get_db_connection()
    cur = conn.cursor()
    try:
        cur.execute("DELETE FROM calificacion_tributaria WHERE id_calificacion = %s", (id_calificacion,))
        if cur.rowcount == 0:
            raise HTTPException(status_code=404, detail="Calificación no encontrada")
        registrar_auditoria(cur, x_usuario, x_rol, "ELIMINAR_CALIFICACION", f"Eliminación de registro #{id_calificacion}")
        conn.commit()
        return {"mensaje": f"Calificación #{id_calificacion} eliminada correctamente"}
    except HTTPException:
        raise
    except Exception as e:
        conn.rollback()
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        cur.close()
        conn.close()

@app.get("/api/auditoria")
def obtener_auditoria():
    conn = get_db_connection()
    cur = conn.cursor(cursor_factory=RealDictCursor)
    try:
        cur.execute("SELECT * FROM log_auditoria ORDER BY id_log DESC LIMIT 50")
        logs = cur.fetchall()
        for l in logs:
            l["fecha_hora"] = str(l["fecha_hora"]).split(".")[0]
        return logs
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        cur.close()
        conn.close()

@app.get("/api/calificaciones/plantilla/csv")
def descargar_plantilla_csv():
    output = io.StringIO()
    writer = csv.writer(output)
    encabezados = ["origen", "mercado", "periodo_comercial"] + [f"factor_{i}" for i in range(1, 30)]
    writer.writerow(encabezados)
    factores_ejemplo = ["0.08000000" if 8 <= i <= 16 else "0.02000000" for i in range(1, 30)]
    writer.writerow(["Corredora de Bolsa", "Acciones", "2026-11-23"] + factores_ejemplo)
    output.seek(0)
    return StreamingResponse(
        iter([output.getvalue()]),
        media_type="text/csv",
        headers={"Content-Disposition": "attachment; filename=plantilla_calificaciones.csv"}
    )

@app.post("/api/calificaciones/cargar-csv")
async def cargar_csv(
    file: UploadFile = File(...),
    x_usuario: Optional[str] = Header(default="anonimo"),
    x_rol: Optional[str] = Header(default="cliente")
):
    contenido = await file.read()
    try:
        texto = contenido.decode("utf-8-sig")
    except UnicodeDecodeError:
        texto = contenido.decode("latin-1")

    lineas = texto.splitlines()
    if not lineas:
        raise HTTPException(status_code=400, detail="El archivo CSV está vacío.")

    primera_linea = lineas[0]
    delimitador = ";" if ";" in primera_linea else ","

    lector = csv.reader(io.StringIO(texto), delimiter=delimitador)
    cabecera = next(lector, None)

    tiene_id = False
    if cabecera and len(cabecera) > 0 and cabecera[0].strip().lower() == "id":
        tiene_id = True

    conn = get_db_connection()
    cur = conn.cursor()
    procesados = 0
    errores = 0
    motivos_error = []

    try:
        for num_fila, fila in enumerate(lector, start=2):
            if not fila or all(c.strip() == "" for c in fila):
                continue

            if tiene_id or (len(fila) >= 33 and fila[0].strip().isdigit()):
                fila = fila[1:]

            while len(fila) > 32 and fila[-1].strip() == "":
                fila.pop()

            if len(fila) < 32:
                errores += 1
                motivos_error.append(f"Fila {num_fila}: tiene {len(fila)} columnas (se esperan 32)")
                continue

            try:
                origen = fila[0].strip()
                mercado = fila[1].strip()
                periodo = fila[2].strip()
                if not periodo:
                    errores += 1
                    motivos_error.append(f"Fila {num_fila}: falta fecha")
                    continue

                factores_dec = []
                for idx_col, val_str in enumerate(fila[3:32], start=1):
                    limpio = val_str.strip().replace(",", ".")
                    if limpio == "":
                        limpio = "0"
                    factores_dec.append(round(Decimal(limpio), 8))

                suma_critica = sum(factores_dec[7:16])
                if suma_critica > Decimal("1.00000000"):
                    errores += 1
                    motivos_error.append(f"Fila {num_fila}: suma factores 8-16 es {suma_critica} (> 1.0)")
                    continue

                cur.execute(
                    """
                    INSERT INTO calificacion_tributaria (origen, mercado, periodo_comercial, usuario_registro)
                    VALUES (%s, %s, %s, %s) RETURNING id_calificacion
                    """,
                    (origen, mercado, periodo, x_usuario)
                )
                nuevo_id = cur.fetchone()[0]

                for idx, val in enumerate(factores_dec, start=1):
                    cur.execute(
                        "INSERT INTO detalle_factores (id_calificacion, numero_factor, valor_calculado) VALUES (%s, %s, %s)",
                        (nuevo_id, idx, val)
                    )
                procesados += 1
            except Exception as e:
                errores += 1
                motivos_error.append(f"Fila {num_fila}: valor no numérico ({str(e)})")
                continue

        if procesados > 0:
            registrar_auditoria(cur, x_usuario, x_rol, "CARGA_MASIVA_CSV", f"Se importaron {procesados} registros vía CSV")
        conn.commit()
        detalle_err = f" Detalle: {' | '.join(motivos_error[:3])}" if motivos_error else ""
        return {
            "mensaje": f"Carga completada: {procesados} registros guardados. ({errores} omitidos).{detalle_err}"
        }
    except Exception as e:
        conn.rollback()
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        cur.close()
        conn.close()

@app.get("/api/calificaciones/exportar/csv")
def exportar_csv():
    conn = get_db_connection()
    cur = conn.cursor(cursor_factory=RealDictCursor)
    try:
        cur.execute("SELECT * FROM calificacion_tributaria ORDER BY id_calificacion ASC")
        cabeceras = cur.fetchall()

        output = io.StringIO()
        writer = csv.writer(output)
        encabezados = ["ID", "Origen", "Mercado", "Periodo Comercial", "Registrado Por"] + [f"Factor_{i}" for i in range(1, 30)]
        writer.writerow(encabezados)

        for cab in cabeceras:
            cur.execute(
                "SELECT valor_calculado FROM detalle_factores WHERE id_calificacion = %s ORDER BY numero_factor ASC",
                (cab["id_calificacion"],)
            )
            factores = [f"{float(r['valor_calculado']):.8f}" for r in cur.fetchall()]
            fila = [cab["id_calificacion"], cab["origen"], cab["mercado"], str(cab["periodo_comercial"]), cab.get("usuario_registro", "admin")] + factores
            writer.writerow(fila)

        output.seek(0)
        return StreamingResponse(
            iter([output.getvalue()]),
            media_type="text/csv",
            headers={"Content-Disposition": "attachment; filename=calificaciones_tributarias.csv"}
        )
    finally:
        cur.close()
        conn.close()