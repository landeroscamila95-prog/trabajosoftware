CREATE TABLE IF NOT EXISTS usuarios (
    id_usuario SERIAL PRIMARY KEY,
    username VARCHAR(50) UNIQUE NOT NULL,
    password VARCHAR(128) NOT NULL,
    rol VARCHAR(20) NOT NULL DEFAULT 'cliente'
);

CREATE TABLE IF NOT EXISTS calificacion_tributaria (
    id_calificacion SERIAL PRIMARY KEY,
    origen VARCHAR(100) NOT NULL,
    mercado VARCHAR(50) NOT NULL,
    periodo_comercial DATE NOT NULL,
    usuario_registro VARCHAR(50) DEFAULT 'admin',
    fecha_creacion TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS detalle_factores (
    id_detalle SERIAL PRIMARY KEY,
    id_calificacion INT REFERENCES calificacion_tributaria(id_calificacion) ON DELETE CASCADE,
    numero_factor INT NOT NULL,
    valor_calculado NUMERIC(18, 8) NOT NULL
);

CREATE TABLE IF NOT EXISTS log_auditoria (
    id_log SERIAL PRIMARY KEY,
    usuario VARCHAR(50) NOT NULL,
    rol VARCHAR(20) NOT NULL,
    accion VARCHAR(100) NOT NULL,
    detalle TEXT,
    fecha_hora TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);