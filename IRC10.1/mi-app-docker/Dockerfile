# Usar imagen base de Python
FROM python:3.9-slim

# Establecer directorio de trabajo
WORKDIR /app

# Copiar requirements y instalar dependencias
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copiar código fuente
COPY src/ .

# Exponer puerto
EXPOSE 250

# Establecer variable de entorno
ENV APP_VERSION=1.0.0

# Comando por defecto
CMD ["python", "app.py"]
