# Usamos una imagen oficial de Python ligera
FROM python:3.11-slim

# Directorio de trabajo dentro del contenedor
WORKDIR /app

# Copiamos primero requirements para aprovechar la caché de Docker
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copiamos el resto del código
COPY . .

# Puerto que expone Flask
EXPOSE 5000

# Comando para arrancar la app
CMD ["python", "app.py"]
