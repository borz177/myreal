FROM python:3.9-slim

WORKDIR /app

# Установка системных зависимостей (включая всё для WeasyPrint и ReportLab)
RUN apt-get update && apt-get install -y \
    build-essential \
    python3-dev \
    libpango1.0-0 \
    libcairo2 \
    libpangocairo-1.0-0 \
    libgdk-pixbuf2.0-0 \
    libffi-dev \
    shared-mime-info \
    libxml2 \
    libxslt1.1 \
    libjpeg-dev \
    libssl-dev \
    curl \
    fonts-liberation \
    fonts-dejavu \
    libcurl4-openssl-dev \
    zlib1g-dev \
    && rm -rf /var/lib/apt/lists/*

# Копируем зависимости и устанавливаем Python-пакеты
COPY requirements.txt .

RUN pip install --no-cache-dir -r requirements.txt

# Копируем все остальные файлы проекта
COPY . .

# Указываем команду запуска Gunicorn (или поменяй по необходимости)
CMD ["gunicorn", "--bind", "0.0.0.0:8080", "app:app"]
