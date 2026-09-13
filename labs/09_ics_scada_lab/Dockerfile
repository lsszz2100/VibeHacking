FROM python:3.11-slim

WORKDIR /app

# Install curl and netcat for troubleshooting
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    netcat-traditional \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app/ /app/

EXPOSE 8089 5020

CMD ["python", "main.py"]
