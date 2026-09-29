FROM python:3.11-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app/ ./app/

EXPOSE 8030

CMD ["uvicorn", "app.main:app", "--host", "127.0.0.1", "--port", "8030"]
