FROM python:3.12-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app/ ./app/

ENV PORT=8036
EXPOSE 8036

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8036"]
