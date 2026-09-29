FROM python:3.12-slim

LABEL lab="lab"
LABEL lab_id="28"
LABEL lab_name="NetShield - Cisco & Network Device Security Lab"

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app/ ./app/

EXPOSE 8028

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8028"]
