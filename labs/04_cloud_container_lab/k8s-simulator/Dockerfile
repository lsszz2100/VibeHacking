FROM python:3.11-slim
WORKDIR /app
RUN pip install --no-cache-dir flask flask-jwt-extended
COPY app.py .
EXPOSE 8443
CMD ["python", "app.py"]
