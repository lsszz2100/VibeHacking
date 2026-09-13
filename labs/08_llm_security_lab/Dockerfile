FROM python:3.11-slim

WORKDIR /app

RUN apt-get update -qq && \
    apt-get install -y -qq curl procps && \
    rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app/ ./app/

# Create secret flags directory
RUN mkdir -p /app/flags && \
    echo "FLAG{LLM_AGENT_TOOL_ABUSE_EXCESSIVE_AGENCY}" > /app/flags/admin_flag.txt && \
    chmod 644 /app/flags/admin_flag.txt

EXPOSE 8088

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8088"]
