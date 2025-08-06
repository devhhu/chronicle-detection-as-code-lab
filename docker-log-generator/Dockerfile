FROM python:3.11-slim

WORKDIR /app
COPY log_emitter.py .

RUN pip install fluent-logger

CMD ["python", "log_emitter.py"]
