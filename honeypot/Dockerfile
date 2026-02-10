FROM python:3.11-slim

WORKDIR /app

# updating to install paramiko and its dependencies
RUN pip install --no-cache-dir paramiko==3.4.1

COPY honeypot.py logger.py ./

# Create directories (logs should be empty in submission; created at runtime too)
RUN mkdir -p /app/logs /app/keys

EXPOSE 22

CMD ["python", "-u", "honeypot.py"]
