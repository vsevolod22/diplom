FROM python:3.13.7-slim
RUN apt-get update && apt-get install -y --no-install-recommends openssl && rm -rf /var/lib/apt/lists/*
CMD ["sh", "-ec", "if test ! -s /certs/cert.pem; then openssl req -x509 -newkey rsa:2048 -sha256 -noenc -days 1 -keyout /certs/key.pem -out /certs/cert.pem -subj '/CN=registry-1.docker.io' -addext 'subjectAltName=DNS:registry-1.docker.io,DNS:auth.docker.io,DNS:production.cloudfront.docker.com' >/dev/null 2>&1; fi; cp /certs/cert.pem /trust/cert.pem; chmod 644 /certs/cert.pem /trust/cert.pem /certs/key.pem"]
