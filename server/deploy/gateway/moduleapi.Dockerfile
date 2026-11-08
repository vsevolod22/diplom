# Separate opt-in image; no existing composition or gateway default changes.
FROM python:3.13.7-slim
WORKDIR /opt/gateway
COPY server/deploy/gateway/proxy.py server/deploy/gateway/moduleapi.py ./
USER 65532:65532
CMD ["python", "-I", "moduleapi.py", "--serve"]
