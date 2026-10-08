FROM python:3.13.7-slim
WORKDIR /opt/gateway
COPY server/deploy/gateway/proxy.py server/deploy/gateway/openrouter.py ./
USER 65532:65532
CMD ["python", "-I", "openrouter.py"]
