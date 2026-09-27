FROM python:3.13.7-slim
WORKDIR /opt/gateway
COPY server/deploy/gateway/proxy.py ./proxy.py
USER 65532:65532
CMD ["python", "-I", "proxy.py"]
