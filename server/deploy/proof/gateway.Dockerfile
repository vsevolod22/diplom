FROM python:3.13.7-slim
WORKDIR /opt/gateway
COPY server/deploy/gateway/proxy.py ./proxy.py
COPY server/deploy/proof/gateway.py ./gateway.py
USER 65532:65532
# The isolated proof image has only these two vetted files; -I would hide proxy.py.
CMD ["python", "gateway.py"]
