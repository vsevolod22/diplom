FROM python:3.13.7-slim
COPY server/deploy/proof/registry.py /registry.py
COPY server/deploy/proof/sink.py /sink.py
USER 65532:65532
CMD ["python", "/registry.py"]
