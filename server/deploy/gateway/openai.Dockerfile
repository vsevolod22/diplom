# Separate opt-in image; existing composition and OpenRouter remain unchanged.
FROM python:3.13.7-slim
WORKDIR /opt/gateway
COPY server/deploy/gateway/proxy.py server/deploy/gateway/openai.py ./
USER 65532:65532
CMD ["python", "-I", "openai.py", "--serve"]
