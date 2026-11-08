# Public-source-only minimal context: this Dockerfile + moduleapi-secret-init.py.
# Use a separately approved digest-pinned Python base; no secrets/build env/mounts.
# Review the resulting immutable image ID before any secret provisioning.
ARG PYTHON_BASE
FROM ${PYTHON_BASE}
USER 0:0
COPY --chown=0:0 moduleapi-secret-init.py /opt/moduleapi-secret-init.py
RUN chmod 0444 /opt/moduleapi-secret-init.py
LABEL org.diplom.moduleapi-secret.initializer="v1"
WORKDIR /
HEALTHCHECK NONE
ENTRYPOINT ["/usr/local/bin/python3", "-I", "-S", "-B", "/opt/moduleapi-secret-init.py"]
CMD ["--initialize"]
