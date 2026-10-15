#!/bin/sh
# Frozen ONE-attempt metadata-only holder discovery R2; NOT EXECUTED by this reviewer.
# Source/literal correctness approval is conditional on independent final security approval.
# Production290486 and discoverye24a are SPENT; e24a reported LIST/UNEXPECTED, no actual states inferred; STOP remains.
# Required cwd: /Users/vsevolod/Documents/startup/diplom; external caller timeout_ms=75000.
# Shared60s/client10s/at most8 fixed metadata calls; final public JSON4096B; no retry or fallback.
# DISCOVERED_NOT_ADOPTED only: no Env/content/log/SQL, lock/lifecycle changes, holder adoption or cleanup authority.
DOCKER_CONTEXT= DOCKER_HOST=unix:///Users/vsevolod/.docker/run/docker.sock PYTHONDONTWRITEBYTECODE=1 \
/Library/Frameworks/Python.framework/Versions/3.13/bin/python3 -I -B \
server/deploy/trust/discover_preservation_holder.py \
--discover-once \
--source-sha256 4afb0bc484d34aca428fee956bd939d7b322727285eef0f721425849bb32a1f4 \
--test-sha256 cc1a168804cb9a07f9c53724730bfbbaae7596c44c88743b0dc169f26a1bf312
