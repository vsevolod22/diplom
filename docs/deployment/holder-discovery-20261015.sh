#!/bin/sh
# Frozen ONE-attempt metadata-only holder discovery; NOT EXECUTED by this reviewer.
# Source/literal correctness approval is conditional on independent final security approval.
# Production290486 is SPENT: reported phaseholder/uncertain/manualtrue; STOP remains, no cause or state inferred.
# Required cwd: /Users/vsevolod/Documents/startup/diplom; external caller timeout_ms=75000.
# Shared60s/client10s/at most8 fixed metadata calls; final public JSON4096B; no retry or fallback.
# DISCOVERED_NOT_ADOPTED only: no Env/content/log/SQL, lock/lifecycle changes, holder adoption or cleanup authority.
DOCKER_CONTEXT= DOCKER_HOST=unix:///Users/vsevolod/.docker/run/docker.sock PYTHONDONTWRITEBYTECODE=1 \
/Library/Frameworks/Python.framework/Versions/3.13/bin/python3 -I -B \
server/deploy/trust/discover_preservation_holder.py \
--discover-once \
--source-sha256 674dbe2f279a05b1263ae28cd2d62913fdcad608d90442fc7e47b506a571419d \
--test-sha256 fcc460c988057d50c7a51138fa7ca64522aaa1b0b24f615582aea12e444085af
