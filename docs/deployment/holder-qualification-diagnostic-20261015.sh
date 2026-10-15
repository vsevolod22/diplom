#!/bin/sh
# Frozen ONE new read-only holder-metadata classification; NOT EXECUTED by this reviewer.
# Correctness approval conditional on independent security acceptance of exact sources/literal.
# Production successor-R2 shell59fe is SPENT: holder/MIGRATION/PREDICATE_REFUSED, uncertain=true.
# Required cwd: /Users/vsevolod/Documents/startup/diplom; external caller timeout_ms=75000.
# Shared60s/client10s; <=6 fixed read clients, listing<=3 IDs; no retry or follow-up authority.
# Config.Env stays in memory for equality only; no keys/values/lengths/hashes emitted.
# NOT qualification/adoption: no journal/private-state reads, SQL, start/stop, lock, cleanup or resource writes.
DOCKER_CONTEXT= DOCKER_HOST=unix:///Users/vsevolod/.docker/run/docker.sock PYTHONDONTWRITEBYTECODE=1 \
/Library/Frameworks/Python.framework/Versions/3.13/bin/python3 -I -B \
server/deploy/trust/diagnose_holder_qualification.py \
--diagnose-holder-qualification-once \
--source-sha256 e7af4d28088bb8b2ae1849887816d4b83f649125a9735d1c844734bc63c3ea44 \
--test-sha256 63ff7df336db440511c0a716b8a4bccc65578bf1d220e4f22b0a0036e793d264 \
--controller-sha256 72f6393d97b0a946bf2bb607e7f1d0c216d91fb36cfecf20fba9b83fd2c12994 \
--controller-test-sha256 3abf97290344e9d18add867e07a378346922407885da373c43fde2f8a6c19ea2
