"""Delegate temporal decisions to the worker's exact-nanosecond operator evaluator.

This checks public metadata only, not signatures or scanner compatibility. Never
accept its output as release authentication or an admission/coverage proof.
"""
import json
from pathlib import Path
import shutil
import subprocess


def evaluate_metadata(metadata):
    node = shutil.which('node')
    if not node:
        raise ValueError('Node required for shared DB policy')
    result = subprocess.run([node, str(Path(__file__).with_name('evaluate-db-metadata.mjs'))],
                            input=json.dumps(metadata).encode(), stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE, timeout=10, check=False,
                            env={'PATH': '/usr/bin:/bin'})
    if result.returncode:
        raise ValueError('DB metadata unusable')
    return json.loads(result.stdout)
