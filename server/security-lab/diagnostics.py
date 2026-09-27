"""Boundary for scanner failures: never retain raw stdout/stderr or remote URLs."""


def scanner_failure(returncode: int) -> dict[str, str]:
    # Trivy's errors include registry URLs (including signed query parameters).
    # Deliberately do not accept scanner output as an argument.
    return {"errorCode": "SCANNER_FAILED", "message": "Image scan failed", "exitCode": str(returncode)}
