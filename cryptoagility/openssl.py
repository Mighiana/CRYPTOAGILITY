"""Timeout-bounded invocation of an isolated, established crypto implementation."""

import os
import shutil
import subprocess
from pathlib import Path

MAX_FILE_BYTES = 4 * 1024 * 1024


class OpenSSLError(RuntimeError):
    pass


def executable() -> str:
    configured = os.environ.get("CRYPTOAGILITY_OPENSSL")
    local = Path(__file__).resolve().parent.parent / ".tools/openssl/bin/openssl"
    candidate = configured or (str(local) if local.is_file() else shutil.which("openssl"))
    if not candidate or not Path(candidate).is_file():
        raise OpenSSLError("OpenSSL executable unavailable; run make setup")
    return candidate


def run(args: list[str], *, input: bytes | None = None, timeout: float = 15) -> bytes:
    env = dict(os.environ)
    env.pop("OPENSSL_CONF", None)
    env.pop("OPENSSL_MODULES", None)
    env["OPENSSL_CONF"] = os.devnull
    try:
        result = subprocess.run(
            [executable(), *args], input=input, capture_output=True, timeout=timeout,
            check=False, env=env,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise OpenSSLError("OpenSSL command failed or timed out") from exc
    if result.returncode:
        # Do not include input, key material or arbitrary OpenSSL diagnostics in reports.
        raise OpenSSLError(f"OpenSSL {args[0] if args else 'command'} failed")
    return result.stdout


def read_bounded(path: Path) -> bytes:
    if path.is_symlink() or not path.is_file():
        raise ValueError("Input must be a regular non-symlink file")
    with path.open("rb") as stream:
        data = stream.read(MAX_FILE_BYTES + 1)
    if len(data) > MAX_FILE_BYTES:
        raise ValueError("Input exceeds 4 MiB limit")
    return data
