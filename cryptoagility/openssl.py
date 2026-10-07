"""Timeout-bounded invocation of an isolated, established crypto implementation."""

import os
import shutil
import subprocess
from pathlib import Path

MAX_FILE_BYTES = 4 * 1024 * 1024


class OpenSSLError(RuntimeError):
    pass


def executable() -> str:
    """Resolve the pinned lab OpenSSL; never silently fall back to an unrelated build.

    Order: CRYPTOAGILITY_OPENSSL, CRYPTOAGILITY_TOOLS_DIR (as used by setup-openssl.sh),
    the checkout's .tools directory, then system OpenSSL only if explicitly allowed.
    """
    configured = os.environ.get("CRYPTOAGILITY_OPENSSL")
    if configured:
        if not Path(configured).is_file():
            raise OpenSSLError("CRYPTOAGILITY_OPENSSL does not point to a file")
        return configured
    tools_dir = os.environ.get("CRYPTOAGILITY_TOOLS_DIR")
    roots = [Path(tools_dir)] if tools_dir else []
    roots.append(Path(__file__).resolve().parent.parent / ".tools")
    for root in roots:
        candidate = root / "openssl" / "bin" / "openssl"
        if candidate.is_file():
            return str(candidate)
    if os.environ.get("CRYPTOAGILITY_ALLOW_SYSTEM_OPENSSL") == "1":
        system = shutil.which("openssl")
        if system:
            return system
    raise OpenSSLError(
        "Pinned OpenSSL not found; run make setup or set CRYPTOAGILITY_TOOLS_DIR"
    )


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
