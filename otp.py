#!/usr/bin/env python3
"""
One-Time Pad utility with safe defaults and streaming XOR.

Back-compat:
- Keeps your original flags: -p (generate pad), -e (encrypt), -d (decrypt).
- Defaults still match your filenames: pad.txt, unencrypted.txt, message.txt, decrypted_message.txt.
- If a filename ends with .txt, values are stored as CSV integers; otherwise raw binary is used.

Safer:
- Default randomness source is local CSPRNG (os.urandom). Use --source randomorg to call random.org.
- Optional --burn removes used pad bytes to prevent reuse.
"""

from __future__ import annotations

import argparse
import base64
import errno
import json
import os
import stat
import sys
from pathlib import Path
from typing import Iterable, Optional

import requests

CHUNK = 65536
RNDORG_MAX_INTS = 10_000  # free-tier practical cap per request
RNDORG_URL = "https://api.random.org/json-rpc/4/invoke"


def eprint(*args, **kwargs):
    print(*args, file=sys.stderr, **kwargs)


def is_text_format(path: Path) -> bool:
    return path.suffix.lower() == ".txt"


def write_file_secure(path: Path, data: bytes) -> None:
    """
    Write bytes to `path` with 0o600 permissions (owner read/write).
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    # Use low-level open to set mode atomically
    fd = os.open(str(path), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(data)
    finally:
        try:
            os.chmod(path, stat.S_IRUSR | stat.S_IWUSR)
        except Exception:
            pass  # best-effort on non-POSIX


def save_as_csv_bytes(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        f.write(",".join(str(b) for b in data))


def load_from_csv_bytes(path: Path) -> bytes:
    with open(path, "r", encoding="utf-8") as f:
        s = f.read().strip()
        if not s:
            return b""
        try:
            vals = [int(x) for x in s.split(",")]
        except ValueError as ex:
            raise ValueError(f"Invalid CSV in {path}: {ex}")
        for v in vals:
            if v < 0 or v > 255:
                raise ValueError(f"Out-of-range byte value {v} in {path}")
        return bytes(vals)


def save_bytes_auto(path: Path, data: bytes) -> None:
    if is_text_format(path):
        save_as_csv_bytes(path, data)
    else:
        write_file_secure(path, data)


def load_bytes_auto(path: Path) -> bytes:
    if is_text_format(path):
        return load_from_csv_bytes(path)
    else:
        with open(path, "rb") as f:
            return f.read()


def getenv_api_key() -> Optional[str]:
    return os.environ.get("RANDOM_ORG_API_KEY")


def get_api_key_interactive(keyfile: Path) -> Optional[str]:
    """
    Best-first order: env var -> keyfile -> prompt (if TTY).
    """
    env_key = getenv_api_key()
    if env_key:
        return env_key.strip()

    if keyfile.exists():
        try:
            return keyfile.read_text(encoding="utf-8").strip()
        except Exception:
            pass

    if sys.stdin.isatty():
        api_key = input("Enter your random.org API key: ").strip()
        try:
            keyfile.write_text(api_key + "\n", encoding="utf-8")
            print(f"API key saved to {keyfile}")
        except Exception as ex:
            eprint(f"Warning: failed to save API key to {keyfile}: {ex}")
        return api_key

    return None


def generate_pad_local(nbytes: int) -> bytes:
    return os.urandom(nbytes)


def rndorg_generate_integers(session: requests.Session, api_key: str, count: int) -> list[int]:
    payload = {
        "jsonrpc": "2.0",
        "method": "generateIntegers",
        "params": {
            "apiKey": api_key,
            "n": count,
            "min": 0,
            "max": 255,
            "replacement": True,
        },
        "id": 1,
    }
    resp = session.post(RNDORG_URL, json=payload, timeout=20)
    if resp.status_code != 200:
        raise RuntimeError(f"random.org HTTP {resp.status_code}: {resp.text[:200]}")
    data = resp.json()
    if "error" in data:
        raise RuntimeError(f"random.org error: {data['error'].get('message')}")
    return data["result"]["random"]["data"]


def generate_pad_randomorg(nbytes: int, api_key: str) -> bytes:
    """
    Chunked JSON-RPC calls to random.org generateIntegers, then pack to bytes.
    """
    out = bytearray(nbytes)
    idx = 0
    with requests.Session() as s:
        while idx < nbytes:
            need = min(RNDORG_MAX_INTS, nbytes - idx)
            ints = rndorg_generate_integers(s, api_key, need)
            if len(ints) != need:
                raise RuntimeError("random.org returned unexpected count")
            out[idx: idx + need] = bytes(ints)
            idx += need
    return bytes(out)


def xor_bytes(a: bytes, b: bytes) -> bytes:
    # Fast path for small buffers
    return bytes(x ^ y for x, y in zip(a, b))


def stream_encrypt(in_path: Path, pad_path: Path, out_path: Path, offset: int, burn: bool, verbose: bool) -> int:
    """
    XOR encrypt (or decrypt) in streaming fashion.
    Returns number of bytes processed; raises on pad shortage.
    """
    # Compute total needed
    try:
        total = in_path.stat().st_size
    except FileNotFoundError:
        raise FileNotFoundError(errno.ENOENT, f"Input file not found: {in_path}")

    pad_size = pad_path.stat().st_size if pad_path.exists() else 0
    if is_text_format(pad_path):
        # If pad is .txt CSV, we must load it to know length
        pad_bytes = load_from_csv_bytes(pad_path)
        pad_len = len(pad_bytes)
        if pad_len - offset < total:
            raise ValueError(f"Pad too short: need {total} bytes, have {max(0, pad_len - offset)} available")
        # Stream input but XOR against slices of cached pad
        with open(in_path, "rb") as fin, open(out_path, "wb") as fout:
            if is_text_format(out_path):
                # Legacy CSV output requires buffering; do it in chunks but collect ints
                written = 0
                first = True
                while True:
                    chunk = fin.read(CHUNK)
                    if not chunk:
                        break
                    pad_chunk = pad_bytes[offset + written: offset + written + len(chunk)]
                    enc = xor_bytes(chunk, pad_chunk)
                    # write as CSV progressively
                    csv = ",".join(str(b) for b in enc)
                    if first:
                        fout.write(csv.encode("utf-8"))
                        first = False
                    else:
                        fout.write(("," + csv).encode("utf-8"))
                    written += len(chunk)
            else:
                # Raw binary output
                written = 0
                while True:
                    chunk = fin.read(CHUNK)
                    if not chunk:
                        break
                    pad_chunk = pad_bytes[offset + written: offset + written + len(chunk)]
                    fout.write(xor_bytes(chunk, pad_chunk))
                    written += len(chunk)

        used = total
        if burn:
            # Remove first offset+used bytes
            remaining = pad_bytes[offset + used:]
            save_bytes_auto(pad_path, remaining)  # keeps CSV format for .txt
            if verbose:
                print(f"Burned {offset + used} bytes from pad {pad_path}")
        return total

    # Binary pad path: stream both files
    with open(in_path, "rb") as fin, open(pad_path, "rb") as fpad:
        # Skip offset in pad
        fpad.seek(offset, os.SEEK_SET)
        # Verify enough pad by checking file size if possible
        file_pad_size = pad_path.stat().st_size
        if file_pad_size - offset < total:
            raise ValueError(f"Pad too short: need {total} bytes, have {max(0, file_pad_size - offset)} available")

        # Prepare output
        if is_text_format(out_path):
            # Legacy CSV out
            out_path.parent.mkdir(parents=True, exist_ok=True)
            with open(out_path, "wb") as fout:
                first = True
                processed = 0
                while True:
                    chunk = fin.read(CHUNK)
                    if not chunk:
                        break
                    pad_chunk = fpad.read(len(chunk))
                    if len(pad_chunk) != len(chunk):
                        raise ValueError("Pad ended unexpectedly while encrypting")
                    enc = xor_bytes(chunk, pad_chunk)
                    csv = ",".join(str(b) for b in enc)
                    if first:
                        fout.write(csv.encode("utf-8"))
                        first = False
                    else:
                        fout.write(("," + csv).encode("utf-8"))
                    processed += len(chunk)
        else:
            with open(out_path, "wb") as fout:
                processed = 0
                while True:
                    chunk = fin.read(CHUNK)
                    if not chunk:
                        break
                    pad_chunk = fpad.read(len(chunk))
                    if len(pad_chunk) != len(chunk):
                        raise ValueError("Pad ended unexpectedly while encrypting")
                    fout.write(xor_bytes(chunk, pad_chunk))
                    processed += len(chunk)

    if burn:
        # Efficiently drop the first (offset + total) bytes from pad file
        cut = offset + total
        tmp = pad_path.with_suffix(pad_path.suffix + ".tmp")
        with open(pad_path, "rb") as fsrc, open(tmp, "wb") as fdst:
            fsrc.seek(cut, os.SEEK_SET)
            while True:
                buf = fsrc.read(CHUNK)
                if not buf:
                    break
                fdst.write(buf)
        os.replace(tmp, pad_path)
        if verbose:
            print(f"Burned {cut} bytes from pad {pad_path}")
    return total


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="otp.py",
        description=(
            "One-Time Pad Encryption Program (streamed & safer).\n\n"
            "This tool can:\n"
            "  • Generate one-time pads using either local CSPRNG (default) or random.org\n"
            "  • Encrypt any file with a pad (XOR operation)\n"
            "  • Decrypt a ciphertext with the same pad\n\n"
            "Pad files and ciphertexts can be stored either as raw binary (.bin) or as CSV of integers (.txt) "
            "for legacy compatibility. If the filename ends in .txt, CSV format is used; otherwise raw bytes."
        ),
        epilog=(
            "Examples:\n"
            "  Generate a 1 MB binary pad with local randomness:\n"
            "    python3 otp.py -p 1048576 --padfile pad.bin -v\n\n"
            "  Generate a 64 KB pad from random.org:\n"
            "    export RANDOM_ORG_API_KEY=your_key_here\n"
            "    python3 otp.py -p 65536 --source randomorg --padfile pad.bin\n\n"
            "  Encrypt with a pad (and burn used bytes so they can't be reused):\n"
            "    python3 otp.py -e --infile secret.pdf --padfile pad.bin --outfile cipher.bin --burn\n\n"
            "  Decrypt back:\n"
            "    python3 otp.py -d --infile cipher.bin --padfile pad.bin --outfile recovered.pdf"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    parser.add_argument(
        "-p", "--pad", type=int,
        help="Generate a one-time pad of the specified size in bytes. "
             "Default randomness source is local os.urandom unless --source randomorg is given."
    )
    parser.add_argument(
        "-e", "--encrypt", action="store_true",
        help="Encrypt infile using padfile (default infile: unencrypted.txt; default outfile: message.txt)."
    )
    parser.add_argument(
        "-d", "--decrypt", action="store_true",
        help="Decrypt infile using padfile (default infile: message.txt; default outfile: decrypted_message.txt)."
    )
    parser.add_argument(
        "--padfile", default="pad.txt",
        help="Path to pad file (default: pad.txt). Extension decides format: .txt = CSV integers, others = binary."
    )
    parser.add_argument(
        "--infile", default=None,
        help="Input file. Default depends on mode: unencrypted.txt for encryption, message.txt for decryption."
    )
    parser.add_argument(
        "--outfile", default=None,
        help="Output file. Default depends on mode: message.txt for encryption, decrypted_message.txt for decryption."
    )
    parser.add_argument(
        "--source", choices=["local", "randomorg"], default="local",
        help="Randomness source when generating pads (default: local CSPRNG)."
    )
    parser.add_argument(
        "--api-key", default=None,
        help="Random.org API key (or set via env RANDOM_ORG_API_KEY). If not provided, "
             "falls back to key.txt file or interactive prompt."
    )
    parser.add_argument(
        "--offset", type=int, default=0,
        help="Byte offset into the pad before starting use (default: 0). Useful for partial pad reuse."
    )
    parser.add_argument(
        "--burn", action="store_true",
        help="After use, remove consumed pad bytes (including any offset) to prevent reuse."
    )
    parser.add_argument(
        "-v", "--verbose", action="store_true",
        help="Verbose output with details of operations performed."
    )

    args = parser.parse_args()

    pad_path = Path(args.padfile)

    try:
        if args.pad:
            nbytes = int(args.pad)
            if nbytes <= 0:
                raise ValueError("Pad size must be positive")
            if args.source == "local":
                pad = generate_pad_local(nbytes)
            else:
                api_key = (args.api_key or getenv_api_key() or get_api_key_interactive(Path("key.txt")))
                if not api_key:
                    raise RuntimeError("Random.org API key not provided (use --api-key or set RANDOM_ORG_API_KEY)")
                pad = generate_pad_randomorg(nbytes, api_key)
            save_bytes_auto(pad_path, pad)
            if args.verbose:
                kind = "CSV" if is_text_format(pad_path) else "binary"
                print(f"One-time pad saved to {pad_path} ({kind}, {len(pad)} bytes)")
            return

        # Determine mode (encrypt/decrypt)
        if args.encrypt:
            in_path = Path(args.infile or "unencrypted.txt")
            out_path = Path(args.outfile or "message.txt")
            processed = stream_encrypt(in_path, pad_path, out_path, offset=args.offset, burn=args.burn,
                                       verbose=args.verbose)
            if args.verbose:
                print(f"Encrypted {processed} bytes -> {out_path}")
            else:
                print(
                    f"Message encrypted and saved to {out_path}{' (CSV integers)' if is_text_format(out_path) else ''}.")
            return

        if args.decrypt:
            in_path = Path(args.infile or "message.txt")
            out_path = Path(args.outfile or "decrypted_message.txt")
            processed = stream_encrypt(in_path, pad_path, out_path, offset=args.offset, burn=args.burn,
                                       verbose=args.verbose)
            if args.verbose:
                print(f"Decrypted {processed} bytes -> {out_path}")
            else:
                print(f"Message decrypted and saved to {out_path}.")
            return

        # No action selected
        eprint("Please specify an option:\n"
               "  -p <size>     Generate pad\n"
               "  -e            Encrypt (uses --infile/--outfile)\n"
               "  -d            Decrypt (uses --infile/--outfile)")
        sys.exit(2)

    except KeyboardInterrupt:
        eprint("\nAborted.")
        sys.exit(130)
    except FileNotFoundError as ex:
        eprint(f"Error: {ex}")
        sys.exit(1)
    except ValueError as ex:
        eprint(f"Error: {ex}")
        sys.exit(1)
    except RuntimeError as ex:
        eprint(f"Error: {ex}")
        sys.exit(1)
    except requests.RequestException as ex:
        eprint(f"Network error: {ex}")
        sys.exit(1)


if __name__ == "__main__":
    main()
