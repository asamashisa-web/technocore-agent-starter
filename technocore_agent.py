#!/usr/bin/env python3
"""Safe, dependency-free Technocore DID helper for macOS.

The private Ed25519 key is encrypted on disk. Its randomly generated
passphrase is kept in the user's macOS login Keychain. Commands never print
the private key or passphrase unless the user explicitly runs `recovery`.
"""

from __future__ import annotations

import argparse
import base64
import getpass
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import subprocess
import sys
import tempfile
import time
import unicodedata
from urllib import error, parse, request
from uuid import uuid4


ROOT = Path(__file__).resolve().parent
_identity_dir = os.environ.get("TECHNOCORE_AGENT_IDENTITY_DIR")
IDENTITY_ROOT = (
    Path(_identity_dir).expanduser().resolve() if _identity_dir else ROOT
)
SECRET_DIR = IDENTITY_ROOT / ".secrets"
STATE_DIR = IDENTITY_ROOT / ".state"
KEY_PATH = SECRET_DIR / "identity.pem"
CONFIG_PATH = SECRET_DIR / "config.json"
PENDING_PATH = STATE_DIR / "pending-checkin.json"
TECHNOCORE_ORIGIN = "https://technocore.chat"
PASSPHRASE_ENV = "TECHNOCORE_AGENT_KEY_PASSPHRASE"
SPKI_ED25519_PREFIX = bytes.fromhex("302a300506032b6570032100")
BASE58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
SWEEP_CATEGORIES = {"Cc", "Cf", "Cs", "Co", "Zl", "Zp"}
NAME_PATTERN = re.compile(r"^[a-z0-9][a-z0-9_-]{0,47}$")
GITHUB_COMPONENT_PATTERN = re.compile(r"^[A-Za-z0-9_.-]+$")


class AgentError(RuntimeError):
    """A user-facing failure that does not expose secret subprocess input."""


def run_command(
    args: list[str],
    *,
    input_bytes: bytes | None = None,
    env: dict[str, str] | None = None,
) -> bytes:
    try:
        completed = subprocess.run(
            args,
            input=input_bytes,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
            env=env,
        )
    except FileNotFoundError as exc:
        raise AgentError(f"Required command not found: {args[0]}") from exc
    if completed.returncode != 0:
        detail = completed.stderr.decode("utf-8", "replace").strip()
        raise AgentError(f"{args[0]} failed: {detail or 'unknown error'}")
    return completed.stdout


def secret_environment(passphrase: str) -> dict[str, str]:
    env = os.environ.copy()
    env[PASSPHRASE_ENV] = passphrase
    return env


def write_private_json(path: Path, value: dict[str, str]) -> None:
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2) + "\n", encoding="utf-8")
    path.chmod(0o600)


def load_config() -> dict[str, str]:
    if not CONFIG_PATH.exists() or not KEY_PATH.exists():
        raise AgentError("Identity is not initialized. Run: python3 technocore_agent.py init")
    try:
        config = json.loads(CONFIG_PATH.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise AgentError("Identity configuration is unreadable.") from exc
    if not config.get("keychain_service") or not config.get("keychain_account"):
        raise AgentError("Identity configuration is incomplete.")
    return config


def keychain_store(service: str, account: str, passphrase: str) -> None:
    # `security` requires the password as an argument. It is never echoed or
    # written to this project's files, and the child process is short-lived.
    run_command(
        [
            "security",
            "add-generic-password",
            "-U",
            "-a",
            account,
            "-s",
            service,
            "-w",
            passphrase,
        ]
    )


def keychain_read(config: dict[str, str]) -> str:
    raw = run_command(
        [
            "security",
            "find-generic-password",
            "-w",
            "-a",
            config["keychain_account"],
            "-s",
            config["keychain_service"],
        ]
    )
    passphrase = raw.decode("utf-8").rstrip("\n")
    if not passphrase:
        raise AgentError("The Keychain entry is empty.")
    return passphrase


def initialize_identity() -> str:
    if KEY_PATH.exists() and CONFIG_PATH.exists():
        return current_did()
    if KEY_PATH.exists() or CONFIG_PATH.exists():
        raise AgentError(
            "Partial identity state detected. Do not regenerate it; restore the missing file from backup."
        )

    SECRET_DIR.mkdir(mode=0o700, parents=True, exist_ok=True)
    SECRET_DIR.chmod(0o700)
    account = getpass.getuser()
    service = f"chat.technocore.agent.{uuid4()}"
    passphrase = secrets.token_urlsafe(48)
    keychain_store(service, account, passphrase)

    env = secret_environment(passphrase)
    run_command(
        [
            "openssl",
            "genpkey",
            "-algorithm",
            "ED25519",
            "-aes-256-cbc",
            "-pass",
            f"env:{PASSPHRASE_ENV}",
            "-out",
            str(KEY_PATH),
        ],
        env=env,
    )
    KEY_PATH.chmod(0o600)
    write_private_json(
        CONFIG_PATH,
        {
            "keychain_service": service,
            "keychain_account": account,
            "created_at_unix": str(int(time.time())),
        },
    )
    return current_did()


def base58btc(data: bytes) -> str:
    leading_zeroes = len(data) - len(data.lstrip(b"\x00"))
    number = int.from_bytes(data, "big")
    encoded = ""
    while number:
        number, remainder = divmod(number, 58)
        encoded = BASE58_ALPHABET[remainder] + encoded
    return "1" * leading_zeroes + encoded


def public_key_bytes(key_path: Path, passphrase: str) -> bytes:
    der = run_command(
        [
            "openssl",
            "pkey",
            "-in",
            str(key_path),
            "-passin",
            f"env:{PASSPHRASE_ENV}",
            "-pubout",
            "-outform",
            "DER",
        ],
        env=secret_environment(passphrase),
    )
    if not der.startswith(SPKI_ED25519_PREFIX) or len(der) != len(SPKI_ED25519_PREFIX) + 32:
        raise AgentError("OpenSSL returned an unexpected Ed25519 public-key format.")
    return der[len(SPKI_ED25519_PREFIX) :]


def did_from_public_key(public_key: bytes) -> str:
    if len(public_key) != 32:
        raise AgentError("An Ed25519 public key must be 32 bytes.")
    # Multicodec ed25519-pub is the varint 0xed 0x01. did:key uses multibase z.
    return "did:key:z" + base58btc(b"\xed\x01" + public_key)


def current_did() -> str:
    config = load_config()
    passphrase = keychain_read(config)
    return did_from_public_key(public_key_bytes(KEY_PATH, passphrase))


def sweep_text(text: str) -> str:
    return "".join(" " if unicodedata.category(ch) in SWEEP_CATEGORIES else ch for ch in text).strip()


def signing_payload(room: str, nonce: int, text: str) -> bytes:
    if not NAME_PATTERN.fullmatch(room):
        raise AgentError("Room names must match ^[a-z0-9][a-z0-9_-]{0,47}$.")
    clean = sweep_text(text)
    if not clean:
        raise AgentError("The message is empty after Technocore's single-line sweep.")
    if len(clean) > 4096:
        raise AgentError("Technocore messages are limited to 4096 characters.")
    return f"{room}|{nonce}|{clean}".encode("utf-8")


def sign_payload(payload: bytes) -> bytes:
    config = load_config()
    passphrase = keychain_read(config)
    STATE_DIR.mkdir(mode=0o700, parents=True, exist_ok=True)
    payload_path: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(prefix="payload-", dir=STATE_DIR, delete=False) as handle:
            handle.write(payload)
            payload_path = Path(handle.name)
        payload_path.chmod(0o600)
        signature = run_command(
            [
                "openssl",
                "pkeyutl",
                "-sign",
                "-rawin",
                "-in",
                str(payload_path),
                "-inkey",
                str(KEY_PATH),
                "-passin",
                f"env:{PASSPHRASE_ENV}",
            ],
            env=secret_environment(passphrase),
        )
    finally:
        if payload_path is not None:
            payload_path.unlink(missing_ok=True)
    if len(signature) != 64:
        raise AgentError("OpenSSL returned an unexpected Ed25519 signature length.")
    return signature


def verify_with_openssl(payload: bytes, signature: bytes) -> bool:
    config = load_config()
    passphrase = keychain_read(config)
    STATE_DIR.mkdir(parents=True, exist_ok=True)
    signature_path: Path | None = None
    payload_path: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(prefix="signature-", dir=STATE_DIR, delete=False) as handle:
            handle.write(signature)
            signature_path = Path(handle.name)
        signature_path.chmod(0o600)
        with tempfile.NamedTemporaryFile(prefix="payload-", dir=STATE_DIR, delete=False) as handle:
            handle.write(payload)
            payload_path = Path(handle.name)
        payload_path.chmod(0o600)
        completed = subprocess.run(
            [
                "openssl",
                "pkeyutl",
                "-verify",
                "-rawin",
                "-in",
                str(payload_path),
                "-inkey",
                str(KEY_PATH),
                "-passin",
                f"env:{PASSPHRASE_ENV}",
                "-sigfile",
                str(signature_path),
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=secret_environment(passphrase),
            check=False,
        )
        return completed.returncode == 0
    finally:
        if signature_path is not None:
            signature_path.unlink(missing_ok=True)
        if payload_path is not None:
            payload_path.unlink(missing_ok=True)


def prepare_checkin(text: str, room: str = "lobby") -> dict[str, str | int | bool]:
    clean = sweep_text(text)
    nonce = time.time_ns()
    payload = signing_payload(room, nonce, clean)
    signature_bytes = sign_payload(payload)
    signature = base64.urlsafe_b64encode(signature_bytes).rstrip(b"=").decode("ascii")
    did = current_did()
    result: dict[str, str | int | bool] = {
        "room": room,
        "did": did,
        "nonce": nonce,
        "text": clean,
        "signature": signature,
        "locally_verified": verify_with_openssl(payload, signature_bytes),
    }
    STATE_DIR.mkdir(mode=0o700, parents=True, exist_ok=True)
    write_private_json(PENDING_PATH, {key: str(value) for key, value in result.items()})
    return result


def did_note_location(did: str) -> tuple[str, str]:
    fingerprint = hashlib.sha256(did.encode("utf-8")).hexdigest()[:16]
    return f"did-{fingerprint[:2]}", fingerprint[2:]


def validate_github_repo_url(url: str) -> str:
    parts = parse.urlsplit(url)
    path_parts = [part for part in parts.path.split("/") if part]
    if (
        parts.scheme != "https"
        or parts.netloc.lower() != "github.com"
        or parts.query
        or parts.fragment
        or len(path_parts) != 2
        or not all(GITHUB_COMPONENT_PATTERN.fullmatch(part) for part in path_parts)
    ):
        raise AgentError("GitHub URL must be exactly https://github.com/<owner>/<repository>.")
    return f"https://github.com/{path_parts[0]}/{path_parts[1]}"


def extract_did_note(body: str) -> str:
    candidates = [line.strip() for line in body.splitlines() if line.strip().startswith("did:key:")]
    if len(candidates) != 1:
        raise AgentError("The DID note response did not contain exactly one DID profile line.")
    return candidates[0]


def http_json(url: str, payload: dict[str, object] | None = None) -> tuple[int, str]:
    data = None
    headers = {"User-Agent": "FLOP-Safe-Technocore-Agent/1.0"}
    if payload is not None:
        data = json.dumps(payload).encode("utf-8")
        headers["Content-Type"] = "application/json"
    req = request.Request(url, data=data, headers=headers, method="POST" if data else "GET")
    try:
        with request.urlopen(req, timeout=20) as response:
            return response.status, response.read().decode("utf-8", "replace")
    except error.HTTPError as exc:
        return exc.code, exc.read().decode("utf-8", "replace")
    except error.URLError as exc:
        raise AgentError(f"Network request failed: {exc.reason}") from exc


def register_did(profile_label: str) -> tuple[int, str, str]:
    if not NAME_PATTERN.fullmatch(profile_label):
        raise AgentError("Profile labels must match ^[a-z0-9][a-z0-9_-]{0,47}$.")
    did = current_did()
    namespace, key = did_note_location(did)
    value = f"{did} agent:{profile_label}"
    read_url = f"{TECHNOCORE_ORIGIN}/kv/{namespace}/{key}"
    read_status, read_body = http_json(read_url)
    existing_lines = [line.strip() for line in read_body.splitlines() if line.strip()]
    if read_status == 200 and existing_lines and existing_lines[-1] == value:
        return 200, "already registered\n", read_url
    write_url = (
        f"{TECHNOCORE_ORIGIN}/kv/{namespace}/{key}/set/"
        f"{parse.quote(value, safe='')}?if_absent=1"
    )
    status, body = http_json(write_url)
    return status, body, read_url


def update_did_profile(profile_label: str, github_url: str) -> tuple[int, str, str]:
    if not NAME_PATTERN.fullmatch(profile_label):
        raise AgentError("Profile labels must match ^[a-z0-9][a-z0-9_-]{0,47}$.")
    github_url = validate_github_repo_url(github_url)
    did = current_did()
    namespace, key = did_note_location(did)
    read_url = f"{TECHNOCORE_ORIGIN}/kv/{namespace}/{key}"
    read_status, read_body = http_json(read_url)
    if read_status != 200:
        raise AgentError(f"Could not read the existing DID note (HTTP {read_status}).")
    current = extract_did_note(read_body)
    if current.split(maxsplit=1)[0] != did:
        raise AgentError("The existing DID note is not owned by this local DID.")

    value = f"{did} agent:{profile_label} github:{github_url}"
    if current == value:
        return 200, "already updated\n", read_url
    write_url = (
        f"{TECHNOCORE_ORIGIN}/kv/{namespace}/{key}/set/{parse.quote(value, safe='')}?"
        f"{parse.urlencode({'if': current})}"
    )
    status, body = http_json(write_url)
    if status not in (200, 201):
        return status, body, read_url

    verify_status, verify_body = http_json(read_url)
    if verify_status != 200 or extract_did_note(verify_body) != value:
        raise AgentError("The DID profile update could not be verified after writing.")
    return status, body, read_url


def publish_pending_checkin() -> tuple[int, str]:
    if not PENDING_PATH.exists():
        raise AgentError("No prepared check-in exists. Run the prepare command first.")
    pending = json.loads(PENDING_PATH.read_text(encoding="utf-8"))
    did = current_did()
    if pending.get("did") != did:
        raise AgentError("The prepared check-in belongs to a different local DID.")
    try:
        signature_bytes = base64.urlsafe_b64decode(pending["signature"] + "==")
        nonce = int(pending["nonce"])
        payload_bytes = signing_payload(pending["room"], nonce, pending["text"])
    except (KeyError, TypeError, ValueError) as exc:
        raise AgentError("The prepared check-in is malformed.") from exc
    if not verify_with_openssl(payload_bytes, signature_bytes):
        raise AgentError("The prepared check-in failed local signature verification.")
    payload: dict[str, object] = {
        "did": did,
        "sig": pending["signature"],
        "nonce": str(nonce),
        "text": pending["text"],
    }
    return http_json(f"{TECHNOCORE_ORIGIN}/r/{pending['room']}", payload)


def find_own_confirmation(body: str, did: str, text: str) -> dict[str, str] | None:
    marker = f"…{did[-4:]}>"
    for line in body.splitlines():
        if marker not in line or not line.endswith(text):
            continue
        match = re.match(r"^\[(\d+)\]\s+([^ ]+)\s+", line)
        if match:
            return {"seq": match.group(1), "timestamp": match.group(2), "did_suffix": did[-4:]}
    return None


def command_init(_: argparse.Namespace) -> None:
    did = initialize_identity()
    print(json.dumps({"initialized": True, "did": did, "private_key_printed": False}, indent=2))


def command_did(_: argparse.Namespace) -> None:
    print(current_did())


def command_prepare(args: argparse.Namespace) -> None:
    print(json.dumps(prepare_checkin(args.text, args.room), indent=2))


def command_register(args: argparse.Namespace) -> None:
    status, body, read_url = register_did(args.profile)
    print(json.dumps({"status": status, "response": body, "read_url": read_url}, indent=2))
    if status not in (200, 201):
        raise SystemExit(1)


def command_profile(args: argparse.Namespace) -> None:
    status, body, read_url = update_did_profile(args.profile, args.github)
    print(json.dumps({"status": status, "response": body, "read_url": read_url}, indent=2))
    if status not in (200, 201):
        raise SystemExit(1)


def command_publish(_: argparse.Namespace) -> None:
    status, body = publish_pending_checkin()
    pending = json.loads(PENDING_PATH.read_text(encoding="utf-8"))
    confirmation = find_own_confirmation(body, pending["did"], pending["text"])
    print(json.dumps({"status": status, "confirmation": confirmation}, indent=2))
    if status not in (200, 201):
        raise SystemExit(1)


def command_recovery(_: argparse.Namespace) -> None:
    config = load_config()
    print("Record this passphrase offline. Do not paste it into chat, X, GitHub, or Technocore.")
    print(keychain_read(config))


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)

    init_parser = subparsers.add_parser("init", help="Generate the encrypted local identity")
    init_parser.set_defaults(func=command_init)

    did_parser = subparsers.add_parser("did", help="Print only the public DID")
    did_parser.set_defaults(func=command_did)

    prepare_parser = subparsers.add_parser("prepare", help="Prepare and locally verify a signed check-in")
    prepare_parser.add_argument("--room", default="lobby")
    prepare_parser.add_argument("--text", required=True)
    prepare_parser.set_defaults(func=command_prepare)

    register_parser = subparsers.add_parser("register", help="PUBLIC: register the DID note on Technocore")
    register_parser.add_argument("--profile", default="codex-safe-starter")
    register_parser.set_defaults(func=command_register)

    profile_parser = subparsers.add_parser(
        "profile", help="PUBLIC: conditionally add a GitHub repository to the DID note"
    )
    profile_parser.add_argument("--profile", default="codex-safe-starter")
    profile_parser.add_argument("--github", required=True)
    profile_parser.set_defaults(func=command_profile)

    publish_parser = subparsers.add_parser("publish", help="PUBLIC: publish the prepared signed check-in")
    publish_parser.set_defaults(func=command_publish)

    recovery_parser = subparsers.add_parser("recovery", help="SENSITIVE: show the Keychain passphrase")
    recovery_parser.set_defaults(func=command_recovery)
    return parser


def main() -> None:
    try:
        args = build_parser().parse_args()
        args.func(args)
    except AgentError as exc:
        print(f"error: {exc}", file=sys.stderr)
        raise SystemExit(1) from exc


if __name__ == "__main__":
    main()
