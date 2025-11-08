# Copyright (c) 2025 Artoo Corporation
# Licensed under the Business Source License 1.1 (see LICENSE).
# Change Date: 2029-09-08  •  Change License: LGPL-3.0-or-later

"""d2._crypto – helper for automatic Ed25519 key bootstrap used by `d2 publish`.

This module is *SDK-internal*; it generates a persistent Ed25519 keypair
(~/.config/d2/keys/id_ed25519) on first use and registers the public key with
D2 Cloud via the `/v1/keys` endpoint. Subsequent calls reuse the cached key.
"""

from __future__ import annotations

from pathlib import Path
from hashlib import blake2s
import base64
import logging
import os
from typing import Tuple, Optional

import httpx
import nacl.signing
import nacl.encoding

logger = logging.getLogger(__name__)

CFG_DIR = Path.home() / ".config" / "d2"
KEY_DIR = CFG_DIR / "keys"
PRIV_PATH = KEY_DIR / "id_ed25519"
PUB_PATH = KEY_DIR / "id_ed25519.pub"


def _write_keypair(sign_key: nacl.signing.SigningKey) -> None:
    """Persist keypair with secure permissions (600 / 644)."""
    KEY_DIR.mkdir(parents=True, exist_ok=True, mode=0o700)

    # Private key (seed, 32 bytes)
    PRIV_PATH.write_bytes(sign_key.encode(encoder=nacl.encoding.RawEncoder))
    os.chmod(PRIV_PATH, 0o600)

    # Public key (32 bytes, raw)
    PUB_PATH.write_bytes(sign_key.verify_key.encode(encoder=nacl.encoding.RawEncoder))
    os.chmod(PUB_PATH, 0o644)


def _load_private_key() -> Optional[nacl.signing.SigningKey]:
    if PRIV_PATH.exists():
        raw = PRIV_PATH.read_bytes()
        if len(raw) == 32:
            return nacl.signing.SigningKey(raw, encoder=nacl.encoding.RawEncoder)
    return None


def _derive_key_id(pub_bytes: bytes) -> str:
    """Return deterministic short ID: 'ed_'+6-byte Blake2s hex."""
    digest = blake2s(pub_bytes, digest_size=6).hexdigest()
    return f"ed_{digest}"


async def get_or_create_key(api_client: httpx.AsyncClient) -> Tuple[Path, str]:
    """Ensure Ed25519 keypair exists locally *and* public key is registered.

    Parameters
    ----------
    api_client : httpx.AsyncClient
        Authenticated (bearer) client pointing at the D2 Cloud root URL.

    Returns
    -------
    (Path, str)
        Tuple of private-key file path and deterministic key_id string.
    """

    # 1. Load or create keypair
    signing_key = _load_private_key()
    newly_generated = False
    if signing_key is None:
        signing_key = nacl.signing.SigningKey.generate()
        _write_keypair(signing_key)
        newly_generated = True
        logger.info("Auto-generated signing keypair at %s", PRIV_PATH)

    pub_bytes = signing_key.verify_key.encode(encoder=nacl.encoding.RawEncoder)
    key_id = _derive_key_id(pub_bytes)

    # 2. Ensure the public key is registered exactly once per process.
    #    We want to self-heal if the server lost the key row or if the key was
    #    generated in a previous run on this machine but never uploaded.
    if not getattr(get_or_create_key, "_verified_once", False):
        payload = {
            "key_id": key_id,
            "public_key": base64.b64encode(pub_bytes).decode(),
        }
        try:
            resp = await api_client.post("/v1/keys", json=payload, timeout=5.0)
            if resp.status_code in (200, 201):
                logger.debug("Registered public key %s", key_id)
            elif resp.status_code == 409:
                # Duplicate – key already present for this account.
                logger.info("Ed25519 key %s already registered – continuing.", key_id)
            else:
                logger.warning(
                    "Key registration check for %s failed (status %s): %s",
                    key_id,
                    resp.status_code,
                    resp.text,
                )
        except Exception as exc:  # pragma: no cover – network failure path
            logger.warning("Key registration check failed: %s", exc)
        # Avoid hitting the endpoint again in the same process.
        setattr(get_or_create_key, "_verified_once", True)

    return PRIV_PATH, key_id 