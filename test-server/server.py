#!/usr/bin/env python3
"""
Test AES API server — simulates a backend that sends/receives
AES-CBC encrypted, Base64-encoded JSON bodies.

Key : 0123456789abcdef0123456789abcdef (hex)
IV  : abcdef0123456789abcdef0123456789 (hex)
Mode: AES/CBC/PKCS7 (identical to PKCS5 for 16-byte blocks)
"""

import base64
import json

from flask import Flask, request, Response
from Cryptodome.Cipher import AES
from Cryptodome.Util.Padding import pad, unpad

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------
KEY = bytes.fromhex("0123456789abcdef0123456789abcdef")
IV  = bytes.fromhex("abcdef0123456789abcdef0123456789")
PORT = 8888

app = Flask(__name__)


# ---------------------------------------------------------------------------
# Crypto helpers
# ---------------------------------------------------------------------------
def encrypt(data: dict) -> str:
    """Serialize dict → JSON bytes, AES-CBC encrypt, Base64-encode."""
    plaintext = json.dumps(data).encode()
    cipher = AES.new(KEY, AES.MODE_CBC, IV)
    ct = cipher.encrypt(pad(plaintext, AES.block_size))
    return base64.b64encode(ct).decode()


def decrypt(b64_body: str) -> dict:
    """Base64-decode, AES-CBC decrypt, parse JSON → dict."""
    ct = base64.b64decode(b64_body.strip())
    cipher = AES.new(KEY, AES.MODE_CBC, IV)
    plaintext = unpad(cipher.decrypt(ct), AES.block_size)
    return json.loads(plaintext.decode())


def encrypted_response(data: dict, status: int = 200) -> Response:
    body = encrypt(data)
    print(f"  [RESPONSE {status}] plaintext : {json.dumps(data)}")
    print(f"  [RESPONSE {status}] encrypted : {body}\n")
    return Response(body, status=status, mimetype="text/plain")


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------
@app.route("/api/health", methods=["GET"])
def health():
    print("[GET] /api/health")
    return Response("OK", status=200, mimetype="text/plain")


@app.route("/api/login", methods=["POST"])
def login():
    print("[POST] /api/login")
    raw = request.get_data(as_text=True).strip()
    print(f"  [REQUEST]  encrypted : {raw}")

    try:
        payload = decrypt(raw)
    except Exception as e:
        print(f"  [ERROR] decryption failed: {e}\n")
        return encrypted_response({"status": "error", "message": "Decryption failed"}, 400)

    print(f"  [REQUEST]  plaintext : {json.dumps(payload)}")

    username = payload.get("username", "")
    password = payload.get("password", "")

    if username == "admin" and password == "secret123":
        resp = {"status": "success", "role": "admin", "token": "abc123"}
    else:
        resp = {"status": "fail", "message": "Invalid credentials"}

    return encrypted_response(resp)


@app.route("/api/profile", methods=["POST"])
def profile():
    print("[POST] /api/profile")
    raw = request.get_data(as_text=True).strip()
    print(f"  [REQUEST]  encrypted : {raw}")

    try:
        payload = decrypt(raw)
    except Exception as e:
        print(f"  [ERROR] decryption failed: {e}\n")
        return encrypted_response({"status": "error", "message": "Decryption failed"}, 400)

    print(f"  [REQUEST]  plaintext : {json.dumps(payload)}")

    user_id = payload.get("user_id", "")
    resp = {
        "name": "John Doe",
        "email": "john@example.com",
        "user_id": user_id,   # reflected — injection point for scanner testing
    }

    return encrypted_response(resp)


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    print(f"AES test server starting on http://0.0.0.0:{PORT}")
    print(f"  Key : 0123456789abcdef0123456789abcdef")
    print(f"  IV  : abcdef0123456789abcdef0123456789\n")
    app.run(host="0.0.0.0", port=PORT, debug=False)
