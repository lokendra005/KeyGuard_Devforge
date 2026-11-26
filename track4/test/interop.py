"""Independent judge-format ML-KEM oracle. Requires the judge's pqcrypto==0.4.0."""
import base64
import hashlib
import hmac
import json
import os
from pathlib import Path
import secrets
import subprocess
import tempfile

from pqcrypto.kem import ml_kem_768

ROOT = Path(__file__).resolve().parents[2]
with tempfile.TemporaryDirectory(prefix="kig-interop-") as directory:
    env = {**os.environ, "TRACK4_STATE_DIR": directory}
    secret_marker = secrets.token_hex(32)

    def call(request, allow_error=False):
        p = subprocess.run([os.environ.get("NODE", "node"), str(ROOT / "track4_service.cjs")], input=json.dumps(request), text=True, capture_output=True, env=env, timeout=8)
        assert secret_marker not in p.stdout and secret_marker not in p.stderr
        if not allow_error:
            assert p.returncode == 0, p.stdout
        return json.loads(p.stdout)

    actor = "身份/\x00" + secrets.token_hex(16)
    asset = "__proto__\x00/" + secrets.token_hex(16)
    body = "\nsecret🙂\x00" + secrets.token_hex(32)
    assert call({"op": "setup", "owners": {asset: actor}, "contents": {asset: body}, "disabled": [], "key_material": secret_marker})["ready"]
    for i in range(16):
        public_key, private_key = ml_kem_768.generate_keypair()
        challenge = secrets.token_hex(24) + "\x00挑战"
        request = {"op": "protected_read", "actor": actor, "asset": asset, "challenge": challenge, "public_key": base64.b64encode(public_key).decode()}
        result = call(request)
        ciphertext = base64.b64decode(result["ciphertext"], validate=True)
        assert len(ciphertext) == 1088
        shared = ml_kem_768.decrypt(private_key, ciphertext)
        expected = hmac.new(shared, (challenge + body).encode(), hashlib.sha256).hexdigest()
        assert hmac.compare_digest(expected, result["proof"])
        assert result["proof"] != hmac.new(shared, (challenge + "changed").encode(), hashlib.sha256).hexdigest()
        wrong_public, wrong_private = ml_kem_768.generate_keypair()
        assert ml_kem_768.decrypt(wrong_private, ciphertext) != shared
        assert call(request, allow_error=True)["error"] == "REPLAY"
    call({"op": "revoke", "actor": actor})
    assert call(request) == {"decision": "deny"}
print("PASS: 16 independently generated pqcrypto ML-KEM-768 keys; decapsulation/HMAC interoperability, wrong-key/content, replay and post-revocation denial.")
