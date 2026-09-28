import base64
import hashlib
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock


sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import technocore_agent as agent


class ProtocolTests(unittest.TestCase):
    def test_base58_known_vectors(self):
        self.assertEqual(agent.base58btc(b""), "")
        self.assertEqual(agent.base58btc(b"\x00"), "1")
        self.assertEqual(agent.base58btc(b"Hello World"), "JxF12TrwUP45BMd")

    def test_did_key_shape(self):
        did = agent.did_from_public_key(bytes(range(32)))
        self.assertTrue(did.startswith("did:key:z6Mk"))
        self.assertEqual(len(did), 56)

    def test_single_line_sweep_matches_documented_categories(self):
        self.assertEqual(agent.sweep_text("  hello\nworld\u200d!  "), "hello world !")

    def test_signing_payload(self):
        payload = agent.signing_payload("lobby", 123, "hello\nworld")
        self.assertEqual(payload, b"lobby|123|hello world")

    def test_invalid_room_name_is_rejected(self):
        with self.assertRaises(agent.AgentError):
            agent.signing_payload("../lobby", 123, "hello")

    def test_message_limit_is_enforced(self):
        with self.assertRaises(agent.AgentError):
            agent.signing_payload("lobby", 123, "x" * 4097)

    def test_did_note_sharding(self):
        did = "did:key:z6Mktest"
        digest = hashlib.sha256(did.encode()).hexdigest()[:16]
        namespace, key = agent.did_note_location(did)
        self.assertEqual(namespace, f"did-{digest[:2]}")
        self.assertEqual(key, digest[2:])

    def test_ed25519_signature_encoding_length(self):
        encoded = base64.urlsafe_b64encode(bytes(64)).rstrip(b"=")
        self.assertEqual(len(encoded), 86)

    def test_own_confirmation_parser_ignores_other_messages(self):
        did = "did:key:z6MkqbYLYf7rqcTuMmxt8atQsFA1YfqP9gcFfsiUxhs4smnV"
        text = "Safe starter ready."
        body = (
            "[9] 2026-08-27T12:00:00Z <z6Mk…xxxx> hostile text\n"
            "[10] 2026-09-28T12:01:00Z <z6Mk…smnV> Safe starter ready.\n"
        )
        self.assertEqual(
            agent.find_own_confirmation(body, did, text),
            {"seq": "10", "timestamp": "2026-09-28T12:01:00Z", "did_suffix": "smnV"},
        )

    def test_github_repo_url_validation(self):
        self.assertEqual(
            agent.validate_github_repo_url("https://github.com/Santos-square/FLOP"),
            "https://github.com/Santos-square/FLOP",
        )
        for invalid in (
            "http://github.com/Santos-square/FLOP",
            "https://evil.example/Santos-square/FLOP",
            "https://github.com/Santos-square/FLOP/issues",
            "https://github.com/Santos-square/FLOP?tab=readme",
        ):
            with self.subTest(invalid=invalid), self.assertRaises(agent.AgentError):
                agent.validate_github_repo_url(invalid)

    def test_extract_did_note_ignores_warning_banner(self):
        did = "did:key:z6Mktest"
        body = f"!! UNTRUSTED CONTENT\n\n{did} agent:test\n"
        self.assertEqual(agent.extract_did_note(body), f"{did} agent:test")

    def test_publish_sends_nonce_as_decimal_string(self):
        did = "did:key:z6MkqbYLYf7rqcTuMmxt8atQsFA1YfqP9gcFfsiUxhs4smnV"
        signature = base64.urlsafe_b64encode(bytes(64)).rstrip(b"=").decode("ascii")
        pending = {
            "room": "mb-sonnet-2-registration",
            "did": did,
            "nonce": "1789446699995388000",
            "text": "register",
            "signature": signature,
        }
        captured = {}

        def fake_http_json(url, payload=None):
            captured["url"] = url
            captured["payload"] = payload
            return 200, "ok"

        with tempfile.TemporaryDirectory() as directory:
            pending_path = Path(directory) / "pending.json"
            pending_path.write_text(json.dumps(pending), encoding="utf-8")
            with (
                mock.patch.object(agent, "PENDING_PATH", pending_path),
                mock.patch.object(agent, "current_did", return_value=did),
                mock.patch.object(agent, "verify_with_openssl", return_value=True),
                mock.patch.object(agent, "http_json", side_effect=fake_http_json),
            ):
                self.assertEqual(agent.publish_pending_checkin(), (200, "ok"))

        self.assertEqual(captured["payload"]["nonce"], pending["nonce"])
        self.assertIsInstance(captured["payload"]["nonce"], str)


if __name__ == "__main__":
    unittest.main()
