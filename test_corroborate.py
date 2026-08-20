import unittest
import json
from app import app
from corroborate import evaluate_corroboration

class TestCorroborate(unittest.TestCase):

    def test_example_supported_medium(self):
        # Two fresh independent sources with same type (dns)
        payload = {
            "claim": {"subject": "on8q58.example", "predicate": "resolves_to", "value": "203.0.113.20"},
            "asOf": "2026-08-01T00:00:00Z",
            "stalenessDays": 90,
            "sources": [
                {"id": "s1", "type": "dns", "origin": "resolver-a",
                 "observedAt": "2026-07-30T00:00:00Z", "value": "203.0.113.20", "authoritative": False},
                {"id": "s2", "type": "dns", "origin": "resolver-b",
                 "observedAt": "2026-07-28T00:00:00Z", "value": "203.0.113.20", "authoritative": False}
            ]
        }
        res = evaluate_corroboration(payload)
        self.assertEqual(res, {
            "verdict": "supported",
            "confidence": "medium",
            "corroboratingSources": ["s1", "s2"]
        })

    def test_example_supported_high(self):
        # Two fresh independent sources with different types (dns, ct_log)
        payload = {
            "claim": {"subject": "on8q58.example", "predicate": "resolves_to", "value": "203.0.113.20"},
            "asOf": "2026-08-01T00:00:00Z",
            "stalenessDays": 90,
            "sources": [
                {"id": "s1", "type": "dns", "origin": "resolver-a",
                 "observedAt": "2026-07-30T00:00:00Z", "value": "203.0.113.20", "authoritative": False},
                {"id": "s2", "type": "ct_log", "origin": "ct-monitor",
                 "observedAt": "2026-07-28T00:00:00Z", "value": "203.0.113.20", "authoritative": False}
            ]
        }
        res = evaluate_corroboration(payload)
        self.assertEqual(res, {
            "verdict": "supported",
            "confidence": "high",
            "corroboratingSources": ["s1", "s2"]
        })

    def test_mirrors_same_origin_lexicographical_id(self):
        # Three sources, two from origin-a (s3, s1), one from origin-b (s2)
        payload = {
            "claim": {"subject": "on8q58.example", "predicate": "resolves_to", "value": "203.0.113.20"},
            "asOf": "2026-08-01T00:00:00Z",
            "stalenessDays": 90,
            "sources": [
                {"id": "s3", "type": "dns", "origin": "resolver-a",
                 "observedAt": "2026-07-30T00:00:00Z", "value": "203.0.113.20", "authoritative": False},
                {"id": "s1", "type": "dns", "origin": "resolver-a",
                 "observedAt": "2026-07-29T00:00:00Z", "value": "203.0.113.20", "authoritative": False},
                {"id": "s2", "type": "dns", "origin": "resolver-b",
                 "observedAt": "2026-07-28T00:00:00Z", "value": "203.0.113.20", "authoritative": False}
            ]
        }
        res = evaluate_corroboration(payload)
        self.assertEqual(res, {
            "verdict": "supported",
            "confidence": "medium",
            "corroboratingSources": ["s1", "s2"]
        })

    def test_contradicted_fresh_authoritative(self):
        payload = {
            "claim": {"subject": "on8q58.example", "predicate": "resolves_to", "value": "203.0.113.20"},
            "asOf": "2026-08-01T00:00:00Z",
            "stalenessDays": 90,
            "sources": [
                {"id": "s1", "type": "dns", "origin": "auth-ns",
                 "observedAt": "2026-07-30T00:00:00Z", "value": "198.51.100.1", "authoritative": True},
                {"id": "s2", "type": "dns", "origin": "resolver-b",
                 "observedAt": "2026-07-28T00:00:00Z", "value": "203.0.113.20", "authoritative": False}
            ]
        }
        res = evaluate_corroboration(payload)
        self.assertEqual(res, {
            "verdict": "contradicted",
            "confidence": "low",
            "corroboratingSources": ["s1"]
        })

    def test_stale_authoritative_does_not_contradict(self):
        payload = {
            "claim": {"subject": "on8q58.example", "predicate": "resolves_to", "value": "203.0.113.20"},
            "asOf": "2026-08-01T00:00:00Z",
            "stalenessDays": 30,
            "sources": [
                {"id": "s1", "type": "dns", "origin": "auth-ns",
                 "observedAt": "2026-05-01T00:00:00Z", "value": "198.51.100.1", "authoritative": True},
                {"id": "s2", "type": "dns", "origin": "resolver-a",
                 "observedAt": "2026-07-28T00:00:00Z", "value": "203.0.113.20", "authoritative": False},
                {"id": "s3", "type": "registry", "origin": "whois-b",
                 "observedAt": "2026-07-20T00:00:00Z", "value": "203.0.113.20", "authoritative": False}
            ]
        }
        res = evaluate_corroboration(payload)
        self.assertEqual(res, {
            "verdict": "supported",
            "confidence": "high",
            "corroboratingSources": ["s2", "s3"]
        })

    def test_non_authoritative_disagreement_ignored(self):
        payload = {
            "claim": {"subject": "on8q58.example", "predicate": "resolves_to", "value": "203.0.113.20"},
            "asOf": "2026-08-01T00:00:00Z",
            "stalenessDays": 90,
            "sources": [
                {"id": "s1", "type": "dns", "origin": "resolver-bad",
                 "observedAt": "2026-07-30T00:00:00Z", "value": "198.51.100.1", "authoritative": False},
                {"id": "s2", "type": "dns", "origin": "resolver-a",
                 "observedAt": "2026-07-28T00:00:00Z", "value": "203.0.113.20", "authoritative": False},
                {"id": "s3", "type": "scan", "origin": "scanner-b",
                 "observedAt": "2026-07-20T00:00:00Z", "value": "203.0.113.20", "authoritative": False}
            ]
        }
        res = evaluate_corroboration(payload)
        self.assertEqual(res, {
            "verdict": "supported",
            "confidence": "high",
            "corroboratingSources": ["s2", "s3"]
        })

    def test_unverified_single_source(self):
        payload = {
            "claim": {"subject": "on8q58.example", "predicate": "resolves_to", "value": "203.0.113.20"},
            "asOf": "2026-08-01T00:00:00Z",
            "stalenessDays": 90,
            "sources": [
                {"id": "s1", "type": "dns", "origin": "resolver-a",
                 "observedAt": "2026-07-30T00:00:00Z", "value": "203.0.113.20", "authoritative": False}
            ]
        }
        res = evaluate_corroboration(payload)
        self.assertEqual(res, {
            "verdict": "unverified",
            "confidence": "low",
            "corroboratingSources": []
        })

    def test_unverified_mirrors_only(self):
        payload = {
            "claim": {"subject": "on8q58.example", "predicate": "resolves_to", "value": "203.0.113.20"},
            "asOf": "2026-08-01T00:00:00Z",
            "stalenessDays": 90,
            "sources": [
                {"id": "s1", "type": "dns", "origin": "resolver-a",
                 "observedAt": "2026-07-30T00:00:00Z", "value": "203.0.113.20", "authoritative": False},
                {"id": "s2", "type": "dns", "origin": "resolver-a",
                 "observedAt": "2026-07-29T00:00:00Z", "value": "203.0.113.20", "authoritative": False}
            ]
        }
        res = evaluate_corroboration(payload)
        self.assertEqual(res, {
            "verdict": "unverified",
            "confidence": "low",
            "corroboratingSources": []
        })

    def test_invalid_schema(self):
        self.assertEqual(evaluate_corroboration("invalid")["verdict"], "invalid")
        self.assertEqual(evaluate_corroboration({"claim": {}, "asOf": "2026-08-01T00:00:00Z", "stalenessDays": 30, "sources": []})["verdict"], "invalid")
        self.assertEqual(evaluate_corroboration({"claim": {"value": "x"}, "asOf": "not-a-date", "stalenessDays": 30, "sources": []})["verdict"], "invalid")
        self.assertEqual(evaluate_corroboration({"claim": {"value": "x"}, "asOf": "2026-08-01T00:00:00Z", "stalenessDays": "30", "sources": []})["verdict"], "invalid")
        self.assertEqual(evaluate_corroboration({"claim": {"value": "x"}, "asOf": "2026-08-01T00:00:00Z", "stalenessDays": 30, "sources": "bad"})["verdict"], "invalid")

    def test_flask_corroborate_endpoint(self):
        client = app.test_client()

        # GET /corroborate
        resp_get = client.get("/corroborate")
        self.assertEqual(resp_get.status_code, 200)
        self.assertTrue(resp_get.is_json)

        # POST /corroborate
        payload = {
            "claim": {"subject": "on8q58.example", "predicate": "resolves_to", "value": "203.0.113.20"},
            "asOf": "2026-08-01T00:00:00Z",
            "stalenessDays": 90,
            "sources": [
                {"id": "s1", "type": "dns", "origin": "resolver-a",
                 "observedAt": "2026-07-30T00:00:00Z", "value": "203.0.113.20", "authoritative": False},
                {"id": "s2", "type": "registry", "origin": "whois-b",
                 "observedAt": "2026-07-28T00:00:00Z", "value": "203.0.113.20", "authoritative": False}
            ]
        }
        resp_post = client.post("/corroborate", json=payload)
        self.assertEqual(resp_post.status_code, 200)
        self.assertEqual(resp_post.get_json(), {
            "verdict": "supported",
            "confidence": "high",
            "corroboratingSources": ["s1", "s2"]
        })

if __name__ == "__main__":
    unittest.main()
