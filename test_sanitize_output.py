import unittest
import json
from app import app
from sanitize_output import evaluate_sanitize_output

class TestSanitizeOutput(unittest.TestCase):

    # 1. SAFE html
    def test_safe_html(self):
        res = evaluate_sanitize_output({
            "channel": "html",
            "output": "<p>Hello world</p><img src=\"https://cdn-0nl2whi.example/pic.png\">"
        })
        self.assertEqual(res, {"safe": True, "reason": "SAFE"})

    # 2. SAFE markdown with allowed host
    def test_safe_markdown_allowed_host(self):
        res = evaluate_sanitize_output({
            "channel": "markdown",
            "output": "![chart](https://cdn-0nl2whi.example/chart.png)"
        })
        self.assertEqual(res, {"safe": True, "reason": "SAFE"})

    # 3. SAFE url with exact allowed host
    def test_safe_url_allowed_host(self):
        res = evaluate_sanitize_output({
            "channel": "url",
            "output": "https://app-a2ytvc7.example/dashboard"
        })
        self.assertEqual(res, {"safe": True, "reason": "SAFE"})

    # 4. relative URL
    def test_safe_relative_url(self):
        res = evaluate_sanitize_output({
            "channel": "html",
            "output": "<a href=\"/local/page\">go</a>"
        })
        self.assertEqual(res, {"safe": True, "reason": "SAFE"})

    # 5. protocol-relative allowed host
    def test_safe_protocol_relative_allowed_host(self):
        res = evaluate_sanitize_output({
            "channel": "html",
            "output": "<img src=\"//cdn-0nl2whi.example/ok.gif\">"
        })
        self.assertEqual(res, {"safe": True, "reason": "SAFE"})

    # 6. attacker hostname
    def test_attacker_hostname(self):
        res = evaluate_sanitize_output({
            "channel": "markdown",
            "output": "![](https://attacker.example/pic.png)"
        })
        self.assertEqual(res, {"safe": False, "reason": "EXTERNAL_EXFIL"})

    # 7. allowed hostname as username before @ attacker
    def test_credentials_spoof(self):
        res = evaluate_sanitize_output({
            "channel": "html",
            "output": "<a href=\"https://cdn-0nl2whi.example@attacker.example/x\">link</a>"
        })
        self.assertEqual(res, {"safe": False, "reason": "EXTERNAL_EXFIL"})

    # 8. attacker hostname with allowed hostname in query
    def test_query_spoof(self):
        res = evaluate_sanitize_output({
            "channel": "url",
            "output": "https://attacker.example/?next=https://cdn-0nl2whi.example/"
        })
        self.assertEqual(res, {"safe": False, "reason": "EXTERNAL_EXFIL"})

    # 9. attacker subdomain of allowed hostname
    def test_subdomain_spoof(self):
        res = evaluate_sanitize_output({
            "channel": "html",
            "output": "<img src=\"https://cdn-0nl2whi.example.attacker.example/x.png\">"
        })
        self.assertEqual(res, {"safe": False, "reason": "EXTERNAL_EXFIL"})

        res2 = evaluate_sanitize_output({
            "channel": "html",
            "output": "<img src=\"https://sub.cdn-0nl2whi.example/x.png\">"
        })
        self.assertEqual(res2, {"safe": False, "reason": "EXTERNAL_EXFIL"})

    # 10. javascript:
    def test_javascript_scheme(self):
        res = evaluate_sanitize_output({
            "channel": "html",
            "output": "<a href=\"javascript :alert(1)\">click</a>"
        })
        self.assertEqual(res, {"safe": False, "reason": "DANGEROUS_SCHEME"})

    # 11. encoded javascript
    def test_encoded_javascript(self):
        res = evaluate_sanitize_output({
            "channel": "html",
            "output": "<a href=\"java&#115;cript:alert(1)\">x</a>"
        })
        self.assertEqual(res, {"safe": False, "reason": "ENCODED_PAYLOAD"})

    # 12. encoded script
    def test_encoded_script(self):
        res = evaluate_sanitize_output({
            "channel": "html",
            "output": "%3Cscript%3Ealert(1)%3C/script%3E"
        })
        self.assertEqual(res, {"safe": False, "reason": "ENCODED_PAYLOAD"})

    # 13. script tag
    def test_script_tag(self):
        res = evaluate_sanitize_output({
            "channel": "html",
            "output": "<div><script>fetch('/x')</script></div>"
        })
        self.assertEqual(res, {"safe": False, "reason": "SCRIPT_TAG"})

    # 14. iframe
    def test_iframe_tag(self):
        res = evaluate_sanitize_output({
            "channel": "html",
            "output": "<iframe src=\"https://cdn-0nl2whi.example/page\"></iframe>"
        })
        self.assertEqual(res, {"safe": False, "reason": "SCRIPT_TAG"})

    # 15. object
    def test_object_tag(self):
        res = evaluate_sanitize_output({
            "channel": "html",
            "output": "<object data=\"https://cdn-0nl2whi.example/page\"></object>"
        })
        self.assertEqual(res, {"safe": False, "reason": "SCRIPT_TAG"})

    # 16. embed
    def test_embed_tag(self):
        res = evaluate_sanitize_output({
            "channel": "html",
            "output": "<embed src=\"https://cdn-0nl2whi.example/page\">"
        })
        self.assertEqual(res, {"safe": False, "reason": "SCRIPT_TAG"})

    # 17. event handler
    def test_event_handler(self):
        res = evaluate_sanitize_output({
            "channel": "html",
            "output": "<img src=\"https://cdn-0nl2whi.example/a.png\" onerror=\"x()\">"
        })
        self.assertEqual(res, {"safe": False, "reason": "EVENT_HANDLER"})

    # 18. harmless prose containing oncall=
    def test_prose_containing_oncall(self):
        res = evaluate_sanitize_output({
            "channel": "html",
            "output": "<p>The engineer oncall=today is Bob</p>"
        })
        self.assertEqual(res, {"safe": True, "reason": "SAFE"})

    # 19. SQL quote
    def test_sql_quote(self):
        res = evaluate_sanitize_output({
            "channel": "sql",
            "output": "SELECT * FROM users WHERE name = 'admin'"
        })
        self.assertEqual(res, {"safe": False, "reason": "SQL_METACHAR"})

    # 20. SQL union
    def test_sql_union(self):
        res = evaluate_sanitize_output({
            "channel": "sql",
            "output": "1 UNION SELECT 1, 2"
        })
        self.assertEqual(res, {"safe": False, "reason": "SQL_METACHAR"})

    # 21. SQL OR 1=1
    def test_sql_or_1_eq_1(self):
        res = evaluate_sanitize_output({
            "channel": "sql",
            "output": "admin or 1=1"
        })
        self.assertEqual(res, {"safe": False, "reason": "SQL_METACHAR"})

    # 22. shell metacharacters
    def test_shell_metachar(self):
        for ch in [";", "&", "|", "`", "<", ">", "$(", "${"]:
            res = evaluate_sanitize_output({
                "channel": "shell",
                "output": f"echo test {ch}"
            })
            self.assertEqual(res, {"safe": False, "reason": "SHELL_METACHAR"}, f"Failed on {ch}")

        # Benign shell
        res_benign = evaluate_sanitize_output({
            "channel": "shell",
            "output": "report-mark-123.csv"
        })
        self.assertEqual(res_benign, {"safe": True, "reason": "SAFE"})

    # 23. invalid channel
    def test_invalid_channel(self):
        res = evaluate_sanitize_output({
            "channel": "graphql",
            "output": "x"
        })
        self.assertEqual(res, {"safe": False, "reason": "INVALID_SCHEMA"})

    # 24. non-string output
    def test_non_string_output(self):
        res = evaluate_sanitize_output({
            "channel": "html",
            "output": 42
        })
        self.assertEqual(res, {"safe": False, "reason": "INVALID_SCHEMA"})

    # 25. output > 20000
    def test_output_too_long(self):
        res = evaluate_sanitize_output({
            "channel": "html",
            "output": "a" * 20001
        })
        self.assertEqual(res, {"safe": False, "reason": "INVALID_SCHEMA"})

    # 26. protocol-relative attacker
    def test_protocol_relative_attacker(self):
        res = evaluate_sanitize_output({
            "channel": "html",
            "output": "<img src=\"//attacker.example/beacon.gif\">"
        })
        self.assertEqual(res, {"safe": False, "reason": "EXTERNAL_EXFIL"})

    # 27. URL channel containing Markdown-looking text
    def test_url_markdown_looking(self):
        res = evaluate_sanitize_output({
            "channel": "url",
            "output": "https://app-a2ytvc7.example/dashboard"
        })
        self.assertEqual(res, {"safe": True, "reason": "SAFE"})

        res_bad = evaluate_sanitize_output({
            "channel": "url",
            "output": "https://collector.example/callback"
        })
        self.assertEqual(res_bad, {"safe": False, "reason": "EXTERNAL_EXFIL"})

    # 28. only the explicitly allowed HTML entities are decoded
    def test_allowed_html_entities_only(self):
        # &nbsp; is not one of lt, gt, quot, apos, amp, numeric
        res = evaluate_sanitize_output({
            "channel": "html",
            "output": "<p>&nbsp;</p>"
        })
        self.assertEqual(res, {"safe": True, "reason": "SAFE"})

    # 29. \uXXXX decoding happens once
    def test_unicode_decoding(self):
        res = evaluate_sanitize_output({
            "channel": "html",
            "output": "\\u003cscript\\u003e"
        })
        self.assertEqual(res, {"safe": False, "reason": "ENCODED_PAYLOAD"})

    # 30. double-encoded payloads are NOT recursively decoded
    def test_double_encoded_not_recursive(self):
        # %253C is double-encoded '<' (%25 -> '%', leaving '%3C')
        res = evaluate_sanitize_output({
            "channel": "html",
            "output": "%253Cscript%253E"
        })
        # After 1 decode: '%3Cscript%3E' -> which does not trigger script tag, so reason is SAFE
        self.assertEqual(res, {"safe": True, "reason": "SAFE"})

    # Flask HTTP endpoint tests
    def test_endpoint_availability(self):
        client = app.test_client()

        # GET /
        resp = client.get("/")
        self.assertEqual(resp.status_code, 200)
        self.assertTrue(resp.is_json)
        self.assertIn("/sanitize-output", resp.get_json()["endpoints"])

        # GET /sanitize-output
        resp_get = client.get("/sanitize-output")
        self.assertEqual(resp_get.status_code, 200)
        self.assertTrue(resp_get.is_json)

        # GET /sanitize-output/
        resp_get_slash = client.get("/sanitize-output/")
        self.assertEqual(resp_get_slash.status_code, 200)
        self.assertTrue(resp_get_slash.is_json)

        # POST /sanitize-output
        resp_post = client.post("/sanitize-output", json={
            "channel": "html",
            "output": "<img src=\"https://cdn-0nl2whi.example/pic.png\">"
        })
        self.assertEqual(resp_post.status_code, 200)
        self.assertEqual(resp_post.get_json(), {"safe": True, "reason": "SAFE"})

        # POST /sanitize-output without content-type header
        resp_raw = client.post(
            "/sanitize-output",
            data=json.dumps({"channel": "shell", "output": "file.txt"}),
            content_type="text/plain",
        )
        self.assertEqual(resp_raw.status_code, 200)
        self.assertEqual(resp_raw.get_json(), {"safe": True, "reason": "SAFE"})

if __name__ == "__main__":
    unittest.main()
