"""
PhishGuard tests. Run from the project folder:

    python -m unittest discover -s tests -v

Uses a temporary database. No URL is ever fetched or opened.
"""

import importlib
import os
import shutil
import sqlite3
import sys
import tempfile
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

_tmp = tempfile.mkdtemp()
os.environ["PHISHGUARD_DB"] = os.path.join(_tmp, "test.db")

import config  # noqa: E402
from app import app  # noqa: E402
from model import predict  # noqa: E402
from utils import database  # noqa: E402
from utils.risk import get_risk_level, get_verdict  # noqa: E402
from utils.validation import InvalidURLError, validate_url  # noqa: E402

NAV_LABELS = ("Dashboard", "URL Scanner", "Scan History")


class ValidationTests(unittest.TestCase):
    def test_adds_https_when_scheme_missing(self):
        self.assertEqual(validate_url("example.com/a"), "https://example.com/a")

    def test_rejects_bad_input(self):
        for bad in ["", "   ", None, "www://google.com", "javascript:alert(1)", "ftp://a.com",
                    "http://", "http://localhost", "a b.com", "http://999.1.1.1",
                    "https://x.com:99999", "http://a..com", "http://foo.123", "x" * 3000]:
            with self.subTest(bad=bad), self.assertRaises(InvalidURLError):
                validate_url(bad)


class RiskTests(unittest.TestCase):
    def test_bands_and_verdict_agree(self):
        for score in range(0, 101):
            level = get_risk_level(score)
            verdict = get_verdict(score / 100)
            self.assertEqual(verdict == "Phishing", level in ("High Risk", "Critical Risk"), score)


class ModelTests(unittest.TestCase):
    def test_model_loads_and_dimensions_match(self):
        predict.reset_for_tests()
        status = predict.get_status()
        self.assertIn(status["state"], ("online", "warning"), status["message"])
        bundle = predict._state["bundle"]
        self.assertEqual(len(bundle["vectorizer"].vocabulary_), bundle["model"].coef_.shape[1])

    def test_prediction_shape(self):
        r = predict.predict_url("https://www.wikipedia.org")
        self.assertIn(r["verdict"], ("Legitimate", "Phishing"))
        self.assertTrue(0 <= r["risk_score"] <= 100)
        self.assertAlmostEqual(r["risk_score"], r["probability"] * 100, delta=0.06)

    def test_obvious_cases(self):
        self.assertEqual(predict.predict_url("https://www.microsoft.com/en-us")["verdict"], "Legitimate")
        self.assertEqual(predict.predict_url("http://secure-login.example.com/verify-account/update.php")["verdict"],
                         "Phishing")

    def test_missing_model_reports_offline(self):
        original = config.MODEL_PATH
        try:
            config.MODEL_PATH = type(original)(os.path.join(_tmp, "missing.pkl"))
            predict.reset_for_tests()
            self.assertEqual(predict.get_status()["state"], "offline")
            with self.assertRaises(predict.ModelLoadError):
                predict.predict_url("https://example.com")
        finally:
            config.MODEL_PATH = original
            predict.reset_for_tests()

    def test_indicators_match_the_url(self):
        codes = {i["code"] for i in predict.predict_url("http://192.168.1.1/verify/account")["indicators"]}
        self.assertIn("ip_host", codes)
        self.assertIn("no_https", codes)
        codes = {i["code"] for i in predict.predict_url("https://www.wikipedia.org")["indicators"]}
        self.assertNotIn("ip_host", codes)
        self.assertNotIn("shortener", codes)
        self.assertIn("shortener", {i["code"] for i in predict.predict_url("https://bit.ly/abc")["indicators"]})


class WebTests(unittest.TestCase):
    def setUp(self):
        if os.path.exists(config.DB_PATH):
            os.remove(config.DB_PATH)
        database.init_db()
        self.client = app.test_client()

    def test_pages_load_and_nav_is_exact(self):
        for path in ("/", "/scanner", "/history"):
            r = self.client.get(path)
            self.assertEqual(r.status_code, 200, path)
            html = r.get_data(as_text=True)
            self.assertNotIn("Methodology", html)
            self.assertNotIn("/methodology", html)
            for label in NAV_LABELS:
                self.assertIn(label, html)
        self.assertEqual(self.client.get("/methodology").status_code, 404)
        self.assertEqual(self.client.get("/dashboard").status_code, 301)

    def test_empty_states(self):
        self.assertIn("No scans yet", self.client.get("/history").get_data(as_text=True))
        self.assertIn("No scan activity yet", self.client.get("/").get_data(as_text=True))

    def test_scan_saved_and_counts_real(self):
        for url in ("https://www.wikipedia.org", "http://secure-login.example.com/verify-account/update.php",
                    "http://192.168.1.1/verify/account"):
            r = self.client.post("/scanner", data={"url": url})
            self.assertEqual(r.status_code, 302)
            self.assertEqual(self.client.get(r.headers["Location"]).status_code, 200)
        stats = database.get_dashboard_stats()
        self.assertEqual(stats["total"], 3)
        self.assertEqual(stats["legitimate"] + stats["phishing"], 3)
        self.assertEqual(stats["phishing"], 2)
        history = self.client.get("/history").get_data(as_text=True)
        self.assertIn("wikipedia.org", history)
        self.assertIn("192.168.1.1", history)
        rows, total = database.get_history(result_filter="Phishing")
        self.assertEqual(total, 2)

    def test_invalid_input_not_saved(self):
        for bad in ("", "   ", "www://google.com", "not a url"):
            r = self.client.post("/scanner", data={"url": bad})
            self.assertEqual(r.status_code, 400, bad)
        self.assertEqual(database.get_dashboard_stats()["total"], 0)

    def test_html_in_url_is_escaped(self):
        payload = 'https://example.com/<script>alert(1)</script>"onmouseover="x'
        r = self.client.post("/scanner", data={"url": payload})
        html = self.client.get(r.headers["Location"]).get_data(as_text=True)
        self.assertNotIn("<script>alert(1)</script>", html)
        self.assertIn("&lt;script&gt;", html)
        history = self.client.get("/history").get_data(as_text=True)
        self.assertNotIn("<script>alert(1)</script>", history)

    def test_no_path_or_trace_leak_and_headers(self):
        r = self.client.post("/scanner", data={"url": "bad input"})
        text = r.get_data(as_text=True)
        self.assertNotIn(ROOT, text)
        self.assertNotIn("Traceback", text)
        self.assertEqual(r.headers["X-Content-Type-Options"], "nosniff")
        self.assertIn("script-src 'self'", r.headers["Content-Security-Policy"])

    def test_unknown_scan_is_404(self):
        self.assertEqual(self.client.get("/scanner?scan=424242").status_code, 404)

    def test_no_http_requests_made_for_scan(self):
        import socket
        original = socket.socket.connect

        def blocked(*a, **k):
            raise AssertionError("network access attempted during analysis")
        socket.socket.connect = blocked
        try:
            predict.predict_url("http://example.com/login")
        finally:
            socket.socket.connect = original


class MigrationTests(unittest.TestCase):
    def test_old_database_is_migrated_without_data_loss(self):
        old_path = os.path.join(_tmp, "old.db")
        con = sqlite3.connect(old_path)
        con.execute("""CREATE TABLE scans (id INTEGER PRIMARY KEY AUTOINCREMENT, url TEXT NOT NULL,
                       result TEXT NOT NULL, risk_score REAL NOT NULL, risk_level TEXT NOT NULL,
                       scanned_at TEXT NOT NULL)""")
        con.execute("INSERT INTO scans (url,result,risk_score,risk_level,scanned_at) VALUES "
                    "('https://old.example.com','Legitimate',1.5,'Low Risk','25 Sep 2026, 01:49 PM')")
        con.commit()
        con.close()

        original = config.DB_PATH
        config.DB_PATH = type(original)(old_path)
        try:
            database.init_db()
            database.init_db()  # idempotent
            rows, total = database.get_history()
            self.assertEqual(total, 1)
            self.assertEqual(rows[0]["url"], "https://old.example.com")
            self.assertEqual(app.test_client().get("/").status_code, 200)
            self.assertEqual(app.test_client().get("/scanner?scan=1").status_code, 200)
            self.assertEqual(app.test_client().get("/history").status_code, 200)
        finally:
            config.DB_PATH = original


class DatasetScriptTests(unittest.TestCase):
    def test_prepare_dataset_balance_and_reproducibility(self):
        import subprocess
        import pandas as pd
        src = os.path.join(_tmp, "src.csv")
        rows = [("https://legit%d.example.com/p" % i, 0) for i in range(30)] + \
               [("http://bad%d.example.net/login" % i, 1) for i in range(30)] + \
               [("https://legit1.example.com/p/", 0), ("HTTPS://LEGIT2.EXAMPLE.COM/p", 0)]  # near-duplicates
        pd.DataFrame(rows, columns=["URLs", "Labels"]).to_csv(src, index=False)
        outs = []
        for name in ("a", "b"):
            out = os.path.join(_tmp, name)
            subprocess.run([sys.executable, os.path.join(ROOT, "scripts", "prepare_dataset.py"),
                            "--source", src, "--out-dir", out, "--per-class", "20", "--no-xlsx"],
                           check=True, capture_output=True)
            outs.append(pd.read_csv(os.path.join(out, "phishguard_balanced_10000.csv")))
        self.assertTrue(outs[0].equals(outs[1]))
        self.assertEqual(outs[0]["Labels"].value_counts().to_dict(), {0: 20, 1: 20})
        self.assertEqual(outs[0]["URLs"].nunique(), 40)

    def test_shortage_is_reported_not_faked(self):
        import json
        import subprocess
        import pandas as pd
        src = os.path.join(_tmp, "small.csv")
        rows = [("https://l%d.example.com" % i, 0) for i in range(10)] + \
               [("http://p%d.example.net" % i, 1) for i in range(4)]
        pd.DataFrame(rows, columns=["URLs", "Labels"]).to_csv(src, index=False)
        out = os.path.join(_tmp, "small_out")
        subprocess.run([sys.executable, os.path.join(ROOT, "scripts", "prepare_dataset.py"),
                        "--source", src, "--out-dir", out, "--per-class", "8", "--no-xlsx"],
                       check=True, capture_output=True)
        with open(os.path.join(out, "phishguard_balanced_10000_summary.json")) as fh:
            summary = json.load(fh)
        self.assertIn("warning", summary)
        self.assertEqual(summary["final_legitimate"], 4)
        self.assertEqual(summary["final_phishing"], 4)


def tearDownModule():
    shutil.rmtree(_tmp, ignore_errors=True)


if __name__ == "__main__":
    unittest.main()
