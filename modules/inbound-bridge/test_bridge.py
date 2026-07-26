#!/usr/bin/env python3
"""Behavioural tests for the inbound HTTP -> LMTP bridge.

These pin the properties the module docstring promises, because every one of
them fails silently if broken. A status mapped the wrong way does not raise: it
makes a caller retry a hard refusal forever, or drop a message that only needed
retrying. Nothing about that shows up in a log you would notice.

Stdlib only, matching the bridge itself — no pytest, no mock library.
"""
import os
import sys
import threading
import unittest
import urllib.error
import urllib.request
from http.server import ThreadingHTTPServer

# The bridge reads its configuration into module-level constants at import time,
# so the environment has to be set up before the import rather than after.
os.environ.setdefault("INBOUND_BRIDGE_SECRET", "test-secret")
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import bridge  # noqa: E402


class FakeLMTP:
    """Stands in for smtplib.LMTP, scripted per stage.

    `script` maps a stage name to the (code, response) that stage should return.
    Any stage left out succeeds with 250. Every instance appends itself to
    `instances`, which is how the per-recipient property is observed: one
    transaction per recipient means one instance per recipient.
    """

    instances = []
    script = {}

    def __init__(self, host, port, timeout=None):
        self.host, self.port, self.timeout = host, port, timeout
        self.stages = []
        self.quit_called = False
        FakeLMTP.instances.append(self)

    def _result(self, stage):
        self.stages.append(stage)
        return FakeLMTP.script.get(stage, (250, b"ok"))

    def docmd(self, cmd, arg=None):
        return self._result(cmd.lower())

    def mail(self, sender):
        self.sender = sender
        return self._result("mail")

    def rcpt(self, recipient):
        self.recipient = recipient
        return self._result("rcpt")

    def data(self, raw):
        self.raw = raw
        return self._result("data")

    def quit(self):
        self.quit_called = True


class DeliverOneTest(unittest.TestCase):
    """The (ok, tempfail, detail) contract of a single LMTP transaction."""

    def setUp(self):
        FakeLMTP.instances = []
        FakeLMTP.script = {}
        self._real = bridge.smtplib.LMTP
        bridge.smtplib.LMTP = FakeLMTP

    def tearDown(self):
        bridge.smtplib.LMTP = self._real

    def test_clean_delivery_is_ok_and_not_tempfail(self):
        ok, tempfail, _ = bridge.deliver_one("s@example.com", "r@example.com", b"raw")
        self.assertTrue(ok)
        self.assertFalse(tempfail)

    def test_lhlo_failure_is_always_temporary(self):
        # A greeting failure says nothing about the message, only about the
        # server's current state — so it must never be reported as a refusal,
        # not even on a 5xx. Getting this wrong bounces mail because the mail
        # server was briefly busy.
        for code in (421, 500, 550):
            with self.subTest(code=code):
                FakeLMTP.script = {"lhlo": (code, b"nope")}
                ok, tempfail, _ = bridge.deliver_one("s@example.com", "r@example.com", b"raw")
                self.assertFalse(ok)
                self.assertTrue(tempfail, "an LHLO failure must be retryable regardless of code")

    def test_4xx_is_temporary_and_5xx_is_permanent(self):
        # The distinction the whole bridge exists to preserve: 4xx means "ask me
        # again", 5xx means "never ask me again". Collapsing them either
        # re-bounces a message forever or discards one that would have delivered.
        for stage in ("mail", "rcpt", "data"):
            with self.subTest(stage=stage, kind="4xx"):
                FakeLMTP.script = {stage: (450, b"later")}
                ok, tempfail, _ = bridge.deliver_one("s@example.com", "r@example.com", b"raw")
                self.assertFalse(ok)
                self.assertTrue(tempfail)
            with self.subTest(stage=stage, kind="5xx"):
                FakeLMTP.script = {stage: (550, b"never")}
                ok, tempfail, _ = bridge.deliver_one("s@example.com", "r@example.com", b"raw")
                self.assertFalse(ok)
                self.assertFalse(tempfail)

    def test_connection_is_always_closed(self):
        FakeLMTP.script = {"rcpt": (550, b"no such user")}
        bridge.deliver_one("s@example.com", "r@example.com", b"raw")
        self.assertTrue(FakeLMTP.instances[0].quit_called,
                        "a refused transaction must still close its connection")


class HttpBehaviourTest(unittest.TestCase):
    """The caller-facing half: one HTTP status per outcome, over a real socket."""

    @classmethod
    def setUpClass(cls):
        cls._real = bridge.smtplib.LMTP
        bridge.smtplib.LMTP = FakeLMTP
        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), bridge.Handler)
        cls.port = cls.server.server_address[1]
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        bridge.smtplib.LMTP = cls._real

    def setUp(self):
        FakeLMTP.instances = []
        FakeLMTP.script = {}
        bridge.SECRET = "test-secret"
        bridge.ALLOWED_CLIENTS = set()

    def post(self, rcpts="r@example.com", body=b"raw message", token="test-secret"):
        req = urllib.request.Request(
            f"http://127.0.0.1:{self.port}/", data=body, method="POST")
        req.add_header("X-Mail-From", "s@example.com")
        req.add_header("X-Rcpt-To", rcpts)
        if token is not None:
            req.add_header("Authorization", f"Bearer {token}")
        try:
            with urllib.request.urlopen(req, timeout=10) as r:
                return r.status
        except urllib.error.HTTPError as e:
            return e.code

    def test_success_is_200(self):
        self.assertEqual(self.post(), 200)

    def test_temporary_failure_is_421_so_the_caller_retries(self):
        FakeLMTP.script = {"data": (450, b"later")}
        self.assertEqual(self.post(), 421)

    def test_hard_refusal_is_550_so_the_caller_does_not_retry(self):
        # Retrying a hard refusal just re-bounces the same message forever.
        FakeLMTP.script = {"data": (550, b"never")}
        self.assertEqual(self.post(), 550)

    def test_one_lmtp_transaction_per_recipient(self):
        # LMTP returns a status line per recipient precisely so a delivery can
        # partially succeed. Blending recipients into one transaction would
        # misreport whichever ones did not match the average.
        self.post(rcpts="a@example.com, b@example.com, c@example.com")
        self.assertEqual(len(FakeLMTP.instances), 3)
        self.assertEqual(
            [i.recipient for i in FakeLMTP.instances],
            ["a@example.com", "b@example.com", "c@example.com"])

    def test_partial_success_reports_success(self):
        # One good mailbox means the message WAS delivered. Reporting a retryable
        # failure here would duplicate it into the mailbox that already has it.
        calls = {"n": 0}
        real_deliver = bridge.deliver_one

        def flaky(mail_from, rcpt, raw):
            calls["n"] += 1
            if calls["n"] == 1:
                return False, False, "refused"
            return True, False, "ok"

        bridge.deliver_one = flaky
        try:
            self.assertEqual(self.post(rcpts="bad@example.com, good@example.com"), 200)
        finally:
            bridge.deliver_one = real_deliver

    def test_wrong_bearer_is_rejected(self):
        self.assertEqual(self.post(token="wrong"), 401)

    def test_missing_bearer_is_rejected(self):
        self.assertEqual(self.post(token=None), 401)

    def test_missing_recipients_is_a_client_error(self):
        self.assertEqual(self.post(rcpts=""), 400)

    def test_oversized_body_is_refused(self):
        original = bridge.MAX_SIZE
        bridge.MAX_SIZE = 4
        try:
            self.assertEqual(self.post(body=b"much longer than four bytes"), 400)
        finally:
            bridge.MAX_SIZE = original

    def test_delivery_exception_is_temporary_never_a_drop(self):
        # No message is ever silently dropped. An unexpected exception must
        # surface as retryable, not as success and not as a refusal.
        real_deliver = bridge.deliver_one

        def boom(mail_from, rcpt, raw):
            raise RuntimeError("LMTP host vanished")

        bridge.deliver_one = boom
        try:
            self.assertEqual(self.post(), 421)
        finally:
            bridge.deliver_one = real_deliver


class FailClosedTest(unittest.TestCase):
    """An unauthenticated inbound endpoint injects arbitrary mail into a real
    mailbox. Refusing to start is strictly the better failure."""

    def test_no_secret_and_no_opt_in_refuses_to_start(self):
        secret, allow = bridge.SECRET, bridge.ALLOW_UNAUTHENTICATED
        bridge.SECRET, bridge.ALLOW_UNAUTHENTICATED = "", False
        try:
            with self.assertRaises(SystemExit) as ctx:
                bridge.main()
            self.assertEqual(ctx.exception.code, 1)
        finally:
            bridge.SECRET, bridge.ALLOW_UNAUTHENTICATED = secret, allow


if __name__ == "__main__":
    unittest.main(verbosity=2)
