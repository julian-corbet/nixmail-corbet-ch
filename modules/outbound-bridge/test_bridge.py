#!/usr/bin/env python3
"""Behavioural tests for the SMTP -> HTTP-API outbound bridge.

This listener has no authentication of its own, and it holds the only
credentials that can spend a paid provider account's sending quota. Its access
control is therefore the whole security model, and its default must fail closed
— the module's own comments record a previous version that defaulted the bind
address to 0.0.0.0, turning a forgotten environment variable into an open relay.
Those defaults are pinned here so that regression cannot recur quietly.

The other properties tested are the ones the docstring calls out as structural
rather than enforced: at most one relay per message, and never a silent drop.

Stdlib unittest, no pytest.
"""
import asyncio
import ipaddress
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import bridge  # noqa: E402


class AccessControlTest(unittest.TestCase):
    """An unset allow-list means loopback, never everyone."""

    def test_empty_allow_list_means_loopback_only(self):
        nets = bridge._parse_allowed_clients("")
        self.assertEqual(
            set(nets),
            {ipaddress.ip_network("127.0.0.1/32"), ipaddress.ip_network("::1/128")},
            "an unset allow-list must be loopback, not a wildcard")

    def test_whitespace_only_allow_list_also_means_loopback(self):
        self.assertEqual(bridge._parse_allowed_clients("   "),
                         bridge._parse_allowed_clients(""))

    def test_bare_address_becomes_a_host_route(self):
        nets = bridge._parse_allowed_clients("192.0.2.5")
        self.assertEqual(nets, [ipaddress.ip_network("192.0.2.5/32")])

    def test_cidr_and_mixed_families_parse(self):
        nets = bridge._parse_allowed_clients("10.0.0.0/24, 192.0.2.5, 2001:db8::/32")
        self.assertEqual(nets, [
            ipaddress.ip_network("10.0.0.0/24"),
            ipaddress.ip_network("192.0.2.5/32"),
            ipaddress.ip_network("2001:db8::/32"),
        ])

    def test_default_nets_admit_loopback_and_refuse_the_internet(self):
        original = bridge.ALLOWED_CLIENT_NETS
        bridge.ALLOWED_CLIENT_NETS = bridge._parse_allowed_clients("")
        try:
            self.assertTrue(bridge._client_allowed("127.0.0.1"))
            self.assertTrue(bridge._client_allowed("::1"))
            # The open-relay case. If this ever passes, anyone who can reach the
            # socket can spend the account's sending quota.
            self.assertFalse(bridge._client_allowed("203.0.113.5"))
            self.assertFalse(bridge._client_allowed("10.0.0.1"))
        finally:
            bridge.ALLOWED_CLIENT_NETS = original

    def test_unparseable_or_absent_address_is_refused(self):
        for addr in (None, "", "not-an-ip", "127.0.0.1extra"):
            with self.subTest(addr=addr):
                self.assertFalse(bridge._client_allowed(addr))


class SafeDefaultsTest(unittest.TestCase):
    """The defaults that turn a forgotten variable into a safe config."""

    def test_listen_host_defaults_to_loopback(self):
        # Guards the recorded incident: this once defaulted to 0.0.0.0.
        self.assertEqual(
            os.environ.get("BRIDGE_HOST", "127.0.0.1"), "127.0.0.1")
        self.assertIn(bridge.LISTEN_HOST, ("127.0.0.1", "::1"),
                      "the bind address must default to loopback")


class ChainTest(unittest.TestCase):
    """Failover order, and the refusal to narrow it silently."""

    def setUp(self):
        self._registry = dict(bridge.RELAY_REGISTRY)
        self._chain_env = os.environ.get("BRIDGE_RELAY_CHAIN")

    def tearDown(self):
        bridge.RELAY_REGISTRY.clear()
        bridge.RELAY_REGISTRY.update(self._registry)
        if self._chain_env is None:
            os.environ.pop("BRIDGE_RELAY_CHAIN", None)
        else:
            os.environ["BRIDGE_RELAY_CHAIN"] = self._chain_env

    def test_unknown_relay_name_is_a_hard_failure(self):
        # A typo must never quietly shrink the failover chain — losing a relay
        # silently is discovered only when the others are already down.
        os.environ["BRIDGE_RELAY_CHAIN"] = "brevo,typoed-provider"
        with self.assertRaises(SystemExit):
            bridge.build_chain()

    def test_chain_includes_only_relays_with_a_key(self):
        for name in bridge.RELAY_REGISTRY:
            bridge.RELAY_REGISTRY[name] = (bridge.RELAY_REGISTRY[name][0], "")
        bridge.RELAY_REGISTRY["resend"] = (bridge.RELAY_REGISTRY["resend"][0], "key")
        os.environ.pop("BRIDGE_RELAY_CHAIN", None)
        self.assertEqual([n for n, _ in bridge.build_chain()], ["resend"])

    def test_explicit_order_is_honoured(self):
        for name in bridge.RELAY_REGISTRY:
            bridge.RELAY_REGISTRY[name] = (bridge.RELAY_REGISTRY[name][0], "key")
        os.environ["BRIDGE_RELAY_CHAIN"] = "resend,brevo"
        self.assertEqual([n for n, _ in bridge.build_chain()], ["resend", "brevo"])


class FakeSession:
    def __init__(self, ip="127.0.0.1"):
        self.peer = (ip, 12345)


class FakeEnvelope:
    def __init__(self, content, mail_from="s@example.com", rcpt_tos=None):
        self.content = content
        self.mail_from = mail_from
        self.rcpt_tos = rcpt_tos or ["r@example.net"]


MESSAGE = (
    b"From: Sender <s@example.com>\r\n"
    b"To: Recipient <r@example.net>\r\n"
    b"Subject: test\r\n"
    b"\r\n"
    b"body\r\n"
)


class DeliveryTest(unittest.TestCase):
    """One relay per message, and no silent drops."""

    def _handler(self, chain):
        h = bridge.BridgeHandler.__new__(bridge.BridgeHandler)
        h.chain = chain
        h.ms_routing_enabled = False
        h.ms_routing_name = None
        h.ms_routing_fn = None
        return h

    def _run(self, handler, session=None, envelope=None):
        return asyncio.run(handler.handle_DATA(
            None,
            session or FakeSession(),
            envelope or FakeEnvelope(MESSAGE)))

    def test_stops_at_the_first_relay_that_accepts(self):
        # This early return IS the "at most one relay per message" guarantee.
        # Nothing else enforces it, so a message must never reach relay two once
        # relay one has accepted it — that would send it twice.
        calls = []

        async def ok(client, m):
            calls.append("first")
            return True, "accepted"

        async def should_not_run(client, m):
            calls.append("second")
            return True, "accepted"

        reply = self._run(self._handler([("first", ok), ("second", should_not_run)]))
        self.assertTrue(reply.startswith("250"), reply)
        self.assertEqual(calls, ["first"], "a delivered message must not be relayed again")

    def test_falls_over_to_the_next_relay_on_failure(self):
        calls = []

        async def fails(client, m):
            calls.append("first")
            return False, "quota exhausted"

        async def succeeds(client, m):
            calls.append("second")
            return True, "accepted"

        reply = self._run(self._handler([("first", fails), ("second", succeeds)]))
        self.assertTrue(reply.startswith("250"), reply)
        self.assertEqual(calls, ["first", "second"])

    def test_a_raising_relay_is_a_failure_not_a_crash(self):
        async def explodes(client, m):
            raise RuntimeError("provider DNS broke")

        async def succeeds(client, m):
            return True, "accepted"

        reply = self._run(self._handler([("boom", explodes), ("ok", succeeds)]))
        self.assertTrue(reply.startswith("250"), reply)

    def test_total_failure_defers_rather_than_bouncing(self):
        # 4xx keeps the message queued on the calling MTA. A 5xx here would
        # bounce mail because every provider happened to be briefly unreachable.
        async def fails(client, m):
            return False, "down"

        reply = self._run(self._handler([("a", fails), ("b", fails)]))
        self.assertTrue(reply.startswith("451"), reply)

    def test_empty_chain_defers_rather_than_dropping(self):
        reply = self._run(self._handler([]))
        self.assertTrue(reply.startswith("451"), reply)

    def test_disallowed_client_is_refused_at_data_too(self):
        # Defence in depth: handle_MAIL already checks, but this must not trust
        # that it fired.
        original = bridge.ALLOWED_CLIENT_NETS
        bridge.ALLOWED_CLIENT_NETS = bridge._parse_allowed_clients("")

        async def ok(client, m):
            raise AssertionError("a disallowed client must never reach a relay")

        try:
            reply = self._run(self._handler([("ok", ok)]),
                              session=FakeSession("203.0.113.5"))
            self.assertTrue(reply.startswith("550"), reply)
        finally:
            bridge.ALLOWED_CLIENT_NETS = original


class ParseTest(unittest.TestCase):
    def test_addresses_are_extracted_with_names(self):
        self.assertEqual(
            bridge._addrs("Alice <a@example.com>, b@example.net"),
            [{"email": "a@example.com", "name": "Alice"},
             {"email": "b@example.net", "name": ""}])

    def test_empty_header_yields_no_addresses(self):
        self.assertEqual(bridge._addrs(""), [])
        self.assertEqual(bridge._addrs(None), [])

    def test_message_parses_into_sender_and_recipients(self):
        m = bridge.parse_message(MESSAGE, FakeEnvelope(MESSAGE))
        self.assertEqual(m["from_email"], "s@example.com")
        self.assertEqual(m["rcpts"], ["r@example.net"])
        self.assertEqual(m["subject"], "test")

    def test_envelope_recipients_win_over_header_recipients(self):
        # The envelope is authoritative, and it must stay that way. A Bcc
        # recipient exists only in the envelope, so deriving recipients from the
        # To: header would silently fail to deliver to them — and a header
        # recipient absent from the envelope must not receive a copy either.
        envelope = FakeEnvelope(MESSAGE, rcpt_tos=["bcc@example.org"])
        m = bridge.parse_message(MESSAGE, envelope)
        self.assertEqual(m["rcpts"], ["bcc@example.org"])
        self.assertNotIn("r@example.net", m["rcpts"])

    def test_duplicate_envelope_recipients_are_collapsed(self):
        # One relay call per message, so a duplicated recipient would otherwise
        # become a duplicate delivery.
        envelope = FakeEnvelope(MESSAGE, rcpt_tos=["a@example.net", "a@example.net", "b@example.net"])
        m = bridge.parse_message(MESSAGE, envelope)
        self.assertEqual(m["rcpts"], ["a@example.net", "b@example.net"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
