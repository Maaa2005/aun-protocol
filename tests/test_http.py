"""SPEC section 11.4 over real TLS connections on this machine."""

from __future__ import annotations

import datetime as dt
import ipaddress
import socket
import ssl
import sys
import threading
import time
from collections.abc import Iterator
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

import aun_http  # noqa: E402
import aun_reference  # noqa: E402
from aun_http import CARD_TYPE, InboxServer, deliver  # noqa: E402
from make_vectors import opening  # noqa: E402

HOST = "relay.example"
LOOPBACK = "127.0.0.1"


def _certificate(tmp: Path, name: str) -> tuple[ssl.SSLContext, ssl.SSLContext]:
    """(server context, client context that trusts only this one certificate)."""
    key = ec.generate_private_key(ec.SECP256R1())
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)])
    now = dt.datetime.now(dt.timezone.utc)
    certificate = (
        x509.CertificateBuilder().subject_name(subject).issuer_name(subject)
        .public_key(key.public_key()).serial_number(x509.random_serial_number())
        .not_valid_before(now - dt.timedelta(hours=1))
        .not_valid_after(now + dt.timedelta(hours=1))
        .add_extension(x509.SubjectAlternativeName([
            x509.DNSName(name), x509.IPAddress(ipaddress.ip_address(LOOPBACK))]), critical=False)
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(key, hashes.SHA256())
    )
    cert_path, key_path = tmp / f"{name}.crt", tmp / f"{name}.key"
    cert_path.write_bytes(certificate.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption()))
    server = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    server.load_cert_chain(cert_path, key_path)
    client = ssl.create_default_context(cafile=str(cert_path))
    return server, client


@pytest.fixture(scope="module")
def contexts(tmp_path_factory) -> tuple[ssl.SSLContext, ssl.SSLContext]:
    return _certificate(tmp_path_factory.mktemp("tls"), HOST)


@pytest.fixture
def inbox(contexts) -> Iterator[InboxServer]:
    server = InboxServer((LOOPBACK, 0), contexts[0])
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield server
    server.shutdown()
    server.server_close()
    thread.join()


def _scripted(contexts, answers: list[tuple[int, dict[str, str]]]):
    """An endpoint that answers from a list and records every request."""
    seen: list[tuple[str, bytes]] = []

    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def do_POST(self) -> None:  # noqa: N802
            body = self.rfile.read(int(self.headers["Content-Length"]))
            seen.append((self.path, body))
            status, headers = answers[min(len(seen) - 1, len(answers) - 1)]
            self.send_response(status)
            for key, value in headers.items():
                self.send_header(key, value)
            self.send_header("Content-Length", "0")
            self.end_headers()

        def log_message(self, format, *args) -> None:  # noqa: A002
            pass

    server = ThreadingHTTPServer((LOOPBACK, 0), Handler)
    server.socket = contexts[0].wrap_socket(server.socket, server_side=True)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server, seen


def _send(url: str, body: bytes, contexts, stop_at: float | None = None, **kwargs) -> aun_http.Delivery:
    """Deliver to the local server under its name, with the address check switched off."""
    options = {
        "context": contexts[1],
        "resolver": lambda host, port: [LOOPBACK],
        "allowed": lambda address: True,
        "backoff": 0.01,
    } | kwargs
    return deliver(url, body, time.time() + 5 if stop_at is None else stop_at, **options)


def _url(server, path: str = "/aun/b", host: str = HOST) -> str:
    return f"https://{host}:{server.server_address[1]}{path}"


def test_a_signed_message_arrives_as_the_same_bytes_and_passes_the_receiver(inbox, contexts):
    from make_vectors import fresh_receiver
    data = opening()
    result = _send(_url(inbox), data, contexts)
    assert (result.outcome, result.status, result.attempts) == ("deposited", 202, 1)
    assert inbox.taken == [("application/aun+json", data)]
    assert fresh_receiver().receive(inbox.taken[0][1], aun_reference.parse_time(
        "2099-01-01T09:00:10+09:00")) == "accepted"


def test_an_endpoint_answers_202_for_a_message_that_will_be_dropped(inbox, contexts):
    """SPEC section 11.4: the answer does not depend on the checks of section 9."""
    for body in (b"not json", opening().replace(b"Test", b"Tampered"), b"{}"):
        assert _send(_url(inbox), body, contexts).status == 202


def test_the_endpoint_refuses_by_size_and_media_type_only(inbox, contexts):
    assert _send(_url(inbox), b"x" * 16385, contexts).status == 413
    assert _send(_url(inbox), b"x" * 16384, contexts).status == 202
    assert _send(_url(inbox), b"x" * 2049, contexts, content_type=CARD_TYPE).status == 413
    assert _send(_url(inbox), b"x" * 2048, contexts, content_type=CARD_TYPE).status == 202
    assert _send(_url(inbox), b"x", contexts, content_type="application/json").status == 415


def test_the_outcome_of_a_refusal_is_give_up_and_takes_one_attempt(inbox, contexts):
    result = _send(_url(inbox), b"x" * 16385, contexts)
    assert (result.outcome, result.attempts) == ("give_up", 1)


def test_a_503_then_a_202_sends_the_identical_bytes_again(contexts):
    server, seen = _scripted(contexts, [(503, {}), (429, {"Retry-After": "0"}), (202, {})])
    data = opening()
    try:
        result = _send(_url(server), data, contexts)
    finally:
        server.shutdown()
    assert (result.outcome, result.attempts) == ("deposited", 3)
    assert [body for _, body in seen] == [data, data, data]


def test_retry_after_is_respected(contexts):
    server, seen = _scripted(contexts, [(429, {"Retry-After": "7"}), (202, {})])
    pauses = []
    try:
        _send(_url(server), b"x", contexts, sleep=pauses.append, stop_at=time.time() + 60)
    finally:
        server.shutdown()
    assert pauses == [7]


def test_sending_stops_at_the_limit_without_a_deposit(contexts):
    server, seen = _scripted(contexts, [(503, {})])
    try:
        result = _send(_url(server), b"x", contexts, backoff=0.05, stop_at=time.time() + 0.3)
    finally:
        server.shutdown()
    assert result.outcome == "stopped" and result.status == 503 and len(seen) >= 2


@pytest.mark.parametrize("status", [301, 302, 307, 308])
def test_a_redirect_is_not_followed(contexts, status):
    other, other_seen = _scripted(contexts, [(202, {})])
    server, seen = _scripted(contexts, [(status, {"Location": _url(other)})])
    try:
        result = _send(_url(server), b"x", contexts)
    finally:
        server.shutdown()
        other.shutdown()
    assert (result.outcome, result.status) == ("give_up", status)
    assert len(seen) == 1 and other_seen == []


def test_a_certificate_for_another_name_sends_nothing_and_counts_as_a_failed_connection(
        tmp_path, contexts):
    """SPEC section 11.4: a later attempt may meet a repaired certificate."""
    server_context, client_context = _certificate(tmp_path, "other.example")
    server = InboxServer((LOOPBACK, 0), server_context)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        result = _send(_url(server), b"x", contexts, context=client_context, backoff=0.05,
                       stop_at=time.time() + 0.2)
    finally:
        server.shutdown()
    assert result.outcome == "stopped" and result.attempts >= 2
    assert "certificate" in result.reason.lower() and server.taken == []


def test_an_unknown_issuer_sends_nothing(inbox):
    result = deliver(_url(inbox), b"x", time.time() + 0.2, resolver=lambda h, p: [LOOPBACK],
                     allowed=lambda a: True, backoff=0.05)
    assert result.outcome == "stopped" and inbox.taken == []


def test_the_real_address_check_refuses_loopback_and_never_connects(inbox, contexts):
    result = deliver(_url(inbox), b"x", time.time() + 0.2, context=contexts[1],
                     resolver=lambda h, p: [LOOPBACK], backoff=0.05)
    assert result.outcome == "stopped" and "no usable address" in result.reason
    assert inbox.taken == []


@pytest.mark.parametrize("private", [
    "127.0.0.1", "10.0.0.1", "169.254.169.254", "::1", "::ffff:127.0.0.1", "fc00::1",
])
def test_a_name_with_only_private_addresses_is_never_connected(contexts, private):
    tried = []
    with pytest.raises(OSError, match="no usable address"):
        aun_http.post_once(f"https://{HOST}/a", b"x", aun_http.MESSAGE_TYPE, contexts[1],
                           resolver=lambda h, p: tried.append(h) or [private])
    assert tried == [HOST]


def test_only_checked_addresses_are_tried_and_the_name_is_resolved_once(inbox, contexts):
    """A second answer from the name server cannot move the connection."""
    answers = [["10.0.0.1", LOOPBACK], ["10.0.0.1"]]
    calls = []

    def resolver(host, port):
        calls.append(host)
        return answers[len(calls) - 1]

    status, _ = aun_http.post_once(
        _url(inbox), b"x", aun_http.MESSAGE_TYPE, contexts[1], resolver=resolver,
        allowed=lambda address: address == LOOPBACK)
    assert status == 202 and calls == [HOST]


def test_a_failed_address_falls_through_to_the_next_checked_one(inbox, contexts):
    """Nothing listens on 127.0.0.2 at this port, because the server took 127.0.0.1 only."""
    status, _ = aun_http.post_once(
        _url(inbox), b"x", aun_http.MESSAGE_TYPE, contexts[1],
        resolver=lambda host, port: ["127.0.0.2", LOOPBACK], allowed=lambda address: True)
    assert status == 202


def test_the_real_resolver_and_check_refuse_localhost(inbox, contexts):
    """Nothing is replaced here: the system's answer for localhost and the real check."""
    result = deliver(_url(inbox, host="localhost"), b"x", time.time() + 0.2, context=contexts[1],
                     backoff=0.05)
    assert result.outcome == "stopped" and "no usable address" in result.reason
    assert inbox.taken == []


@pytest.mark.parametrize("url", [
    "http://relay.example/a", "https://user:secret@relay.example/a",
    "https://relay.example/a#part",
])
def test_a_bad_endpoint_gives_up_without_any_connection(url, contexts):
    tried = []
    result = deliver(url, b"x", time.time() + 1, context=contexts[1],
                     resolver=lambda h, p: tried.append(h) or [LOOPBACK], allowed=lambda a: True)
    assert result.outcome == "give_up" and result.attempts == 0 and tried == []


def test_a_get_is_refused_and_compression_is_refused(inbox, contexts):
    import http.client
    connection = http.client.HTTPSConnection(LOOPBACK, inbox.server_address[1], context=contexts[1])
    connection.request("GET", "/aun/b")
    assert connection.getresponse().status == 405
    connection.close()
    connection = http.client.HTTPSConnection(LOOPBACK, inbox.server_address[1], context=contexts[1])
    connection.request("POST", "/aun/b", b"x", {"Content-Type": aun_http.MESSAGE_TYPE,
                                                "Content-Encoding": "gzip"})
    assert connection.getresponse().status == 400
    connection.close()
    assert inbox.taken == []


# ---- from review: a slow endpoint, Retry-After, and strict request framing


class _Slow(BaseHTTPRequestHandler):
    """Sends a body, or the status line itself, one byte at a time without end."""

    protocol_version = "HTTP/1.1"
    stream_header = False

    def do_POST(self) -> None:  # noqa: N802
        self.rfile.read(int(self.headers["Content-Length"]))
        try:
            if self.stream_header:
                self.wfile.write(b"HTTP/1.1 ")
            else:
                self.wfile.write(b"HTTP/1.1 202 Accepted\r\nContent-Length: 100000\r\n\r\n")
            while True:
                self.wfile.write(b"a")
                self.wfile.flush()
                time.sleep(0.05)
        except OSError:
            pass

    def log_message(self, format, *args) -> None:  # noqa: A002
        pass


class _SlowHeader(_Slow):
    stream_header = True


@pytest.mark.parametrize("handler,outcome", [(_Slow, "deposited"), (_SlowHeader, "stopped")])
def test_a_slow_endpoint_cannot_hold_a_sender_past_its_limit(contexts, handler, outcome):
    """A status is enough, so a body is never read, and an attempt has a total limit."""
    server = ThreadingHTTPServer((LOOPBACK, 0), handler)
    server.daemon_threads = True
    server.socket = contexts[0].wrap_socket(server.socket, server_side=True)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    started = time.time()
    try:
        result = _send(_url(server), b"x", contexts, stop_at=started + 0.5, backoff=0.05)
    finally:
        server.shutdown()
    assert result.outcome == outcome
    assert time.time() - started < 5


@pytest.mark.parametrize("value,pause", [
    ("7", 7.0), ("0", 1.0), ("garbage", 1.0), ("", 1.0), ("٣", 1.0), ("-5", 1.0),
    ("Fri, 01 Jan 2100 00:00:10 GMT", 10.0),
    ("Thu, 31 Dec 2099 23:59:00 GMT", 1.0),
])
def test_retry_after_seconds_and_dates(value, pause):
    now = dt.datetime(2100, 1, 1, tzinfo=dt.timezone.utc).timestamp()
    assert aun_http._pause({"retry-after": value}, 0, 1.0, now) == pause


def test_a_pause_keeps_growing_when_the_endpoint_says_zero():
    assert aun_http._pause({"retry-after": "0"}, 3, 1.0, 0.0) == 8.0


def test_a_retry_after_beyond_the_limit_stops_sending(contexts):
    server, seen = _scripted(contexts, [(429, {"Retry-After": "100000"})])
    pauses = []
    try:
        result = _send(_url(server), b"x", contexts, sleep=pauses.append,
                       stop_at=time.time() + 60)
    finally:
        server.shutdown()
    assert result.outcome == "stopped" and result.attempts == 1 and pauses == []


def _raw(inbox, contexts, head: bytes) -> bytes:
    with socket.create_connection((LOOPBACK, inbox.server_address[1])) as raw:
        with contexts[1].wrap_socket(raw, server_hostname=HOST) as tls:
            tls.sendall(head)
            return tls.recv(100)


@pytest.mark.parametrize("line", [
    b"Content-Length: 1_0", b"Content-Length: +5", b"Content-Length: -1", b"Content-Length: x",
    b"Content-Length: 1\r\nTransfer-Encoding: chunked", b"Transfer-Encoding: chunked",
    b"Content-Length: 1\r\nContent-Encoding: gzip",
])
def test_an_endpoint_refuses_unclear_framing(inbox, contexts, line):
    head = (b"POST /aun/b HTTP/1.1\r\nHost: relay.example\r\n"
            b"Content-Type: application/aun+json\r\n" + line + b"\r\n\r\nx")
    assert _raw(inbox, contexts, head).startswith(b"HTTP/1.1 400")
    assert inbox.taken == []
