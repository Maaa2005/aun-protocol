"""Delivery over HTTP for AUN Protocol 0.4 (SPEC section 11.4), standard library only.

`deliver` is the sender and `InboxServer` an endpoint. The decisions are the plain
functions of aun_reference.py. This file adds the real connection: certificate
checks, no redirects, and the address check on the socket really used.
"""

from __future__ import annotations

import http.client
import re
import socket
import ssl
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass
from email.utils import parsedate_to_datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit

from aun_reference import address_usable, delivery_action, endpoint_usable, inbox_status

MESSAGE_TYPE = "application/aun+json"
CARD_TYPE = "application/aun-card+json"
TIMEOUT_SECONDS = 10
ATTEMPT_SECONDS = 30
MAX_PAUSE_SECONDS = 3600


@dataclass
class Delivery:
    """`outcome` is "deposited", "give_up" (a status that retrying cannot help)
    or "stopped" (the limit came while attempts were failing).

    Only "deposited" is the deposit of SPEC section 5.3.
    """

    outcome: str
    attempts: int
    status: int | None = None
    reason: str = ""


class _PinnedConnection(http.client.HTTPSConnection):
    """Connects to one checked address, and checks the certificate against the host."""

    def __init__(self, host: str, address: str, port: int, context: ssl.SSLContext) -> None:
        super().__init__(host, port, timeout=TIMEOUT_SECONDS, context=context)
        self._address = address

    def connect(self) -> None:
        raw = socket.create_connection((self._address, self.port), self.timeout)
        self.sock = raw  # `_cut` can reach it during the TLS handshake
        self.sock = self._context.wrap_socket(raw, server_hostname=self.host)


def _cut(connection: _PinnedConnection) -> None:
    """End an attempt that took too long, whatever call is waiting on the socket."""
    if connection.sock is not None:
        try:
            connection.sock.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass


def resolve(host: str, port: int) -> list[str]:
    """Every address of a host, in the order the system gives them."""
    return list(dict.fromkeys(
        info[4][0] for info in socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)))


def post_once(
    url: str, body: bytes, content_type: str, context: ssl.SSLContext,
    resolver: Callable[[str, int], list[str]] = resolve,
    allowed: Callable[[str], bool] = address_usable,
    limit: float = ATTEMPT_SECONDS,
) -> tuple[int, dict[str, str]]:
    """One POST. Raises OSError when no checked address answers.

    The name is resolved once and the socket goes to a checked address, so a
    second answer from the name server cannot move the connection elsewhere.
    A redirect is returned like any other status and is not followed. The body
    of an answer is never read, and each address gets at most `limit` seconds.
    """
    parts = urlsplit(url)
    port = parts.port or 443
    addresses = [a for a in resolver(parts.hostname, port) if allowed(a)]
    if not addresses:
        raise OSError(f"no usable address for {parts.hostname}")
    target = parts.path or "/"
    if parts.query:
        target += "?" + parts.query
    last: OSError = OSError("no address tried")
    for address in addresses:
        connection = _PinnedConnection(parts.hostname, address, port, context)
        timer = threading.Timer(limit, _cut, [connection])
        timer.start()
        try:
            connection.request("POST", target, body, {"Content-Type": content_type})
            response = connection.getresponse()
            return response.status, {k.lower(): v for k, v in response.getheaders()}
        except (OSError, http.client.HTTPException) as exc:
            last = OSError(str(exc))
        finally:
            timer.cancel()
            connection.close()
    raise last


def _asked(headers: dict[str, str], now: float) -> float:
    """The seconds `Retry-After` asks for, as a number or a date. 0 if none or unreadable."""
    value = headers.get("retry-after", "")
    if value.isascii() and value.isdigit():
        return float(value)
    try:
        return parsedate_to_datetime(value).timestamp() - now
    except (TypeError, ValueError):
        return 0.0


def _pause(headers: dict[str, str], attempt: int, backoff: float, now: float) -> float:
    """What the endpoint asked for, and never less than a pause that keeps growing."""
    return max(_asked(headers, now), min(backoff * 2 ** attempt, MAX_PAUSE_SECONDS))


def deliver(
    url: str, body: bytes, stop_at: float, *, content_type: str = MESSAGE_TYPE,
    context: ssl.SSLContext | None = None, backoff: float = 1.0,
    resolver: Callable[[str, int], list[str]] = resolve,
    allowed: Callable[[str], bool] = address_usable,
    clock: Callable[[], float] = time.time, sleep: Callable[[float], None] = time.sleep,
) -> Delivery:
    """Send the identical bytes until a deposit, a refusal, or `stop_at`.

    `stop_at` is a Unix time: `expires_at` + 300 seconds for a message. For a
    card the sender chooses a limit. A certificate that fails counts as a failed
    connection: nothing was sent, and a later attempt may meet a repaired one.
    An endpoint that asks for a pause beyond `stop_at` ends the sending.
    """
    if not endpoint_usable(url):
        return Delivery("give_up", 0, reason="endpoint not usable")
    context = context or ssl.create_default_context()
    attempts = 0
    status = None
    reason = ""
    while clock() <= stop_at:
        headers: dict[str, str] = {}
        attempts += 1
        try:
            limit = min(ATTEMPT_SECONDS, max(stop_at - clock(), 0.05))
            status, headers = post_once(url, body, content_type, context, resolver, allowed,
                                        limit)
            reason = f"status {status}"
            action = delivery_action(status)
            if action != "retry":
                return Delivery(action, attempts, status, reason)
        except OSError as exc:
            status, reason = None, str(exc)
        now = clock()
        remaining = stop_at - now
        if remaining <= 0.05 or _asked(headers, now) > remaining:
            break
        sleep(min(_pause(headers, attempts - 1, backoff, now), remaining - 0.05))
    return Delivery("stopped", attempts, status, reason or "out of time")


class InboxServer(ThreadingHTTPServer):
    """An endpoint: keeps what it takes in `taken`, in order of arrival."""

    def __init__(self, address: tuple[str, int], context: ssl.SSLContext) -> None:
        super().__init__(address, _InboxHandler)
        self.socket = context.wrap_socket(self.socket, server_side=True)
        self.taken: list[tuple[str, bytes]] = []


class _InboxHandler(BaseHTTPRequestHandler):
    server: InboxServer
    protocol_version = "HTTP/1.1"
    timeout = TIMEOUT_SECONDS

    def _answer(self, status: int) -> None:
        self.send_response(status)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def _refuse_method(self) -> None:
        self.close_connection = True
        self._answer(405)

    do_GET = do_HEAD = do_PUT = do_DELETE = do_PATCH = do_OPTIONS = _refuse_method

    def do_POST(self) -> None:  # noqa: N802
        content_type = self.headers.get("Content-Type", "")
        lengths = self.headers.get_all("Content-Length", [])
        if (len(lengths) != 1 or not re.fullmatch(r"[0-9]{1,16}", lengths[0])
                or "Content-Encoding" in self.headers or "Transfer-Encoding" in self.headers):
            self.close_connection = True
            self._answer(400)
            return
        size = int(lengths[0])
        status = inbox_status("POST", content_type, size)
        if status != 202:
            self.close_connection = True  # the body is not read
            self._answer(status)
            return
        body = self.rfile.read(size)
        self.server.taken.append((content_type, body))
        self._answer(202)

    def log_message(self, format: str, *args: object) -> None:  # noqa: A002
        pass
