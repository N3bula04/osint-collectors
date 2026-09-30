import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Callable, List

import pytest

from osint_collectors import clock
from osint_collectors.cache import Cache
from osint_collectors.http import HttpClient


class FakeServer:
    """Local HTTP server on 127.0.0.1. `handler(path, count)` returns (status, headers, body[, delay])."""

    def __init__(self, handler: Callable):
        self.handler = handler
        self.requests: List[dict] = []
        outer = self

        class H(BaseHTTPRequestHandler):
            def do_GET(self):
                outer.requests.append({"path": self.path, "headers": dict(self.headers)})
                out = outer.handler(self.path, len(outer.requests))
                status, headers, body = out[:3]
                if len(out) > 3 and out[3]:
                    import time
                    time.sleep(out[3])
                data = body if isinstance(body, bytes) else (
                    body.encode() if isinstance(body, str) else json.dumps(body).encode())
                try:
                    self.send_response(status)
                    for k, v in headers.items():
                        self.send_header(k, v)
                    self.send_header("Content-Length", str(len(data)))
                    self.end_headers()
                    self.wfile.write(data)
                except (BrokenPipeError, ConnectionResetError):
                    pass

            def log_message(self, *a):
                pass

        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), H)
        self.httpd.daemon_threads = True
        self.url = f"http://127.0.0.1:{self.httpd.server_address[1]}/"
        self.thread = threading.Thread(target=self.httpd.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True)
        self.thread.start()

    def close(self):
        self.httpd.shutdown()
        self.httpd.server_close()


@pytest.fixture
def fake_server():
    servers = []

    def make(handler):
        s = FakeServer(handler)
        servers.append(s)
        return s
    yield make
    for s in servers:
        s.close()


@pytest.fixture
def cache(tmp_path):
    return Cache(tmp_path / "cache")


@pytest.fixture
def sleeps():
    return []


@pytest.fixture
def client(sleeps):
    return HttpClient(user_agent="osint-collectors-tests/0", sleep=sleeps.append)


@pytest.fixture(autouse=True)
def _reset_clock():
    yield
    clock.set_fixed_time(None)

