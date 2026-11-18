"""证书到期巡检 API 接口层测试。

TestClient 在独立线程的独立事件循环中运行应用，因此假 DNS、TLS 目标与
静默目标都通过 lifespan 钩子在 *同一* 循环内创建。多地址场景利用
127.0.0.1 / 127.0.0.2 可绑定同一端口的回环特性。
"""

from __future__ import annotations

import asyncio
import importlib
import ssl
from contextlib import asynccontextmanager

import pytest
from fastapi.testclient import TestClient

from app.probe import dns_wire


class InLoopDns:
    def __init__(self) -> None:
        self.zones: dict[str, list[str]] = {}
        self._transport = None

    def connection_made(self, transport):  # noqa: ANN001
        self._transport = transport

    def connection_lost(self, exc) -> None:  # noqa: ANN001
        self._transport = None

    def datagram_received(self, data: bytes, addr) -> None:  # noqa: ANN001
        msg = dns_wire.parse_message(data, require_qr=False)
        q = msg.questions[0]
        if q.qname.lower() in self.zones:
            reply = dns_wire.build_response(msg.qid, q, answers=self.zones[q.qname.lower()])
        else:
            reply = dns_wire.build_response(
                msg.qid, q, rcode=dns_wire.RCODE_NAME_ERROR
            )
        self._transport.sendto(reply, addr)


class InLoopTls:
    """TLS 目标：完成握手后只读到 EOF，记录是否收到应用层字节。"""

    def __init__(self, certfile, keyfile) -> None:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(str(certfile), str(keyfile))
        self._ctx = ctx
        self.connections = 0
        self.received: list[bytes] = []
        self._server = None
        self.port = 0

    async def _handle(self, reader, writer):  # noqa: ANN001
        self.connections += 1
        try:
            data = await reader.read()
            self.received.append(data)
        except (ConnectionError, ssl.SSLError):
            pass
        finally:
            try:
                writer.close()
                await writer.wait_closed()
            except OSError:
                pass

    async def start(self) -> None:
        self._server = await asyncio.start_server(
            self._handle, "127.0.0.1", 0, ssl=self._ctx
        )
        self.port = self._server.sockets[0].getsockname()[1]

    async def stop(self) -> None:
        self._server.close()
        await self._server.wait_closed()


class InLoopSilent:
    """静默目标：接受 TCP 但永不回应（模拟握手挂起的后端）。"""

    def __init__(self) -> None:
        self.connections = 0
        self.closed = 0
        self._server = None

    async def _handle(self, reader, writer):  # noqa: ANN001
        self.connections += 1
        try:
            while True:
                data = await reader.read(1024)
                if not data:
                    return
        except ConnectionError:
            pass
        finally:
            self.closed += 1
            try:
                writer.close()
                await writer.wait_closed()
            except OSError:
                pass

    async def start(self, port: int) -> None:
        self._server = await asyncio.start_server(self._handle, "127.0.0.2", port)

    async def stop(self) -> None:
        self._server.close()
        await self._server.wait_closed()


@pytest.fixture()
def cert_client(monkeypatch, demo_certs):
    certfile, keyfile, cafile = demo_certs
    dns = InLoopDns()
    tls = InLoopTls(certfile, keyfile)
    silent = InLoopSilent()

    import app.probe.main as main_mod

    @asynccontextmanager
    async def test_lifespan(app):
        loop = asyncio.get_running_loop()
        transport, _ = await loop.create_datagram_endpoint(
            lambda: dns, local_addr=("127.0.0.1", 0)
        )
        dns._transport = transport
        dns_port = transport.get_extra_info("socket").getsockname()[1]
        await tls.start()
        await silent.start(tls.port)  # 127.0.0.2 上的同端口静默后端

        monkeypatch.setenv("ALLOWED_CIDRS", "127.0.0.0/24")
        monkeypatch.setenv("DNS_SERVER", "127.0.0.1")
        monkeypatch.setenv("DNS_PORT", str(dns_port))
        monkeypatch.setenv("DNS_RETRIES", "0")
        monkeypatch.setenv("DNS_TIMEOUT", "2.0")
        monkeypatch.setenv("CA_BUNDLE", str(cafile))
        monkeypatch.setenv("CONNECT_TIMEOUT", "3.0")
        monkeypatch.setenv("READ_TIMEOUT", "5.0")
        monkeypatch.setenv("TLS_TIMEOUT", "30.0")
        # 总时限 2s：正常用例毫秒级完成；超时用例在 2s 到点
        monkeypatch.setenv("PROBE_OVERALL_TIMEOUT", "2.0")

        import app.probe.config as config_mod
        import app.probe.dns_client as dns_client_mod

        importlib.reload(config_mod)
        importlib.reload(dns_client_mod)
        importlib.reload(main_mod)
        main_mod.app.router.lifespan_context = test_lifespan
        try:
            yield
        finally:
            transport.close()
            await tls.stop()
            await silent.stop()

    main_mod.app.router.lifespan_context = test_lifespan
    with TestClient(main_mod.app) as c:
        c._dns = dns
        c._tls = tls
        c._silent = silent
        yield c


def test_cert_scan_ok_no_http_bytes(cert_client):
    port = cert_client._tls.port
    cert_client._dns.zones = {"https.allowed.demo.test": ["127.0.0.1"]}
    r = cert_client.post(
        "/api/v1/cert-scan",
        json={"url": f"https://https.allowed.demo.test:{port}/", "warn_days": 30},
    )
    assert r.status_code == 200
    body = r.json()
    assert body["outcome"] == "ok"
    assert body["hostname"] == "https.allowed.demo.test"
    assert body["port"] == port
    assert body["resolved_addresses"] == ["127.0.0.1"]
    assert body["approved_addresses"] == ["127.0.0.1"]
    assert len(body["addresses"]) == 1
    addr = body["addresses"][0]
    assert addr["status"] == "ok"
    assert addr["not_after"] is not None
    assert addr["days_remaining"] > 30
    assert addr["tls_version"].startswith("TLS")
    # 只握手、未发送任何 HTTP 字节
    assert cert_client._tls.received == [b""]


def test_cert_scan_default_warn_days(cert_client):
    port = cert_client._tls.port
    cert_client._dns.zones = {"https.allowed.demo.test": ["127.0.0.1"]}
    r = cert_client.post(
        "/api/v1/cert-scan",
        json={"url": f"https://https.allowed.demo.test:{port}/"},
    )
    assert r.status_code == 200
    assert r.json()["warn_days"] == 30


def test_cert_scan_expiring(cert_client):
    port = cert_client._tls.port
    cert_client._dns.zones = {"https.allowed.demo.test": ["127.0.0.1"]}
    # 演示证书为长期证书，阈值调到 4000 天 -> 临期
    r = cert_client.post(
        "/api/v1/cert-scan",
        json={"url": f"https://https.allowed.demo.test:{port}/", "warn_days": 4000},
    )
    body = r.json()
    assert body["outcome"] == "expiring"
    assert body["addresses"][0]["status"] == "expiring"
    assert "临期" in body["summary"]


def test_cert_scan_blocked_no_connection(cert_client):
    cert_client._dns.zones = {"cert-bad.test": ["8.8.8.8"]}
    r = cert_client.post(
        "/api/v1/cert-scan",
        json={"url": "https://cert-bad.test/", "warn_days": 30},
    )
    assert r.status_code == 200
    body = r.json()
    assert body["outcome"] == "blocked"
    assert body["approved_addresses"] == []
    assert body["addresses"] == []
    assert cert_client._tls.connections == 0  # 未发起任何连接


def test_cert_scan_mixed_resolution_blocked(cert_client):
    cert_client._dns.zones = {"cert-mix.test": ["127.0.0.1", "8.8.8.8"]}
    body = cert_client.post(
        "/api/v1/cert-scan", json={"url": "https://cert-mix.test/"}
    ).json()
    assert body["outcome"] == "blocked"
    assert body["resolved_addresses"] == ["127.0.0.1", "8.8.8.8"]
    assert cert_client._tls.connections == 0


def test_cert_scan_timeout_marks_unknown(cert_client):
    port = cert_client._tls.port
    # 同一域名两个后端：127.0.0.1 正常 TLS，127.0.0.2 静默挂起
    cert_client._dns.zones = {"multi-a.demo.test": ["127.0.0.1", "127.0.0.2"]}
    r = cert_client.post(
        "/api/v1/cert-scan",
        json={"url": f"https://multi-a.demo.test:{port}/", "warn_days": 30},
    )
    assert r.status_code == 200  # 到点不报错，保留已核验结果
    body = r.json()
    assert body["outcome"] == "timeout"
    assert len(body["addresses"]) == 2
    by_addr = {a["address"]: a for a in body["addresses"]}
    assert by_addr["127.0.0.1"]["status"] == "ok"
    assert by_addr["127.0.0.1"]["not_after"] is not None
    assert by_addr["127.0.0.2"]["status"] == "unknown"
    assert by_addr["127.0.0.2"]["not_after"] is None
    # 整次耗时受既有总时限约束（2s + 关闭余量）
    assert body["elapsed_ms"] < 5000
    # 被取消的连接已关闭
    assert cert_client._silent.closed == 1


def test_cert_scan_http_url_422(cert_client):
    r = cert_client.post(
        "/api/v1/cert-scan", json={"url": "http://allowed.demo.test/"}
    )
    assert r.status_code == 422


def test_cert_scan_warn_days_validation(cert_client):
    assert cert_client.post(
        "/api/v1/cert-scan",
        json={"url": "https://x.test/", "warn_days": -1},
    ).status_code == 422
    assert cert_client.post(
        "/api/v1/cert-scan",
        json={"url": "https://x.test/", "warn_days": 40000},
    ).status_code == 422


def test_cert_scan_in_openapi_docs(cert_client):
    spec = cert_client.get("/openapi.json").json()
    assert "/api/v1/cert-scan" in spec["paths"]
    assert "/api/v1/probe" in spec["paths"]  # 原探测接口保留
    assert cert_client.get("/docs").status_code == 200
