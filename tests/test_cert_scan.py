"""证书到期巡检引擎测试（真实本地 DNS / TCP / TLS）。

覆盖需求关键点：
* 同一次 DNS 应答的全部 IPv4 地址过白名单后才逐址核验（全或无）；
* 逐址按原域名校验证书并报告到期时间，不发送任何 HTTP 请求；
* 任一地址临期或握手失败，整体都不能报告安全；
* 到达既有总时限时保留已核验结果，未完成地址标 unknown；
* 失败或取消后关闭所属连接。

多地址场景利用 Linux 回环特性：127.0.0.1 与 127.0.0.2 可绑定同一端口，
从而一个 URL（一个端口）即可覆盖两台“后端服务器”。
"""

from __future__ import annotations

import asyncio
import datetime
import ssl
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from app.probe.cert_scan import CertChecker
from app.probe.dns_client import DnsResolver
from app.probe.policy import AddressPolicy, PolicyError


async def start_tls_server(host: str, certfile, keyfile, port: int = 0):
    """在指定回环地址上启动 TLS 服务，记录连接与收到的应用层字节。"""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(str(certfile), str(keyfile))
    stats = {"opened": 0, "closed": 0, "received": []}

    async def handle(reader, writer):  # noqa: ANN001
        stats["opened"] += 1
        try:
            # 巡检不应发送任何应用层数据；读到 EOF 即对端关闭
            data = await reader.read()
            stats["received"].append(data)
        except (ConnectionError, ssl.SSLError):
            pass
        finally:
            stats["closed"] += 1
            try:
                writer.close()
                await writer.wait_closed()
            except OSError:
                pass

    server = await asyncio.start_server(handle, host, port, ssl=ctx)
    real_port = server.sockets[0].getsockname()[1]
    return server, real_port, stats


async def start_raw_server(host: str, responder, port: int = 0):
    """启动裸 TCP 服务；responder(reader, writer) 自定义行为。"""
    stats = {"opened": 0, "closed": 0}

    async def handle(reader, writer):  # noqa: ANN001
        stats["opened"] += 1
        try:
            await responder(reader, writer)
        except (ConnectionError, ssl.SSLError):
            pass
        finally:
            stats["closed"] += 1
            try:
                writer.close()
                await writer.wait_closed()
            except OSError:
                pass

    server = await asyncio.start_server(handle, host, port)
    real_port = server.sockets[0].getsockname()[1]
    return server, real_port, stats


async def silent_responder(reader, writer):  # noqa: ANN001
    # 永不回应：模拟 TLS 握手挂起的后端，直到对端关闭
    while True:
        data = await reader.read(1024)
        if not data:
            return


async def garbage_responder(reader, writer):  # noqa: ANN001
    # 收到 ClientHello 后回复非 TLS 数据：模拟 TLS 握手失败的后端
    await reader.read(1024)
    writer.write(b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n")
    await writer.drain()


async def wait_for_condition(predicate, timeout: float = 3.0) -> bool:
    """轮询等待条件成立（用于断言对端连接已被关闭）。"""
    loop = asyncio.get_running_loop()
    deadline = loop.time() + timeout
    while loop.time() < deadline:
        if predicate():
            return True
        await asyncio.sleep(0.02)
    return predicate()


def issue_short_lived_cert(cafile: Path, days: int, names: list[str],
                           tmp_path: Path) -> tuple[Path, Path]:
    """用演示 CA 签发一张短期服务器证书（巡检端信任该 CA）。"""
    ca_cert = x509.load_pem_x509_certificate(cafile.read_bytes())
    ca_key = serialization.load_pem_private_key(
        (cafile.parent / "demo-ca.key.pem").read_bytes(), password=None
    )
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(
            x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, names[0])])
        )
        .issuer_name(ca_cert.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=1))
        .not_valid_after(now + datetime.timedelta(days=days))
        .add_extension(
            x509.SubjectAlternativeName([x509.DNSName(n) for n in names]),
            critical=False,
        )
        .sign(ca_key, hashes.SHA256())
    )
    cert_p = tmp_path / "short-lived.crt.pem"
    key_p = tmp_path / "short-lived.key.pem"
    cert_p.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    key_p.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption(),
        )
    )
    return cert_p, key_p


class TestCertScanCore:
    async def test_single_address_ok_no_http_request(
        self, fake_dns, https_server, make_checker
    ):
        fake_dns.set_zones({"https.allowed.demo.test": ["127.0.0.1"]})
        checker = make_checker()

        report = await checker.scan(
            f"https://https.allowed.demo.test:{https_server.port}/secure",
            warn_days=30,
        )

        assert report.outcome == "ok"
        assert report.hostname == "https.allowed.demo.test"
        assert report.resolved_addresses == ["127.0.0.1"]
        assert report.approved_addresses == ["127.0.0.1"]
        assert len(report.addresses) == 1
        addr = report.addresses[0]
        assert addr.status == "ok"
        assert addr.not_after is not None
        assert addr.days_remaining > 30  # 演示证书为长期证书
        assert addr.tls_version.startswith("TLS")
        # 关键保证：只做了 TLS 握手，目标没有收到任何 HTTP 请求
        assert https_server.requests == []

    async def test_expiring_when_within_warn_days(
        self, fake_dns, demo_certs, tmp_path, make_checker
    ):
        # 用演示 CA 签发 5 天短期证书：阈值 30 天 -> 临期
        _cert, _key, cafile = demo_certs
        cert_p, key_p = issue_short_lived_cert(
            cafile, days=5, names=["short.demo.test"], tmp_path=tmp_path
        )
        srv, port, _stats = await start_tls_server("127.0.0.1", cert_p, key_p)
        fake_dns.set_zones({"short.demo.test": ["127.0.0.1"]})
        checker = make_checker()
        try:
            report = await checker.scan(f"https://short.demo.test:{port}/", 30)
        finally:
            srv.close()
            await srv.wait_closed()

        assert report.outcome == "expiring"
        addr = report.addresses[0]
        assert addr.status == "expiring"
        assert 0 <= addr.days_remaining <= 30
        assert "临期" in report.summary

    async def test_multi_address_all_checked_no_http_bytes(
        self, fake_dns, demo_certs, make_checker
    ):
        # 同一域名指向两台后端：127.0.0.1 与 127.0.0.2 绑定同一端口
        certfile, keyfile, _cafile = demo_certs
        srv1, port, stats1 = await start_tls_server("127.0.0.1", certfile, keyfile)
        srv2, port2, stats2 = await start_tls_server(
            "127.0.0.2", certfile, keyfile, port=port
        )
        assert port2 == port
        fake_dns.set_zones({"multi-a.demo.test": ["127.0.0.1", "127.0.0.2"]})
        checker = make_checker(allowed=("127.0.0.0/24",))
        try:
            report = await checker.scan(f"https://multi-a.demo.test:{port}/", 30)
        finally:
            srv1.close()
            srv2.close()
            await asyncio.gather(srv1.wait_closed(), srv2.wait_closed())

        assert report.outcome == "ok"
        assert report.resolved_addresses == ["127.0.0.1", "127.0.0.2"]
        assert [a.address for a in report.addresses] == ["127.0.0.1", "127.0.0.2"]
        assert all(a.status == "ok" for a in report.addresses)
        assert all(a.not_after for a in report.addresses)
        # 两台后端都被逐址核验，且都只收到 TLS 握手、没有任何 HTTP 字节
        assert stats1["opened"] == 1 and stats2["opened"] == 1
        assert await wait_for_condition(
            lambda: stats1["received"] == [b""] and stats2["received"] == [b""]
        )
        # 核验完成后两个连接都被关闭
        assert await wait_for_condition(
            lambda: stats1["closed"] == 1 and stats2["closed"] == 1
        )

    async def test_one_address_handshake_failure_not_safe(
        self, fake_dns, demo_certs, make_checker
    ):
        # 127.0.0.1 正常 TLS；127.0.0.2 收到 ClientHello 回复垃圾数据
        certfile, keyfile, _cafile = demo_certs
        srv1, port, _stats1 = await start_tls_server("127.0.0.1", certfile, keyfile)
        srv2, _p2, stats2 = await start_raw_server(
            "127.0.0.2", garbage_responder, port=port
        )
        fake_dns.set_zones({"www.allowed.demo.test": ["127.0.0.1", "127.0.0.2"]})
        checker = make_checker(allowed=("127.0.0.0/24",))
        try:
            report = await checker.scan(f"https://www.allowed.demo.test:{port}/", 30)
        finally:
            srv1.close()
            srv2.close()
            await asyncio.gather(srv1.wait_closed(), srv2.wait_closed())

        assert report.outcome == "error"  # 任一地址失败即不能报告整体安全
        by_addr = {a.address: a for a in report.addresses}
        assert by_addr["127.0.0.1"].status == "ok"  # 已核验结果保留
        assert by_addr["127.0.0.2"].status == "error"
        assert "TLS" in by_addr["127.0.0.2"].error
        # 失败地址的连接也被关闭
        assert await wait_for_condition(lambda: stats2["closed"] == 1)

    async def test_overall_timeout_keeps_verified_marks_unknown(
        self, fake_dns, demo_certs, make_checker
    ):
        # 127.0.0.1 正常 TLS（快）；127.0.0.2 静默（握手挂起直到总时限）
        certfile, keyfile, _cafile = demo_certs
        srv1, port, _stats1 = await start_tls_server("127.0.0.1", certfile, keyfile)
        srv2, _p2, stats2 = await start_raw_server(
            "127.0.0.2", silent_responder, port=port
        )
        fake_dns.set_zones({"swapped.demo.test": ["127.0.0.1", "127.0.0.2"]})
        # 总时限 1s，远小于 TLS 超时 30s：第二个地址必然到点中断
        checker = make_checker(
            allowed=("127.0.0.0/24",), tls_timeout=30.0, overall_timeout=1.0
        )
        loop = asyncio.get_running_loop()
        started = loop.time()
        try:
            report = await checker.scan(f"https://swapped.demo.test:{port}/", 30)
        finally:
            srv1.close()
            srv2.close()
            await asyncio.gather(srv1.wait_closed(), srv2.wait_closed())
        elapsed = loop.time() - started

        assert report.outcome == "timeout"
        assert len(report.addresses) == 2
        by_addr = {a.address: a for a in report.addresses}
        # 已核验结果保留；未完成地址标 unknown
        assert by_addr["127.0.0.1"].status == "ok"
        assert by_addr["127.0.0.1"].not_after is not None
        assert by_addr["127.0.0.2"].status == "unknown"
        assert by_addr["127.0.0.2"].not_after is None
        assert "总时限" in by_addr["127.0.0.2"].note
        # 整次巡检受总时限约束（含关闭连接的余量）
        assert elapsed < 5.0
        # 被取消的连接已关闭：静默服务端读到 EOF
        assert await wait_for_condition(lambda: stats2["closed"] == 1)

    async def test_dns_budget_exhausted_reports_timeout(self, make_checker):
        # DNS 解析器静默（绑定但永不回应的 UDP 端口），总时限先到：
        # 不发起任何连接，整体 timeout
        _ = make_checker  # 本测试手工构造，使用静默解析器
        loop = asyncio.get_running_loop()
        transport, _ = await loop.create_datagram_endpoint(
            asyncio.DatagramProtocol, local_addr=("127.0.0.1", 0)
        )
        dns_port = transport.get_extra_info("socket").getsockname()[1]
        try:
            resolver = DnsResolver("127.0.0.1", port=dns_port, timeout=5.0, retries=0)
            checker = CertChecker(
                policy=AddressPolicy.from_cidrs(["127.0.0.1/32"]),
                resolver=resolver,
                ca_bundle=None,
                connect_timeout=1.0,
                tls_timeout=1.0,
                overall_timeout=0.2,
            )
            report = await checker.scan("https://whatever.demo.test/", 30)
        finally:
            transport.close()
        assert report.outcome == "timeout"
        assert report.addresses == []


class TestCertScanPolicy:
    async def test_non_https_url_rejected(self, make_checker):
        checker = make_checker()
        with pytest.raises(PolicyError):
            await checker.scan("http://allowed.demo.test/", warn_days=30)

    async def test_mixed_resolution_blocked_no_connections(
        self, fake_dns, https_server, make_checker
    ):
        fake_dns.set_zones({"mix.test": ["127.0.0.1", "8.8.8.8"]})
        checker = make_checker()

        report = await checker.scan(f"https://mix.test:{https_server.port}/", 30)

        assert report.outcome == "blocked"
        assert "整体拒绝" in report.reject_reason
        assert report.approved_addresses == []
        assert report.addresses == []
        assert https_server.requests == []  # 未发起任何连接

    async def test_ip_literal_denied_without_dns(self, fake_dns, make_checker):
        checker = make_checker(allowed=("10.0.0.0/8",))
        report = await checker.scan("https://127.0.0.1:8443/", 30)
        assert report.outcome == "blocked"
        assert fake_dns.queried_names == []  # IP 字面量不触发 DNS

    async def test_nxdomain_blocked(self, fake_dns, make_checker):
        fake_dns.set_zones({})
        checker = make_checker()
        report = await checker.scan("https://unknown.test/", 30)
        assert report.outcome == "blocked"
        assert "NXDOMAIN" in report.reject_reason

    async def test_untrusted_cert_is_error_not_safe(
        self, fake_dns, https_server, make_checker
    ):
        # 域名不在证书 SAN 中 -> 按原域名校验失败 -> 该地址 error
        fake_dns.set_zones({"other.test": ["127.0.0.1"]})
        checker = make_checker()
        report = await checker.scan(f"https://other.test:{https_server.port}/", 30)
        assert report.outcome == "error"
        assert report.addresses[0].status == "error"
        assert "证书校验失败" in report.addresses[0].error
