"""证书到期巡检：对同一 HTTPS 域名的全部已批准地址逐址核验 TLS 证书。

与出站探测共用同一套安全模型：

  URL 静态校验（仅 https）→ 只问配置的解析器 → 一次 DNS 应答的 *全部*
  IPv4 地址过 CIDR 白名单（全或无）→ 仅向已批准 IP 建 TCP（运行时不再
  解析）→ 按原域名做 SNI 并强制校验证书 → 读取证书到期时间 → 关闭连接

关键差异与保证：
* 只做 TLS 握手读取证书，**绝不发送任何 HTTP 请求**；
* 逐址核验：任一地址临期或握手失败，整体都不能判定为安全；
* 整次巡检受既有总时限（PROBE_OVERALL_TIMEOUT）约束：到点保留已核验
  结果，未完成地址标为 ``unknown``；
* 每个地址的核验无论成功、失败还是被取消，都会关闭所属连接。
"""

from __future__ import annotations

import asyncio
import ipaddress
import ssl
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone

from .connection import build_ssl_context, close_writer, open_tcp, start_tls
from .dns_client import DnsResolver
from .policy import (
    AddressPolicy,
    PolicyError,
    is_ip_literal,
    parse_target,
)

DEFAULT_HTTPS_PORT = 443
SECONDS_PER_DAY = 86400.0


@dataclass
class AddressCertReport:
    """单个地址的证书核验结果。"""

    address: str
    status: str = "unknown"  # ok | expiring | error | unknown
    not_after: str | None = None  # 证书到期时间（ISO8601 UTC）
    days_remaining: float | None = None  # 距到期剩余天数
    tls_version: str | None = None
    cipher: str | None = None
    subject: str | None = None
    error: str | None = None  # 连接/TLS 失败原因
    note: str | None = None  # unknown 等状态的补充说明


@dataclass
class CertScanReport:
    """一次证书巡检的完整报告。"""

    url: str
    hostname: str
    port: int
    warn_days: int
    resolved_addresses: list[str] = field(default_factory=list)
    approved_addresses: list[str] = field(default_factory=list)
    addresses: list[AddressCertReport] = field(default_factory=list)
    outcome: str = "ok"  # ok | expiring | error | timeout | blocked
    summary: str = ""
    reject_reason: str | None = None


class CertChecker:
    """证书到期巡检器。配置与出站探测同源（解析器、白名单、CA、超时）。"""

    def __init__(
        self,
        policy: AddressPolicy,
        resolver: DnsResolver,
        ca_bundle: str | None = None,
        connect_timeout: float = 5.0,
        tls_timeout: float = 8.0,
        overall_timeout: float = 30.0,
    ) -> None:
        self._policy = policy
        self._resolver = resolver
        self._ssl = build_ssl_context(ca_bundle)
        self._connect_timeout = connect_timeout
        self._tls_timeout = tls_timeout
        self._overall_timeout = overall_timeout

    async def scan(self, url: str, warn_days: int) -> CertScanReport:
        """巡检指定 https URL 的全部已批准地址的证书到期时间。

        入口级静态错误（非法 URL、非 https scheme）抛 PolicyError，由 API
        层转成 422；策略拒绝与 DNS 失败以 outcome=blocked 返回（未产生任何
        连接）；到达总时限以 outcome=timeout 返回，未完成地址标 unknown。
        """
        # 1) 静态校验（不产生流量）
        scheme, host, port, _user, raw = parse_target(url)
        if scheme != "https":
            raise PolicyError(
                f"证书巡检仅支持 https URL，收到 scheme: {scheme!r}"
            )
        port = port or DEFAULT_HTTPS_PORT
        report = CertScanReport(url=raw, hostname=host, port=port, warn_days=warn_days)

        loop = asyncio.get_running_loop()
        # 既有总时限：与出站探测共用 PROBE_OVERALL_TIMEOUT
        deadline = loop.time() + self._overall_timeout

        # 2) 解析 + 白名单：IP 字面量直接校验；域名只问配置的解析器。
        #    一次应答的全部 IPv4 地址必须全部获准，否则整体拒绝（全或无）。
        try:
            if is_ip_literal(host):
                resolved = [host]
            else:
                resolved = await asyncio.wait_for(
                    self._resolver.resolve_a(host),
                    timeout=max(0.05, deadline - loop.time()),
                )
            report.resolved_addresses = list(resolved)
            approved = self._policy.check_resolved(resolved)
            report.approved_addresses = [str(ip) for ip in approved]
        except asyncio.TimeoutError:
            report.outcome = "timeout"
            report.summary = (
                f"DNS 解析在总时限（{self._overall_timeout}s）内未完成，"
                "未发起任何连接"
            )
            return report
        except PolicyError as exc:  # DnsError 是 PolicyError 子类
            report.outcome = "blocked"
            report.reject_reason = str(exc)
            report.summary = f"目标未通过策略校验，未发起任何连接: {exc}"
            return report

        # 3) 逐址核验：每个已批准地址各试一次，绝不重新解析；
        #    到达总时限即停止，未完成地址标 unknown，已核验结果保留。
        results: list[AddressCertReport] = []
        for idx, ip in enumerate(approved):
            remaining = deadline - loop.time()
            if remaining <= 0:
                results.extend(self._unknown_rest(approved[idx:]))
                break
            try:
                result = await asyncio.wait_for(
                    self._check_one(ip, port, host, warn_days),
                    timeout=remaining,
                )
            except asyncio.TimeoutError:
                results.append(self._unknown_one(ip))
                results.extend(self._unknown_rest(approved[idx + 1:]))
                break
            results.append(result)
        report.addresses = results
        report.outcome, report.summary = self._verdict(results, warn_days)
        return report

    async def _check_one(
        self,
        ip: ipaddress.IPv4Address,
        port: int,
        hostname: str,
        warn_days: int,
    ) -> AddressCertReport:
        """对单个已批准地址做 TLS 核验：握手、按原域名校验、取到期时间。

        不发送任何 HTTP 请求；无论成功、失败还是被外层取消，都在 finally
        中关闭所属连接。
        """
        address = str(ip)
        writer = None
        try:
            _reader, writer, _peer = await open_tcp(ip, port, self._connect_timeout)
            _reader, writer, tls_info = await start_tls(
                writer, _reader, hostname, self._ssl, self._tls_timeout
            )
            ssl_obj = writer.get_extra_info("ssl_object")
            if ssl_obj is None:  # 防御：start_tls 已保证，这里兜底
                raise PolicyError("TLS 启动后未取得 SSL 对象")
            cert = ssl_obj.getpeercert()
            not_after_ts = ssl.cert_time_to_seconds(cert["notAfter"])
            days_remaining = (not_after_ts - time.time()) / SECONDS_PER_DAY
            status = "expiring" if days_remaining <= warn_days else "ok"
            return AddressCertReport(
                address=address,
                status=status,
                not_after=datetime.fromtimestamp(
                    not_after_ts, tz=timezone.utc
                ).isoformat(),
                days_remaining=round(days_remaining, 2),
                tls_version=tls_info.version,
                cipher=tls_info.cipher,
                subject=tls_info.subject,
            )
        except PolicyError as exc:
            # 连接失败 / TLS 握手失败 / 证书校验失败：该地址判 error
            return AddressCertReport(address=address, status="error", error=str(exc))
        finally:
            # 成功、失败、被取消都要关闭所属连接；start_tls 取消后
            # wait_closed 可能不返回，close_writer 内部有界等待
            await close_writer(writer)

    def _unknown_one(self, ip: ipaddress.IPv4Address) -> AddressCertReport:
        return AddressCertReport(
            address=str(ip),
            status="unknown",
            note=f"到达总时限（{self._overall_timeout}s），该地址核验中断",
        )

    def _unknown_rest(
        self, ips: list[ipaddress.IPv4Address]
    ) -> list[AddressCertReport]:
        return [
            AddressCertReport(
                address=str(ip),
                status="unknown",
                note=f"到达总时限（{self._overall_timeout}s），未完成核验",
            )
            for ip in ips
        ]

    @staticmethod
    def _verdict(
        results: list[AddressCertReport], warn_days: int
    ) -> tuple[str, str]:
        """汇总整体结论：任一地址非 ok，整体都不能报告安全。"""
        total = len(results)
        if total == 0:
            return "error", "没有可核验的地址"
        unknown = [a for a in results if a.status == "unknown"]
        errors = [a for a in results if a.status == "error"]
        expiring = [a for a in results if a.status == "expiring"]
        if unknown:
            return "timeout", (
                f"到达总时限：{len(unknown)}/{total} 个地址未完成核验"
                f"（标为 unknown），已核验 {total - len(unknown)} 个；"
                "整体不能判定为安全"
            )
        if errors:
            addrs = ", ".join(a.address for a in errors)
            return "error", (
                f"{len(errors)}/{total} 个地址 TLS 核验失败（{addrs}）；"
                "整体不能判定为安全"
            )
        if expiring:
            addrs = ", ".join(
                f"{a.address}（剩 {a.days_remaining} 天）" for a in expiring
            )
            return "expiring", (
                f"{len(expiring)}/{total} 个地址证书临期"
                f"（阈值 {warn_days} 天）：{addrs}；整体不能判定为安全"
            )
        earliest = min(results, key=lambda a: a.days_remaining or 0)
        return "ok", (
            f"全部 {total} 个地址证书核验通过；最早到期 {earliest.not_after}"
            f"（剩 {earliest.days_remaining} 天，阈值 {warn_days} 天）"
        )
