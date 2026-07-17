#!/usr/bin/env python3
"""Summarize GlobalProtect connection attempts from a macOS log dump.

The parser accepts either a GlobalProtect .tgz/.tar.gz support bundle or an
already-extracted directory. It reads PanGPS logs, groups related portal/SAML/
gateway activity into connection attempts, and writes CSV and JSON reports.

No third-party packages are required.
"""

from __future__ import annotations

import argparse
import csv
import ipaddress
import json
import re
import sys
import tarfile
import tempfile
from dataclasses import asdict, dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Iterable, Iterator, Optional


PARSER_VERSION = "2.0.0"


LOG_LINE_RE = re.compile(
    r"^[^P\r\n]{0,3}P(?P<pid>\d+)-T(?P<tid>\d+)\s+"
    r"(?P<date>\d{2}/\d{2}/\d{4})\s+"
    r"(?P<time>\d{2}:\d{2}:\d{2}:\d{3})\s+"
    r"(?P<level>[A-Za-z]+)\s*\(\s*(?P<code>\d+)\):\s?(?P<message>.*)$"
)

SENSITIVE_XML_RE = re.compile(
    r"<(?:saml-request|prelogin-cookie|authcookie|portal-userauthcookie)[^>]*>.*",
    re.IGNORECASE,
)

RELEVANT_TIMELINE_PATTERNS = (
    "msgtype = portal",
    "portal processing starts",
    "portal pre-login starts",
    "portal prelogin starts",
    "portal login starts",
    "portal auth method:",
    "prelogin to portal result",
    "gateway pre-login starts",
    "gateway prelogin starts",
    "gateway login starts",
    "gateway auth method:",
    "received challenge nsurlauthenticationmethodclientcertificate",
    "user identity subs:",
    "system identity subs:",
    "found ",
    "final identity:",
    "ssl_connect: write client certificate",
    "auth failed",
    "authentication failed",
    "invalid-gateway-credential",
    "unserialized non-empty cookie",
    "auth cookie is not empty",
    "actual user for gateway login is",
    "set state to retrieving configuration",
    "set state to connecting",
    "set state to connected",
    "set state to disconnected",
    "vpn tunnel is connected",
    "tunnel to ",
    "saml-pre-login",
    "saml-auth-status",
    "certificate-store-lookup",
)


@dataclass
class LogEntry:
    timestamp: datetime
    level: str
    message: str
    source_file: str
    source_line: int
    pid: str
    tid: str

    @property
    def location(self) -> str:
        return f"{self.source_file}:{self.source_line}"


@dataclass
class CertificateExchange:
    phase: str
    timestamp: str
    source: str
    thread_id: str
    user_identities: list[str] = field(default_factory=list)
    system_identities: list[str] = field(default_factory=list)
    matching_identity_count: Optional[int] = None
    selected_identity: Optional[str] = None
    selected_store: str = "unknown"
    selection_status: str = "not-selected"
    selection_error: Optional[str] = None
    keychain_locked: bool = False


@dataclass
class TimelineEvent:
    timestamp: str
    phase: str
    event: str
    source: str


@dataclass
class ConnectionAttempt:
    attempt_id: int
    start_time: datetime
    start_source: str
    end_time: Optional[datetime] = None
    end_source: Optional[str] = None
    portal: Optional[str] = None
    gateway: Optional[str] = None
    gateway_ip: Optional[str] = None
    username: Optional[str] = None
    mode: Optional[str] = None
    certificate_store_lookup: Optional[str] = None
    portal_auth_method: Optional[str] = None
    portal_auth_source: Optional[str] = None
    gateway_auth_method: Optional[str] = None
    gateway_auth_source: Optional[str] = None
    auth_cookie_used: bool = False
    saml_used: bool = False
    saml_waiting: bool = False
    state_retrieving_config: bool = False
    state_connecting: bool = False
    state_connected: bool = False
    tunnel_connected: bool = False
    client_certificate_write_count: int = 0
    certificate_exchanges: list[CertificateExchange] = field(default_factory=list)
    auth_failures: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    timeline: list[TimelineEvent] = field(default_factory=list)
    last_event_time: Optional[datetime] = None
    phase: str = "portal"

    def add_timeline(self, entry: LogEntry, event: str, phase: Optional[str] = None) -> None:
        self.last_event_time = entry.timestamp
        self.timeline.append(
            TimelineEvent(
                timestamp=format_dt(entry.timestamp),
                phase=phase or self.phase,
                event=compact_text(event),
                source=entry.location,
            )
        )

    def final_status(self) -> str:
        if self.state_connected or self.tunnel_connected:
            return "connected"
        if self.auth_failures:
            return "failed"
        if self.state_connecting or self.state_retrieving_config:
            return "incomplete"
        return "unknown"

    def duration_seconds(self) -> Optional[float]:
        endpoint = self.end_time or self.last_event_time
        if not endpoint:
            return None
        return round((endpoint - self.start_time).total_seconds(), 3)

    def selected_identities(self, phase: Optional[str] = None) -> list[str]:
        values: list[str] = []
        for exchange in self.certificate_exchanges:
            if phase and exchange.phase != phase:
                continue
            if exchange.selected_identity and exchange.selected_identity not in values:
                values.append(exchange.selected_identity)
        return values

    def selected_identity_sequence(self) -> list[str]:
        values: list[str] = []
        for exchange in self.certificate_exchanges:
            if exchange.selected_identity:
                values.append(exchange.selected_identity)
        return values

    def selected_identity_transition(self) -> list[str]:
        values: list[str] = []
        for identity in self.selected_identity_sequence():
            if not values or values[-1] != identity:
                values.append(identity)
        return values

    def final_selected_exchange(self, phase: Optional[str] = None) -> Optional[CertificateExchange]:
        for exchange in reversed(self.certificate_exchanges):
            if phase and exchange.phase != phase:
                continue
            if exchange.selected_identity and exchange.selection_status != "unusable":
                return exchange
        return None

    def successful_path_exchange(self) -> Optional[CertificateExchange]:
        if self.final_status() != "connected":
            return None
        return self.final_selected_exchange("gateway") or self.final_selected_exchange()

    def successful_certificate_identity(self) -> Optional[str]:
        exchange = self.successful_path_exchange()
        return exchange.selected_identity if exchange else None

    def successful_certificate_store(self) -> Optional[str]:
        exchange = self.successful_path_exchange()
        return exchange.selected_store if exchange else None

    def connected_after_retry(self) -> bool:
        return self.final_status() == "connected" and bool(self.auth_failures)

    def certificate_selection_failures(self) -> list[str]:
        values: list[str] = []
        for exchange in self.certificate_exchanges:
            if exchange.selection_error:
                message = (
                    f"{exchange.phase} identity {exchange.selected_identity or 'unknown'}: "
                    f"{exchange.selection_error}"
                )
                add_unique(values, message)
        return values

    def certificate_selection_recovered(self) -> bool:
        return bool(
            self.certificate_selection_failures()
            and self.final_status() == "connected"
            and self.successful_path_exchange()
        )

    def observed_identity_store(self, identity: Optional[str]) -> str:
        if not identity:
            return "none"
        user_identities: list[str] = []
        system_identities: list[str] = []
        for exchange in self.certificate_exchanges:
            for value in exchange.user_identities:
                add_unique(user_identities, value)
            for value in exchange.system_identities:
                add_unique(system_identities, value)
        return determine_identity_store(identity, user_identities, system_identities)

    def identity_stores_selected(self) -> list[str]:
        stores: list[str] = []
        for exchange in self.certificate_exchanges:
            if exchange.selected_identity and exchange.selected_store not in stores:
                stores.append(exchange.selected_store)
        return stores

    def machine_certificate_selected(self) -> bool:
        return any(
            exchange.selected_identity
            and exchange.selected_store == "machine"
            and exchange.selection_status != "unusable"
            for exchange in self.certificate_exchanges
        )

    def user_certificate_selected(self) -> bool:
        return any(
            exchange.selected_identity
            and exchange.selected_store == "user"
            and exchange.selection_status != "unusable"
            for exchange in self.certificate_exchanges
        )

    def machine_certificate_selection_attempted(self) -> bool:
        return any(
            exchange.selected_identity and exchange.selected_store == "machine"
            for exchange in self.certificate_exchanges
        )

    def user_certificate_selection_attempted(self) -> bool:
        return any(
            exchange.selected_identity and exchange.selected_store == "user"
            for exchange in self.certificate_exchanges
        )

    def certificate_summary(self) -> str:
        if not self.certificate_exchanges:
            return "not requested"
        selected = self.selected_identities()
        if selected:
            return ", ".join(selected)
        return "requested; no identity selected"

    def successful_certificate_summary(self) -> str:
        identity = self.successful_certificate_identity()
        store = self.successful_certificate_store()
        if identity:
            return f"{identity} ({store or 'unknown'})"
        if self.certificate_exchanges:
            return "no usable identity confirmed on successful path"
        return "not observed"


class GlobalProtectParser:
    def __init__(self, entries: list[LogEntry]) -> None:
        self.entries = entries
        self.attempts: list[ConnectionAttempt] = []
        self.current: Optional[ConnectionAttempt] = None
        self.last_certificate_exchange: Optional[CertificateExchange] = None
        self.certificate_exchanges_by_tid: dict[str, CertificateExchange] = {}

    def parse(self) -> list[ConnectionAttempt]:
        for entry in self.entries:
            text = entry.message
            lower = text.lower()

            if "msgtype = portal" in lower:
                self._handle_portal_message(entry)
                continue

            if self.current is None:
                if "--set state to retrieving configuration" in lower:
                    self._start_attempt(entry, inferred=True)
                else:
                    continue

            assert self.current is not None
            self._consume(entry)

            # A connection attempt ends when GlobalProtect reaches Connected.
            # Subsequent disconnects, HIP activity, and periodic portal refreshes
            # belong to the established session or to a later attempt.
            if self.current is not None and self.current.state_connected:
                self._finalize_current()

        self._finalize_current()
        return self.attempts

    def _handle_portal_message(self, entry: LogEntry) -> None:
        if self.current is None:
            self._start_attempt(entry)
            return

        gap = (entry.timestamp - (self.current.last_event_time or self.current.start_time)).total_seconds()
        elapsed = (entry.timestamp - self.current.start_time).total_seconds()

        is_continuation = (
            not self.current.state_connected
            and elapsed <= 900
            and (
                self.current.saml_waiting
                or gap <= 5
                or (self.current.state_retrieving_config and gap <= 120)
            )
        )

        if is_continuation:
            self.current.phase = "portal"
            self.current.add_timeline(entry, "Portal message continuation")
            self.current.saml_waiting = False
        else:
            self._finalize_current()
            self._start_attempt(entry)

    def _start_attempt(self, entry: LogEntry, inferred: bool = False) -> None:
        attempt = ConnectionAttempt(
            attempt_id=len(self.attempts) + 1,
            start_time=entry.timestamp,
            start_source=entry.location,
            last_event_time=entry.timestamp,
        )
        attempt.add_timeline(
            entry,
            "Connection attempt inferred from retrieving configuration"
            if inferred
            else "Portal connection request received",
            phase="portal",
        )
        self.current = attempt
        self.last_certificate_exchange = None
        self.certificate_exchanges_by_tid = {}

    def _finalize_current(self) -> None:
        if self.current is None:
            return

        if self.current.end_time is None:
            self.current.end_time = self.current.last_event_time
            if self.current.timeline:
                self.current.end_source = self.current.timeline[-1].source

        # Drop empty inferred blocks that do not contain meaningful connection data.
        meaningful = any(
            (
                self.current.portal,
                self.current.gateway,
                self.current.state_connecting,
                self.current.state_connected,
                self.current.tunnel_connected,
                self.current.certificate_exchanges,
                self.current.auth_failures,
                self.current.saml_used,
            )
        )
        if meaningful:
            self.current.attempt_id = len(self.attempts) + 1
            self.attempts.append(self.current)

        self.current = None
        self.last_certificate_exchange = None
        self.certificate_exchanges_by_tid = {}

    def _consume(self, entry: LogEntry) -> None:
        attempt = self.current
        assert attempt is not None
        text = entry.message
        lower = text.lower()

        # Phase markers
        if any(
            marker in lower
            for marker in (
                "portal processing starts",
                "portal pre-login starts",
                "portal prelogin starts",
                "portal login starts",
                "prelogin to portal result",
                "portal auth method:",
            )
        ):
            attempt.phase = "portal"

        if any(
            marker in lower
            for marker in (
                "gateway pre-login starts",
                "gateway prelogin starts",
                "gateway login starts",
                "prelogin to gateway",
                "gateway auth method:",
                "actual user for gateway login",
            )
        ):
            attempt.phase = "gateway"

        # Basic connection fields
        portal_match = re.search(r"\bPortal\s+([^,\s]+),\s+user\s+([^,\s]+)", text, re.IGNORECASE)
        if portal_match:
            attempt.portal = portal_match.group(1)
            attempt.username = clean_username(portal_match.group(2))

        for tag, attr in (("portal", "portal"), ("gateway", "gateway"), ("user-name", "username")):
            tag_match = re.search(fr"<{tag}>([^<]+)</{tag}>", text, re.IGNORECASE)
            if tag_match:
                value = tag_match.group(1).strip()
                if value and value not in {"gateway-list", "___empty_username___"}:
                    setattr(attempt, attr, value)

        actual_user = re.search(r"Actual user for gateway login is\s+([^\s<]+)", text, re.IGNORECASE)
        if actual_user:
            attempt.username = clean_username(actual_user.group(1))

        tunnel_match = re.search(r"tunnel to\s+([^\s]+)\s+connected", text, re.IGNORECASE)
        if tunnel_match:
            attempt.gateway_ip = tunnel_match.group(1).rstrip(".,")
            attempt.tunnel_connected = True
            attempt.end_time = entry.timestamp
            attempt.add_timeline(entry, f"Tunnel connected to {attempt.gateway_ip}", phase="gateway")

        gateway_host = re.search(r"gateway\s+([A-Za-z0-9_.:-]+)", text, re.IGNORECASE)
        if gateway_host and "gateway list" not in lower:
            candidate = gateway_host.group(1).rstrip(".,")
            if "." in candidate and candidate.lower() not in {"login", "auth", "prelogin"}:
                host_only = candidate.rsplit(":", 1)[0] if candidate.count(":") == 1 else candidate
                if is_ip_address(host_only):
                    if not attempt.gateway_ip:
                        attempt.gateway_ip = host_only
                else:
                    attempt.gateway = candidate

        if "on-demand mode" in lower:
            attempt.mode = "On-Demand"
        elif "always-on mode" in lower:
            attempt.mode = "Always-On"

        store_match = re.search(
            r"<certificate-store-lookup>([^<]+)</certificate-store-lookup>",
            text,
            re.IGNORECASE,
        )
        if store_match:
            attempt.certificate_store_lookup = store_match.group(1).strip()
            attempt.add_timeline(
                entry,
                f"Certificate store lookup: {attempt.certificate_store_lookup}",
                phase="portal",
            )

        # Authentication method/source
        portal_auth = re.search(
            r"Portal auth method:\s*([^,\s]+),\s*auth src:\s*([^\s<]+)",
            text,
            re.IGNORECASE,
        )
        if portal_auth:
            attempt.portal_auth_method = portal_auth.group(1)
            attempt.portal_auth_source = portal_auth.group(2)
            attempt.saml_used |= attempt.portal_auth_method.lower() in {"saml", "cas"}
            attempt.add_timeline(
                entry,
                f"Portal authentication: {attempt.portal_auth_method} via {attempt.portal_auth_source}",
                phase="portal",
            )

        gateway_auth = re.search(
            r"Gateway auth method:\s*([^,\s]+),\s*auth src:\s*([^\s<]+)",
            text,
            re.IGNORECASE,
        )
        if gateway_auth:
            attempt.gateway_auth_method = gateway_auth.group(1)
            attempt.gateway_auth_source = gateway_auth.group(2)
            attempt.saml_used |= attempt.gateway_auth_method.lower() in {"saml", "cas"}
            attempt.add_timeline(
                entry,
                f"Gateway authentication: {attempt.gateway_auth_method} via {attempt.gateway_auth_source}",
                phase="gateway",
            )

        if "saml" in lower or "auth method: cas" in lower:
            attempt.saml_used = True
        if "send saml-pre-login" in lower or "<type>saml-pre-login</type>" in lower:
            attempt.saml_waiting = True
            attempt.add_timeline(entry, "Waiting for SAML authentication response")

        if "unserialized non-empty cookie" in lower or "auth cookie is not empty" in lower:
            attempt.auth_cookie_used = True
            if is_relevant_timeline(lower):
                attempt.add_timeline(entry, "Existing authentication cookie loaded")

        # Certificate selection
        if "received challenge nsurlauthenticationmethodclientcertificate" in lower:
            exchange = CertificateExchange(
                phase=attempt.phase,
                timestamp=format_dt(entry.timestamp),
                source=entry.location,
                thread_id=entry.tid,
            )
            attempt.certificate_exchanges.append(exchange)
            self.last_certificate_exchange = exchange
            self.certificate_exchanges_by_tid[entry.tid] = exchange
            attempt.add_timeline(entry, "Server requested a client certificate")

        active_exchange = (
            self.certificate_exchanges_by_tid.get(entry.tid)
            or self.last_certificate_exchange
        )

        user_identity = re.search(r'User identity subs:\s*"([^"]+)"', text, re.IGNORECASE)
        if user_identity and active_exchange:
            add_unique(active_exchange.user_identities, user_identity.group(1))
            attempt.add_timeline(entry, f"User identity available: {user_identity.group(1)}")

        system_identity = re.search(r'System identity subs:\s*"([^"]+)"', text, re.IGNORECASE)
        if system_identity and active_exchange:
            add_unique(active_exchange.system_identities, system_identity.group(1))
            attempt.add_timeline(entry, f"Machine identity available: {system_identity.group(1)}")

        matching = re.search(r"Found\s+(\d+)\s+matching keychain identities", text, re.IGNORECASE)
        if matching and active_exchange:
            active_exchange.matching_identity_count = int(matching.group(1))
            attempt.add_timeline(entry, f"Matching certificate identities: {matching.group(1)}")

        selected = re.search(r"Final identity:\s*\[([^\]]*)\]", text, re.IGNORECASE)
        if selected and active_exchange:
            identity = selected.group(1).strip() or None
            active_exchange.selected_identity = identity
            active_exchange.selected_store = determine_identity_store(
                identity,
                active_exchange.user_identities,
                active_exchange.system_identities,
            )
            if active_exchange.selected_store == "unknown":
                active_exchange.selected_store = attempt.observed_identity_store(identity)
            active_exchange.selection_status = "selected" if identity else "none"
            attempt.add_timeline(
                entry,
                f"Selected certificate identity: {identity or 'none'} "
                f"({active_exchange.selected_store})",
            )

        if "keychain with identity is locked" in lower and active_exchange:
            active_exchange.keychain_locked = True
            active_exchange.selection_status = "unusable"
            active_exchange.selection_error = "system keychain identity was locked"
            warning = (
                f"Certificate identity {active_exchange.selected_identity or 'unknown'} "
                "could not be used because its keychain was locked"
            )
            add_unique(attempt.warnings, warning)
            attempt.add_timeline(entry, warning, phase=active_exchange.phase)

        if "final identity cannot be used" in lower and active_exchange:
            active_exchange.selection_status = "unusable"
            if not active_exchange.selection_error:
                active_exchange.selection_error = "Final identity could not be used; request cancelled"
            attempt.add_timeline(
                entry,
                f"Certificate identity {active_exchange.selected_identity or 'unknown'} was rejected",
                phase=active_exchange.phase,
            )

        if "ssl_connect: write client certificate" in lower:
            attempt.client_certificate_write_count += 1
            attempt.add_timeline(entry, "TLS client certificate written", phase="gateway")

        # States and outcome
        if "--set state to retrieving configuration" in lower:
            attempt.state_retrieving_config = True
            attempt.add_timeline(entry, "State: Retrieving configuration", phase="portal")

        if "--set state to connecting" in lower:
            attempt.state_connecting = True
            attempt.phase = "gateway"
            attempt.add_timeline(entry, "State: Connecting", phase="gateway")

        if "vpn tunnel is connected" in lower:
            attempt.tunnel_connected = True
            attempt.end_time = entry.timestamp
            attempt.end_source = entry.location
            attempt.add_timeline(entry, "VPN tunnel connected", phase="gateway")

        if "--set state to connected" in lower:
            attempt.state_connected = True
            attempt.end_time = entry.timestamp
            attempt.end_source = entry.location
            attempt.add_timeline(entry, "State: Connected", phase="gateway")

        if "--set state to disconnected" in lower:
            attempt.add_timeline(entry, "State: Disconnected")

        # Failures and warnings. Keep intermediate failures even when a retry succeeds.
        if any(marker in lower for marker in ("auth failed", "authentication failed", "invalid-gateway-credential")):
            failure = extract_failure(text)
            add_unique(attempt.auth_failures, failure)
            attempt.add_timeline(entry, f"Authentication issue: {failure}")

        if "no matching keychain identities" in lower:
            warning = "No matching certificate identity was found"
            add_unique(attempt.warnings, warning)
            attempt.add_timeline(entry, warning)

        if is_relevant_timeline(lower):
            attempt.last_event_time = entry.timestamp


def iter_log_entries(path: Path) -> Iterator[LogEntry]:
    current: Optional[LogEntry] = None
    continuation: list[str] = []

    def emit() -> Optional[LogEntry]:
        nonlocal current, continuation
        if current is None:
            return None
        if continuation:
            current.message += "\n" + "\n".join(continuation)
        result = current
        current = None
        continuation = []
        return result

    with path.open("r", encoding="utf-8", errors="replace") as handle:
        for line_number, raw in enumerate(handle, start=1):
            line = raw.rstrip("\r\n")
            match = LOG_LINE_RE.match(line)
            if match:
                previous = emit()
                if previous:
                    yield previous
                timestamp = datetime.strptime(
                    f"{match.group('date')} {match.group('time')}",
                    "%m/%d/%Y %H:%M:%S:%f",
                )
                current = LogEntry(
                    timestamp=timestamp,
                    level=match.group("level"),
                    message=match.group("message"),
                    source_file=path.name,
                    source_line=line_number,
                    pid=match.group("pid"),
                    tid=match.group("tid"),
                )
                continue

            if current is not None:
                stripped = line.strip()
                if not stripped:
                    continue
                if SENSITIVE_XML_RE.search(stripped):
                    continue
                if len(stripped) > 1500:
                    continue
                # Retain useful XML fields while avoiding large response dumps.
                if stripped.startswith("<") or len(continuation) < 6:
                    continuation.append(stripped)

    previous = emit()
    if previous:
        yield previous


def discover_pangps_logs(root: Path) -> list[Path]:
    candidates = [
        path
        for path in root.rglob("*")
        if path.is_file()
        and re.fullmatch(r"PanGPS\.log(?:\.old|\.\d+)?", path.name, re.IGNORECASE)
    ]
    if not candidates:
        raise FileNotFoundError("No PanGPS.log or rotated PanGPS log was found in the input.")
    return sorted(candidates, key=lambda p: p.name)


def load_entries(root: Path) -> list[LogEntry]:
    entries: list[LogEntry] = []
    for log_path in discover_pangps_logs(root):
        entries.extend(iter_log_entries(log_path))

    entries.sort(key=lambda e: (e.timestamp, e.source_file, e.source_line))

    # Support bundles can contain overlapping rotated logs. Remove exact duplicate entries.
    deduped: list[LogEntry] = []
    seen: set[tuple[datetime, str, str]] = set()
    for entry in entries:
        key = (entry.timestamp, entry.level, entry.message)
        if key in seen:
            continue
        seen.add(key)
        deduped.append(entry)
    return deduped


def safe_extract_tar(archive: Path, destination: Path) -> None:
    destination_resolved = destination.resolve()
    with tarfile.open(archive, "r:*") as tar:
        for member in tar.getmembers():
            target = (destination / member.name).resolve()
            if destination_resolved not in target.parents and target != destination_resolved:
                raise ValueError(f"Unsafe archive member path: {member.name}")
        try:
            tar.extractall(destination, filter="data")
        except TypeError:  # Python versions before 3.12
            tar.extractall(destination)


def attempt_to_dict(attempt: ConnectionAttempt) -> dict:
    selected_exchanges = [
        exchange for exchange in attempt.certificate_exchanges if exchange.selected_identity
    ]
    initial_exchange = selected_exchanges[0] if selected_exchanges else None
    final_portal_exchange = attempt.final_selected_exchange("portal")
    final_gateway_exchange = attempt.final_selected_exchange("gateway")
    successful_exchange = attempt.successful_path_exchange()

    return {
        "attempt_id": attempt.attempt_id,
        "start_time": format_dt(attempt.start_time),
        "end_time": format_dt(attempt.end_time) if attempt.end_time else None,
        "end_source": attempt.end_source,
        "duration_seconds": attempt.duration_seconds(),
        "status": attempt.final_status(),
        "connected_after_retry": attempt.connected_after_retry(),
        "certificate_selection_recovered": attempt.certificate_selection_recovered(),
        "portal": attempt.portal,
        "gateway": attempt.gateway,
        "gateway_ip": attempt.gateway_ip,
        "username": attempt.username,
        "mode": attempt.mode,
        "certificate_store_lookup": attempt.certificate_store_lookup,
        "portal_auth_method": attempt.portal_auth_method,
        "portal_auth_source": attempt.portal_auth_source,
        "gateway_auth_method": attempt.gateway_auth_method,
        "gateway_auth_source": attempt.gateway_auth_source,
        "saml_used": attempt.saml_used,
        "auth_cookie_used": attempt.auth_cookie_used,
        "certificate_requested": bool(attempt.certificate_exchanges),
        "certificate_exchange_count": len(attempt.certificate_exchanges),
        "portal_certificate_exchange_count": sum(
            exchange.phase == "portal" for exchange in attempt.certificate_exchanges
        ),
        "gateway_certificate_exchange_count": sum(
            exchange.phase == "gateway" for exchange in attempt.certificate_exchanges
        ),
        "selected_identities": attempt.selected_identities(),
        "selected_identity_sequence": attempt.selected_identity_sequence(),
        "selected_identity_transition": attempt.selected_identity_transition(),
        "portal_selected_identities": attempt.selected_identities("portal"),
        "gateway_selected_identities": attempt.selected_identities("gateway"),
        "selected_identity_stores": attempt.identity_stores_selected(),
        "initial_selected_identity": initial_exchange.selected_identity if initial_exchange else None,
        "initial_selected_identity_store": initial_exchange.selected_store if initial_exchange else None,
        "initial_selected_identity_status": initial_exchange.selection_status if initial_exchange else None,
        "final_portal_selected_identity": (
            final_portal_exchange.selected_identity if final_portal_exchange else None
        ),
        "final_portal_selected_identity_store": (
            final_portal_exchange.selected_store if final_portal_exchange else None
        ),
        "final_gateway_selected_identity": (
            final_gateway_exchange.selected_identity if final_gateway_exchange else None
        ),
        "final_gateway_selected_identity_store": (
            final_gateway_exchange.selected_store if final_gateway_exchange else None
        ),
        "successful_path_certificate_identity": (
            successful_exchange.selected_identity if successful_exchange else None
        ),
        "successful_path_certificate_store": (
            successful_exchange.selected_store if successful_exchange else None
        ),
        "successful_path_certificate_phase": (
            successful_exchange.phase if successful_exchange else None
        ),
        "successful_machine_certificate": bool(
            successful_exchange and successful_exchange.selected_store == "machine"
        ),
        "successful_user_certificate": bool(
            successful_exchange and successful_exchange.selected_store == "user"
        ),
        "machine_certificate_selection_attempted": (
            attempt.machine_certificate_selection_attempted()
        ),
        "user_certificate_selection_attempted": attempt.user_certificate_selection_attempted(),
        "machine_certificate_selected": attempt.machine_certificate_selected(),
        "user_certificate_selected": attempt.user_certificate_selected(),
        "client_certificate_write_count": attempt.client_certificate_write_count,
        "tunnel_connected": attempt.tunnel_connected,
        "auth_failures": attempt.auth_failures,
        "certificate_selection_failures": attempt.certificate_selection_failures(),
        "warnings": attempt.warnings,
        "certificate_exchanges": [asdict(item) for item in attempt.certificate_exchanges],
        "timeline": [asdict(item) for item in attempt.timeline],
        "start_source": attempt.start_source,
    }


def write_json(attempts: list[ConnectionAttempt], destination: Path, source: Path) -> None:
    status_counts: dict[str, int] = {}
    for attempt in attempts:
        status = attempt.final_status()
        status_counts[status] = status_counts.get(status, 0) + 1

    payload = {
        "parser_version": PARSER_VERSION,
        "source": str(source),
        "generated_at": format_dt(datetime.now()),
        "attempt_count": len(attempts),
        "summary": {
            "status_counts": status_counts,
            "connected_after_retry_count": sum(
                attempt.connected_after_retry() for attempt in attempts
            ),
            "successful_machine_certificate_count": sum(
                attempt.successful_certificate_store() == "machine" for attempt in attempts
            ),
            "successful_user_certificate_count": sum(
                attempt.successful_certificate_store() == "user" for attempt in attempts
            ),
            "certificate_selection_failure_count": sum(
                len(attempt.certificate_selection_failures()) for attempt in attempts
            ),
            "certificate_selection_recovered_count": sum(
                attempt.certificate_selection_recovered() for attempt in attempts
            ),
        },
        "attempts": [attempt_to_dict(attempt) for attempt in attempts],
    }
    destination.write_text(json.dumps(payload, indent=2), encoding="utf-8")


def write_csv(attempts: list[ConnectionAttempt], destination: Path) -> None:
    fields = [
        "attempt_id",
        "start_time",
        "end_time",
        "end_source",
        "duration_seconds",
        "status",
        "connected_after_retry",
        "certificate_selection_recovered",
        "portal",
        "gateway",
        "gateway_ip",
        "username",
        "mode",
        "certificate_store_lookup",
        "portal_auth",
        "gateway_auth",
        "saml_used",
        "auth_cookie_used",
        "certificate_requested",
        "certificate_exchange_count",
        "portal_certificate_exchange_count",
        "gateway_certificate_exchange_count",
        "selected_identities",
        "selected_identity_sequence",
        "selected_identity_transition",
        "portal_selected_identities",
        "gateway_selected_identities",
        "selected_identity_stores",
        "initial_selected_identity",
        "initial_selected_identity_store",
        "initial_selected_identity_status",
        "final_portal_selected_identity",
        "final_portal_selected_identity_store",
        "final_gateway_selected_identity",
        "final_gateway_selected_identity_store",
        "successful_path_certificate_identity",
        "successful_path_certificate_store",
        "successful_path_certificate_phase",
        "successful_machine_certificate",
        "successful_user_certificate",
        "machine_certificate_selection_attempted",
        "user_certificate_selection_attempted",
        "machine_certificate_selected",
        "user_certificate_selected",
        "client_certificate_write_count",
        "tunnel_connected",
        "auth_failures",
        "certificate_selection_failures",
        "warnings",
        "start_source",
    ]
    with destination.open("w", newline="", encoding="utf-8-sig") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        for attempt in attempts:
            data = attempt_to_dict(attempt)
            writer.writerow(
                {
                    "attempt_id": data["attempt_id"],
                    "start_time": data["start_time"],
                    "end_time": data["end_time"],
                    "end_source": data["end_source"],
                    "duration_seconds": data["duration_seconds"],
                    "status": data["status"],
                    "connected_after_retry": data["connected_after_retry"],
                    "certificate_selection_recovered": data["certificate_selection_recovered"],
                    "portal": data["portal"],
                    "gateway": data["gateway"],
                    "gateway_ip": data["gateway_ip"],
                    "username": data["username"],
                    "mode": data["mode"],
                    "certificate_store_lookup": data["certificate_store_lookup"],
                    "portal_auth": join_auth(data["portal_auth_method"], data["portal_auth_source"]),
                    "gateway_auth": join_auth(data["gateway_auth_method"], data["gateway_auth_source"]),
                    "saml_used": data["saml_used"],
                    "auth_cookie_used": data["auth_cookie_used"],
                    "certificate_requested": data["certificate_requested"],
                    "certificate_exchange_count": data["certificate_exchange_count"],
                    "portal_certificate_exchange_count": data["portal_certificate_exchange_count"],
                    "gateway_certificate_exchange_count": data["gateway_certificate_exchange_count"],
                    "selected_identities": "; ".join(data["selected_identities"]),
                    "selected_identity_sequence": " -> ".join(data["selected_identity_sequence"]),
                    "selected_identity_transition": " -> ".join(
                        data["selected_identity_transition"]
                    ),
                    "portal_selected_identities": "; ".join(data["portal_selected_identities"]),
                    "gateway_selected_identities": "; ".join(data["gateway_selected_identities"]),
                    "selected_identity_stores": "; ".join(data["selected_identity_stores"]),
                    "initial_selected_identity": data["initial_selected_identity"],
                    "initial_selected_identity_store": data["initial_selected_identity_store"],
                    "initial_selected_identity_status": data["initial_selected_identity_status"],
                    "final_portal_selected_identity": data["final_portal_selected_identity"],
                    "final_portal_selected_identity_store": data["final_portal_selected_identity_store"],
                    "final_gateway_selected_identity": data["final_gateway_selected_identity"],
                    "final_gateway_selected_identity_store": data["final_gateway_selected_identity_store"],
                    "successful_path_certificate_identity": data["successful_path_certificate_identity"],
                    "successful_path_certificate_store": data["successful_path_certificate_store"],
                    "successful_path_certificate_phase": data["successful_path_certificate_phase"],
                    "successful_machine_certificate": data["successful_machine_certificate"],
                    "successful_user_certificate": data["successful_user_certificate"],
                    "machine_certificate_selection_attempted": data["machine_certificate_selection_attempted"],
                    "user_certificate_selection_attempted": data["user_certificate_selection_attempted"],
                    "machine_certificate_selected": data["machine_certificate_selected"],
                    "user_certificate_selected": data["user_certificate_selected"],
                    "client_certificate_write_count": data["client_certificate_write_count"],
                    "tunnel_connected": data["tunnel_connected"],
                    "auth_failures": " | ".join(data["auth_failures"]),
                    "certificate_selection_failures": " | ".join(
                        data["certificate_selection_failures"]
                    ),
                    "warnings": " | ".join(data["warnings"]),
                    "start_source": data["start_source"],
                }
            )


def print_report(attempts: list[ConnectionAttempt], verbose: bool = False) -> None:
    if not attempts:
        print("No connection attempts were found.")
        return

    connected = sum(attempt.final_status() == "connected" for attempt in attempts)
    machine = sum(attempt.successful_certificate_store() == "machine" for attempt in attempts)
    user = sum(attempt.successful_certificate_store() == "user" for attempt in attempts)
    retries = sum(attempt.connected_after_retry() for attempt in attempts)
    print(
        f"Found {len(attempts)} connection attempt(s): "
        f"{connected} connected, {retries} connected after an authentication retry, "
        f"{machine} completed with a machine identity, "
        f"{user} completed with a user identity."
    )

    for attempt in attempts:
        print()
        print(f"Attempt {attempt.attempt_id}: {format_dt(attempt.start_time)}")
        print(f"  Status:                 {attempt.final_status()}")
        print(f"  Duration:               {format_duration(attempt.duration_seconds())}")
        print(f"  User:                   {attempt.username or '-'}")
        print(f"  Portal:                 {attempt.portal or '-'}")
        print(f"  Gateway:                {attempt.gateway or '-'}")
        print(f"  Gateway IP:             {attempt.gateway_ip or '-'}")
        print(f"  Mode:                   {attempt.mode or '-'}")
        print(
            f"  Portal authentication:  "
            f"{join_auth(attempt.portal_auth_method, attempt.portal_auth_source) or '-'}"
        )
        print(
            f"  Gateway authentication: "
            f"{join_auth(attempt.gateway_auth_method, attempt.gateway_auth_source) or '-'}"
        )
        print(f"  Authentication cookie:  {'used' if attempt.auth_cookie_used else 'not observed'}")
        print(f"  Certificate store:      {attempt.certificate_store_lookup or '-'}")
        print(f"  Client-cert requests:   {len(attempt.certificate_exchanges)}")
        print(f"  Identities observed:    {attempt.certificate_summary()}")
        print(f"  Successful-path cert:   {attempt.successful_certificate_summary()}")
        transition = attempt.selected_identity_transition()
        if len(transition) > 1:
            print(f"  Identity transition:    {' -> '.join(transition)}")
        print(f"  TLS cert writes:        {attempt.client_certificate_write_count}")
        print(f"  Tunnel connected:       {'yes' if attempt.tunnel_connected else 'no'}")
        if attempt.connected_after_retry():
            print("  Retry outcome:          connected after authentication retry")
        if attempt.auth_failures:
            print(f"  Authentication issues:  {' | '.join(attempt.auth_failures)}")
        selection_failures = attempt.certificate_selection_failures()
        if selection_failures:
            label = "Recovered cert issue" if attempt.certificate_selection_recovered() else "Certificate issues"
            print(f"  {label + ':':<25}{' | '.join(selection_failures)}")
        if attempt.warnings:
            print(f"  Warnings:               {' | '.join(attempt.warnings)}")

        if verbose:
            print("  Timeline:")
            for event in attempt.timeline:
                print(
                    f"    {event.timestamp} [{event.phase:<7}] "
                    f"{event.event} ({event.source})"
                )


def parse_args(argv: Optional[list[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Report GlobalProtect authentication and certificate details per connection attempt."
    )
    parser.add_argument("input", type=Path, help="GlobalProtect .tgz/.tar.gz bundle or extracted directory")
    parser.add_argument(
        "-o",
        "--output-dir",
        type=Path,
        default=Path.cwd(),
        help="Directory for CSV and JSON output (default: current directory)",
    )
    parser.add_argument(
        "--prefix",
        default="globalprotect_connection_attempts",
        help="Output filename prefix",
    )
    parser.add_argument(
        "--latest",
        type=int,
        default=None,
        help="Only include the newest N attempts",
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Print a detailed timeline for every attempt",
    )
    return parser.parse_args(argv)


def main(argv: Optional[list[str]] = None) -> int:
    args = parse_args(argv)
    source = args.input.expanduser().resolve()
    if not source.exists():
        print(f"Input does not exist: {source}", file=sys.stderr)
        return 2

    args.output_dir.mkdir(parents=True, exist_ok=True)

    try:
        if source.is_dir():
            entries = load_entries(source)
        else:
            with tempfile.TemporaryDirectory(prefix="gp-log-report-") as temp_dir:
                extracted = Path(temp_dir)
                safe_extract_tar(source, extracted)
                entries = load_entries(extracted)

        attempts = GlobalProtectParser(entries).parse()
        if args.latest is not None:
            if args.latest < 1:
                raise ValueError("--latest must be at least 1")
            attempts = attempts[-args.latest :]

        csv_path = args.output_dir / f"{args.prefix}.csv"
        json_path = args.output_dir / f"{args.prefix}.json"
        write_csv(attempts, csv_path)
        write_json(attempts, json_path, source)
        print_report(attempts, verbose=args.verbose)
        print()
        print(f"CSV report:  {csv_path}")
        print(f"JSON report: {json_path}")
        return 0
    except (OSError, ValueError, tarfile.TarError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1


def format_dt(value: Optional[datetime]) -> str:
    if value is None:
        return ""
    return value.strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]


def compact_text(value: str, limit: int = 260) -> str:
    value = re.sub(r"\s+", " ", value).strip()
    if len(value) > limit:
        return value[: limit - 3] + "..."
    return value


def clean_username(value: str) -> Optional[str]:
    cleaned = value.strip().strip(",.;")
    if not cleaned or cleaned == "___empty_username___":
        return None
    return cleaned


def add_unique(values: list[str], value: str) -> None:
    value = compact_text(value)
    if value and value not in values:
        values.append(value)


def is_ip_address(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def determine_identity_store(
    selected_identity: Optional[str],
    user_identities: list[str],
    system_identities: list[str],
) -> str:
    if not selected_identity:
        return "none"
    in_user = selected_identity in user_identities
    in_system = selected_identity in system_identities
    if in_system and not in_user:
        return "machine"
    if in_user and not in_system:
        return "user"
    if in_user and in_system:
        return "ambiguous"
    return "unknown"


def extract_failure(text: str) -> str:
    first_line = text.splitlines()[0]
    first_line = re.sub(r"^[^:]+:\s*", "", first_line)
    return compact_text(first_line)


def is_relevant_timeline(lower_text: str) -> bool:
    return any(pattern in lower_text for pattern in RELEVANT_TIMELINE_PATTERNS)


def join_auth(method: Optional[str], source: Optional[str]) -> str:
    if method and source:
        return f"{method} via {source}"
    return method or source or ""


def format_duration(seconds: Optional[float]) -> str:
    if seconds is None:
        return "-"
    if seconds < 60:
        return f"{seconds:.3f} seconds"
    minutes, remainder = divmod(seconds, 60)
    return f"{int(minutes)}m {remainder:.3f}s"


if __name__ == "__main__":
    raise SystemExit(main())
