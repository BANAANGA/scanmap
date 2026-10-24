"""Validation and argv construction for the two scanning engines.

Everything a user can influence is checked here before it ever reaches
``subprocess``. Only allow-listed flags are emitted, targets and ports are
validated against strict patterns, and no value is ever passed through a
shell. This keeps the web UI from turning into a remote command execution
service.
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
from typing import Any

# --------------------------------------------------------------------------- #
# Patterns
# --------------------------------------------------------------------------- #

# A single scan target token: IPv4, IPv6, hostname, CIDR or nmap octet range.
TOKEN_RE = re.compile(r"^[A-Za-z0-9_.:\[\]/+-]+$")
PORTS_RE = re.compile(r"^[0-9]{1,5}(?:-[0-9]{1,5})?(?:,[0-9]{1,5}(?:-[0-9]{1,5})?)*$")
BANDWIDTH_RE = re.compile(r"^[1-9][0-9]*(?:\.[0-9]+)?[KMG]?$")
SCRIPT_RE = re.compile(r"^[A-Za-z0-9_,.\-+]+$")
NAME_RE = re.compile(r"^[A-Za-z0-9_.-]+$")
CIDR_RE = re.compile(r"^[0-9A-Fa-f:.]{2,64}(?:/[0-9]{1,3})?$")

NMAP_SCAN_FLAGS: dict[str, list[str]] = {
    "connect": ["-sT"],
    "syn": ["-sS"],
    "udp": ["-sU"],
    "ping": ["-sn"],
}

ZMAP_MODULES: dict[str, str] = {
    "tcp_synscan": "TCP SYN scan",
    "tcp_ackscan": "TCP ACK scan",
    "icmp_echoscan": "ICMP echo scan",
    "icmp_echo_time": "ICMP timestamp scan",
}

ZMAP_OUTPUT_FIELDS = {
    "saddr",
    "daddr",
    "sport",
    "dport",
    "seqno",
    "ackno",
    "window",
    "classification",
    "success",
    "cooldown",
    "ttl",
    "timestamp-str",
    "timestamp-ts",
    "timestamp-us",
}


class ValidationError(ValueError):
    """Raised when user supplied parameters are unacceptable."""


# --------------------------------------------------------------------------- #
# Small helpers
# --------------------------------------------------------------------------- #


def _text(params: dict[str, Any], key: str, label: str, *, default: str = "", max_len: int = 512) -> str:
    raw = params.get(key, default)
    if raw is None:
        raw = default
    if not isinstance(raw, (str, int, float)):
        raise ValidationError(f"{label} must be text")
    value = str(raw).strip()
    if len(value) > max_len:
        raise ValidationError(f"{label} is too long (max {max_len} characters)")
    return value


def _flag(params: dict[str, Any], key: str) -> bool:
    value = params.get(key, False)
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        return value.lower() in {"1", "true", "yes", "on"}
    return bool(value)


def _int(
    params: dict[str, Any],
    key: str,
    label: str,
    *,
    default: int | None = None,
    low: int = 1,
    high: int = 65535,
) -> int | None:
    raw = params.get(key, "")
    if raw is None or (isinstance(raw, str) and not raw.strip()):
        return default
    try:
        value = int(str(raw).strip())
    except (TypeError, ValueError):
        raise ValidationError(f"{label} must be a whole number") from None
    if not low <= value <= high:
        raise ValidationError(f"{label} must be between {low} and {high}")
    return value


def _choice(params: dict[str, Any], key: str, label: str, options: dict[str, Any], default: str) -> str:
    value = _text(params, key, label, default=default)
    for option in options:
        if value.lower() == option.lower():
            return option
    raise ValidationError(f"{label} must be one of: {', '.join(sorted(options))}")


# --------------------------------------------------------------------------- #
# Target validation
# --------------------------------------------------------------------------- #


def _check_token(token: str, label: str) -> None:
    if token.startswith("-"):
        raise ValidationError(f"{label} may not start with '-'")
    if not TOKEN_RE.match(token):
        raise ValidationError(f"{label} contains unsupported characters: {token!r}")
    if token.count("/") > 1 or token.count("[") != token.count("]") or token.count("[") > 1:
        raise ValidationError(f"{label} is not a valid host, range or CIDR: {token!r}")


def validate_nmap_target(raw: str) -> str:
    """nmap accepts a comma or space separated list of hosts and ranges."""
    target = raw.strip()
    if not target:
        raise ValidationError("target is required, e.g. 192.168.1.0/24")
    tokens = [t for t in re.split(r"[,\s]+", target) if t]
    if len(tokens) > 64:
        raise ValidationError("at most 64 targets may be supplied at once")
    for token in tokens:
        _check_token(token, "target")
    return ",".join(tokens)


def validate_zmap_target(raw: str) -> str:
    """zmap needs exactly one IP or CIDR block (it randomises inside it)."""
    target = raw.strip()
    if not target:
        raise ValidationError("target is required, e.g. 192.168.1.0/24")
    if re.search(r"[,\s]", target):
        raise ValidationError("zmap accepts a single IP address or CIDR block")
    _check_token(target, "target")
    if not CIDR_RE.match(target):
        raise ValidationError("zmap target must be an IP address or CIDR block")
    return target


def _validate_ports(raw: str) -> str:
    if not PORTS_RE.match(raw):
        raise ValidationError("ports must look like 22,80,443 or 1-1000")
    for part in raw.split(","):
        bounds = part.split("-")
        numbers = [int(value) for value in bounds]
        if any(number > 65535 for number in numbers):
            raise ValidationError("port numbers must be between 0 and 65535")
        if len(numbers) == 2 and numbers[0] > numbers[1]:
            raise ValidationError(f"invalid port range: {part}")
    return raw


def _resolve_data_file(raw: str, data_dir: str, label: str) -> str:
    if not raw:
        return ""
    if raw.startswith("-"):
        raise ValidationError(f"{label} may not start with '-'")
    root = os.path.realpath(data_dir)
    candidate = os.path.realpath(raw if os.path.isabs(raw) else os.path.join(root, raw))
    if os.path.commonpath([root, candidate]) != root:
        raise ValidationError(f"{label} must live inside the data directory")
    if not os.path.isfile(candidate):
        raise ValidationError(f"{label} does not exist: {raw}")
    return candidate


# --------------------------------------------------------------------------- #
# nmap
# --------------------------------------------------------------------------- #


def build_nmap(params: dict[str, Any], data_dir: str = "/data") -> list[str]:
    target = validate_nmap_target(_text(params, "target", "target"))
    scan = _choice(params, "scan", "scan type", NMAP_SCAN_FLAGS, "connect")
    timing = _choice(
        params, "timing", "timing template", {f"T{i}": i for i in range(6)}, "T3"
    )

    argv: list[str] = ["nmap", "-v", *NMAP_SCAN_FLAGS[scan], f"-{timing}"]

    if scan != "ping":
        ports = _text(params, "ports", "ports", default="1-1000", max_len=200)
        argv += ["-p", _validate_ports(ports)]

    if _flag(params, "service_detection"):
        argv.append("-sV")
        intensity = _int(params, "version_intensity", "version intensity", default=7, low=0, high=9)
        if intensity != 7:
            argv += ["--version-intensity", str(intensity)]

    if _flag(params, "default_scripts"):
        argv.append("-sC")

    scripts = _text(params, "scripts", "scripts", max_len=300)
    if scripts:
        if "--" in scripts or not SCRIPT_RE.match(scripts):
            raise ValidationError("scripts may only contain names, separated by commas")
        argv += ["--script", scripts]

    if _flag(params, "os_detection"):
        argv.append("-O")
    if _flag(params, "no_ping"):
        argv.append("-Pn")
    if _flag(params, "no_dns"):
        argv.append("-n")
    if _flag(params, "open_only"):
        argv.append("--open")

    argv.append(target)
    return argv


# --------------------------------------------------------------------------- #
# zmap
# --------------------------------------------------------------------------- #


def build_zmap(params: dict[str, Any], data_dir: str = "/data") -> list[str]:
    target = validate_zmap_target(_text(params, "target", "target"))
    argv: list[str] = ["zmap"]

    port = _int(params, "port", "port", default=443)
    argv += ["-p", str(port)]

    bandwidth = _text(params, "bandwidth", "bandwidth", default="1M", max_len=16).upper()
    if not BANDWIDTH_RE.match(bandwidth):
        raise ValidationError("bandwidth must look like 10M, 1G or 500K")
    argv += ["-B", bandwidth]

    rate = _int(params, "rate", "rate", default=None, low=1, high=10_000_000)
    if rate is not None:
        argv += ["-r", str(rate)]

    interface = _text(params, "interface", "interface", max_len=32)
    if interface:
        if not NAME_RE.match(interface):
            raise ValidationError("interface must be a plain device name such as eth0")
        argv += ["-i", interface]

    source_port = _int(params, "source_port", "source port", default=None)
    if source_port is not None:
        argv += ["-S", str(source_port)]

    module = _choice(params, "probe_module", "probe module", ZMAP_MODULES, "tcp_synscan")
    argv += ["-M", module]

    fields_raw = _text(params, "output_fields", "output fields", default="saddr,dport", max_len=200)
    fields = [f.strip() for f in fields_raw.split(",") if f.strip()]
    if not fields:
        raise ValidationError("at least one output field is required")
    unknown = [f for f in fields if f not in ZMAP_OUTPUT_FIELDS]
    if unknown:
        raise ValidationError(f"unknown output field(s): {', '.join(unknown)}")
    argv += ["-f", ",".join(fields)]

    max_targets = _int(params, "max_targets", "max targets", default=None, low=1, high=4_294_967_295)
    if max_targets is not None:
        argv += ["-n", str(max_targets)]

    if _flag(params, "cooldown"):
        argv += ["-c", "1"]

    blocklist = _text(params, "blocklist", "blocklist file", max_len=256)
    if blocklist:
        argv += ["-b", _resolve_data_file(blocklist, data_dir, "blocklist file")]
    elif _flag(params, "disable_default_blacklist") or _flag(params, "no_blacklist") or _flag(params, "ignore_blacklist"):
        # Create empty blocklist file
        import tempfile
        empty_blocklist = os.path.join(data_dir, ".empty_blocklist")
        if not os.path.exists(empty_blocklist):
            open(empty_blocklist, 'w').close()
        argv += ["-b", empty_blocklist]


    if _flag(params, "dry_run"):
        argv.append("-d")

    argv.append(target)
    return argv


# --------------------------------------------------------------------------- #
# Discovery / introspection
# --------------------------------------------------------------------------- #

BUILDERS = {"nmap": build_nmap, "zmap": build_zmap}


def build_argv(scanner: str, params: dict[str, Any], data_dir: str = "/data") -> list[str]:
    try:
        builder = BUILDERS[scanner]
    except KeyError:
        raise ValidationError(f"unknown scanner: {scanner!r}") from None
    if not isinstance(params, dict):
        raise ValidationError("params must be an object")
    return builder(params, data_dir)


def tool_info() -> list[dict[str, Any]]:
    """Report whether the binaries are installed, and their versions."""
    info: list[dict[str, Any]] = []
    for name in ("nmap", "zmap"):
        path = shutil.which(name)
        version = ""
        if path:
            try:
                proc = subprocess.run(
                    [path, "--version"], capture_output=True, text=True, timeout=10, check=False
                )
                lines = (proc.stdout or proc.stderr or "").strip().splitlines()
                version = lines[0][:120] if lines else ""
            except (OSError, subprocess.SubprocessError):
                version = ""
        info.append({"name": name, "available": bool(path), "version": version})
    return info
