# ============================================================
#
# Passive Network / PCAP Security Analyzer
#
# Defensive analysis only:
#   - Does NOT inject packets
#   - Does NOT modify packets
#   - Does NOT perform MITM
#
# Features:
#   * PCAP / PCAPNG analysis
#   * 5-tuple flow tracking
#   * packet index / timestamp
#   * TCP sequence / ACK analysis
#   * retransmission / duplicate indicators
#   * packet gap / loss indicators
#   * timing anomaly analysis
#   * payload SHA-256
#   * DNS analysis
#   * TLS ClientHello / SNI / ALPN
#   * TLS fingerprint-style feature extraction
#   * IP intelligence
#   * domain/service intelligence
#   * periodic / beacon-like behavior detection
#   * multi-signal risk scoring
#   * JSON report
#
# ============================================================

import argparse
import hashlib
import ipaddress
import json
import math
import os
import re
import statistics
import sys
from collections import defaultdict, Counter
from functools import lru_cache

import requests

try:
    from scapy.all import (
        rdpcap,
        IP,
        IPv6,
        TCP,
        UDP,
        DNS,
        DNSQR,
        DNSRR,
        Raw,
    )
except ImportError:
    print("ERROR: Scapy is not installed.")
    print("Install with:")
    print("    python -m pip install scapy requests")
    sys.exit(1)


# ============================================================
# CONFIGURATION
# ============================================================

API_TIMEOUT = 8

USER_AGENT = "Nightmare-PCAP-Analyzer/1.0"

MAX_PACKET_RECORDS = 100000

TIMING_MIN_SAMPLES = 5

PERIODICITY_MIN_SAMPLES = 6

PERIODICITY_TOLERANCE = 0.20

REPORT_VERSION = "1.0"


# ============================================================
# KNOWN SERVICE DATABASE
# ============================================================

SERVICE_DATABASE = {

    "youtube.com": {
        "service": "YouTube",
        "provider": "Google",
        "category": "Video Streaming",
        "related_domains": [
            "googlevideo.com",
            "ytimg.com",
            "youtube-nocookie.com",
            "youtube.googleapis.com",
        ],
    },

    "google.com": {
        "service": "Google",
        "provider": "Google",
        "category": "Search / Web Services",
        "related_domains": [
            "googleusercontent.com",
            "gstatic.com",
            "googleapis.com",
        ],
    },

    "googlevideo.com": {
        "service": "YouTube Infrastructure",
        "provider": "Google",
        "category": "Video Delivery / CDN",
        "related_domains": [
            "youtube.com",
            "ytimg.com",
        ],
    },

    "facebook.com": {
        "service": "Facebook",
        "provider": "Meta",
        "category": "Social Media",
        "related_domains": [
            "fbcdn.net",
            "facebook.net",
            "messenger.com",
        ],
    },

    "instagram.com": {
        "service": "Instagram",
        "provider": "Meta",
        "category": "Social Media",
        "related_domains": [
            "cdninstagram.com",
            "instagram.net",
        ],
    },

    "twitter.com": {
        "service": "X / Twitter",
        "provider": "X Corp.",
        "category": "Social Media",
        "related_domains": [
            "x.com",
            "twimg.com",
        ],
    },

    "x.com": {
        "service": "X / Twitter",
        "provider": "X Corp.",
        "category": "Social Media",
        "related_domains": [
            "twitter.com",
            "twimg.com",
        ],
    },

    "microsoft.com": {
        "service": "Microsoft",
        "provider": "Microsoft",
        "category": "Technology",
        "related_domains": [
            "microsoftonline.com",
            "office.com",
        ],
    },

    "github.com": {
        "service": "GitHub",
        "provider": "Microsoft",
        "category": "Developer Platform",
        "related_domains": [
            "githubusercontent.com",
            "githubassets.com",
        ],
    },

    "cloudflare.com": {
        "service": "Cloudflare",
        "provider": "Cloudflare",
        "category": "CDN / Network Infrastructure",
        "related_domains": [],
    },

    "amazon.com": {
        "service": "Amazon",
        "provider": "Amazon",
        "category": "E-Commerce / Web Services",
        "related_domains": [
            "amazonaws.com",
            "cloudfront.net",
        ],
    },

    "netflix.com": {
        "service": "Netflix",
        "provider": "Netflix",
        "category": "Video Streaming",
        "related_domains": [
            "nflxvideo.net",
            "nflximg.net",
            "nflxso.net",
        ],
    },

    "spotify.com": {
        "service": "Spotify",
        "provider": "Spotify",
        "category": "Music Streaming",
        "related_domains": [
            "scdn.co",
        ],
    },
}


# ============================================================
# BASIC HELPERS
# ============================================================

def normalize_domain(domain):

    if not domain:
        return None

    domain = str(domain).strip().lower()

    domain = re.sub(
        r"^https?://",
        "",
        domain
    )

    domain = domain.split("/")[0]
    domain = domain.split(":")[0]

    domain = domain.lstrip("*.")
    domain = domain.rstrip(".")

    return domain or None


def sha256_bytes(data):

    if not data:
        return None

    return hashlib.sha256(
        bytes(data)
    ).hexdigest()


def safe_float(value):

    try:
        return float(value)
    except Exception:
        return None


def median_or_none(values):

    if not values:
        return None

    try:
        return statistics.median(values)
    except Exception:
        return None


# ============================================================
# IP CLASSIFICATION
# ============================================================

def classify_ip(ip):

    try:
        obj = ipaddress.ip_address(ip)
    except ValueError:

        return {
            "ip": ip,
            "type": "INVALID",
            "is_public": False,
        }

    if obj.is_loopback:
        ip_type = "LOOPBACK"

    elif obj.is_link_local:
        ip_type = "LINK-LOCAL"

    elif obj.is_private:
        ip_type = "PRIVATE / LOCAL"

    elif obj.is_multicast:
        ip_type = "MULTICAST"

    elif obj.is_reserved:
        ip_type = "RESERVED"

    elif obj.is_unspecified:
        ip_type = "UNSPECIFIED"

    elif obj.is_global:
        ip_type = "PUBLIC"

    else:
        ip_type = "OTHER"

    return {
        "ip": ip,
        "type": ip_type,
        "version": obj.version,
        "is_public": obj.is_global,
    }


# ============================================================
# IP INTELLIGENCE
# ============================================================

@lru_cache(maxsize=2048)
def get_ip_intelligence(ip):

    classification = classify_ip(ip)

    result = {

        "ip": ip,

        "type":
            classification["type"],

        "country": None,
        "country_code": None,
        "region": None,
        "city": None,
        "postal": None,
        "timezone": None,

        "latitude": None,
        "longitude": None,

        "isp": None,
        "organization": None,
        "asn": None,

        "hosting": "UNKNOWN",
        "vpn": "UNKNOWN",
        "proxy": "UNKNOWN",
        "tor": "UNKNOWN",

        "confidence": "UNKNOWN",

        "source": None,
        "error": None,
    }

    if not classification["is_public"]:

        result["confidence"] = "HIGH"

        result["source"] = "Local classification"

        result["note"] = (
            "Private/local IP cannot be geolocated "
            "through Internet IP geolocation."
        )

        return result

    try:

        response = requests.get(
            f"https://ipwho.is/{ip}",
            timeout=API_TIMEOUT,
            headers={
                "User-Agent": USER_AGENT
            },
        )

        response.raise_for_status()

        data = response.json()

        if not data.get("success", False):

            result["error"] = data.get(
                "message",
                "Lookup failed"
            )

            return result

        connection = data.get(
            "connection",
            {}
        )

        security = data.get(
            "security",
            {}
        )

        timezone = data.get(
            "timezone",
            {}
        )

        result.update({

            "country":
                data.get("country"),

            "country_code":
                data.get("country_code"),

            "region":
                data.get("region"),

            "city":
                data.get("city"),

            "postal":
                data.get("postal"),

            "timezone":
                timezone.get("id"),

            "latitude":
                data.get("latitude"),

            "longitude":
                data.get("longitude"),

            "isp":
                connection.get("isp"),

            "organization":
                connection.get("org"),

            "asn":
                connection.get("asn"),

            "hosting":
                security_flag(
                    security.get("hosting")
                ),

            "vpn":
                security_flag(
                    security.get("vpn")
                ),

            "proxy":
                security_flag(
                    security.get("proxy")
                ),

            "tor":
                security_flag(
                    security.get("tor")
                ),

            "confidence":
                "ESTIMATED",

            "source":
                "ipwho.is",
        })

    except Exception as exc:

        result["error"] = str(exc)

    return result


def security_flag(value):

    if value is True:
        return "LIKELY"

    if value is False:
        return "NO EVIDENCE"

    return "UNKNOWN"


# ============================================================
# DOMAIN INTELLIGENCE
# ============================================================

def find_service(domain):

    domain = normalize_domain(domain)

    result = {

        "observed_domain": domain,

        "service": None,
        "provider": None,
        "category": None,

        "match_type": "UNKNOWN",

        "matched_domain": None,

        "related_domains": [],

        "confidence": "UNKNOWN",

        "note": None,
    }

    if not domain:

        result["match_type"] = "NOT OBSERVED"
        result["confidence"] = "NONE"

        return result

    # Exact
    if domain in SERVICE_DATABASE:

        info = SERVICE_DATABASE[domain]

        result.update({

            "service":
                info["service"],

            "provider":
                info["provider"],

            "category":
                info["category"],

            "match_type":
                "EXACT",

            "matched_domain":
                domain,

            "related_domains":
                info.get(
                    "related_domains",
                    []
                ),

            "confidence":
                "HIGH",
        })

        return result

    # Subdomain
    for known_domain, info in SERVICE_DATABASE.items():

        if domain.endswith(
            "." + known_domain
        ):

            result.update({

                "service":
                    info["service"],

                "provider":
                    info["provider"],

                "category":
                    info["category"],

                "match_type":
                    "SUBDOMAIN",

                "matched_domain":
                    known_domain,

                "related_domains":
                    info.get(
                        "related_domains",
                        []
                    ),

                "confidence":
                    "HIGH",
            })

            return result

    # Related domain
    for known_domain, info in SERVICE_DATABASE.items():

        for related in info.get(
            "related_domains",
            []
        ):

            if (
                domain == related
                or domain.endswith(
                    "." + related
                )
            ):

                result.update({

                    "service":
                        info["service"],

                    "provider":
                        info["provider"],

                    "category":
                        info["category"],

                    "match_type":
                        "RELATED_DOMAIN",

                    "matched_domain":
                        known_domain,

                    "related_domains":
                        info.get(
                            "related_domains",
                            []
                        ),

                    "confidence":
                        "MEDIUM",

                    "note":
                        "Associated infrastructure; "
                        "does not prove exact website/page.",
                })

                return result

    return result


# ============================================================
# TCP FLAGS
# ============================================================

def tcp_flags(tcp):

    flags = str(tcp.flags)

    names = []

    mapping = {

        "S": "SYN",
        "A": "ACK",
        "F": "FIN",
        "R": "RST",
        "P": "PSH",
        "U": "URG",
        "E": "ECE",
        "C": "CWR",
    }

    for key, name in mapping.items():

        if key in flags:
            names.append(name)

    return names


# ============================================================
# FLOW KEY
# ============================================================

def make_flow_key(packet):

    if IP in packet:

        src = packet[IP].src
        dst = packet[IP].dst

    elif IPv6 in packet:

        src = packet[IPv6].src
        dst = packet[IPv6].dst

    else:

        return None

    proto = int(packet.proto)

    sport = None
    dport = None

    if TCP in packet:

        sport = int(packet[TCP].sport)
        dport = int(packet[TCP].dport)

    elif UDP in packet:

        sport = int(packet[UDP].sport)
        dport = int(packet[UDP].dport)

    return (
        src,
        sport,
        dst,
        dport,
        proto,
    )


def canonical_flow_key(key):

    if key is None:
        return None

    reverse = (
        key[2],
        key[3],
        key[0],
        key[1],
        key[4],
    )

    return min(
        key,
        reverse
    )


# ============================================================
# TLS PARSING
# ============================================================

def parse_tls_client_hello(payload):

    result = {

        "detected": False,

        "tls_version": None,

        "sni": None,

        "alpn": [],

        "cipher_suites": [],

        "extensions": [],

        "supported_groups": [],

        "ec_point_formats": [],

        "fingerprint": None,

        "fingerprint_type":
            "TLS feature fingerprint",

    }

    if not payload:
        return result

    data = bytes(payload)

    # TLS record header
    if len(data) < 5:
        return result

    content_type = data[0]

    if content_type != 22:
        return result

    version_major = data[1]
    version_minor = data[2]

    if version_major != 3:
        return result

    record_length = int.from_bytes(
        data[3:5],
        "big"
    )

    if len(data) < 5 + record_length:
        return result

    body = data[5:5 + record_length]

    if len(body) < 4:
        return result

    handshake_type = body[0]

    # ClientHello
    if handshake_type != 1:
        return result

    result["detected"] = True

    try:

        hs_length = int.from_bytes(
            body[1:4],
            "big"
        )

        hello = body[4:4 + hs_length]

        if len(hello) < 34:
            return result

        # legacy version
        legacy_version = (
            hello[0],
            hello[1],
        )

        result["tls_version"] = (
            f"{legacy_version[0]}."
            f"{legacy_version[1]}"
        )

        pos = 2

        # random
        pos += 32

        # session ID
        if pos >= len(hello):
            return result

        session_len = hello[pos]

        pos += 1
        pos += session_len

        if pos + 2 > len(hello):
            return result

        cipher_length = int.from_bytes(
            hello[pos:pos + 2],
            "big"
        )

        pos += 2

        cipher_bytes = hello[
            pos:pos + cipher_length
        ]

        pos += cipher_length

        result["cipher_suites"] = [

            cipher_bytes[i:i + 2].hex()

            for i in range(
                0,
                len(cipher_bytes) - 1,
                2
            )
        ]

        if pos >= len(hello):
            return result

        compression_len = hello[pos]

        pos += 1
        pos += compression_len

        if pos + 2 > len(hello):
            return result

        extensions_length = int.from_bytes(
            hello[pos:pos + 2],
            "big"
        )

        pos += 2

        end = min(
            pos + extensions_length,
            len(hello)
        )

        while pos + 4 <= end:

            ext_type = int.from_bytes(
                hello[pos:pos + 2],
                "big"
            )

            ext_len = int.from_bytes(
                hello[pos + 2:pos + 4],
                "big"
            )

            ext_data_start = pos + 4

            ext_data_end = (
                ext_data_start + ext_len
            )

            if ext_data_end > end:
                break

            ext_data = hello[
                ext_data_start:ext_data_end
            ]

            result["extensions"].append(
                ext_type
            )

            # SNI
            if ext_type == 0:

                sni = parse_sni(
                    ext_data
                )

                if sni:
                    result["sni"] = sni

            # ALPN
            elif ext_type == 16:

                result["alpn"] = parse_alpn(
                    ext_data
                )

            # Supported groups
            elif ext_type == 10:

                result["supported_groups"] = (
                    parse_u16_vector(ext_data)
                )

            # EC point formats
            elif ext_type == 11:

                if len(ext_data) >= 1:

                    count = ext_data[0]

                    result["ec_point_formats"] = list(
                        ext_data[
                            1:1 + count
                        ]
                    )

            pos = ext_data_end

        # Feature fingerprint.
        #
        # This is intentionally called a
        # "TLS feature fingerprint" rather than
        # claiming a vendor-specific JA3 implementation.
        result["fingerprint"] = build_tls_fingerprint(
            result
        )

    except Exception:

        pass

    return result


def parse_sni(data):

    try:

        if len(data) < 5:
            return None

        list_length = int.from_bytes(
            data[0:2],
            "big"
        )

        pos = 2

        end = min(
            2 + list_length,
            len(data)
        )

        while pos + 3 <= end:

            name_type = data[pos]

            name_len = int.from_bytes(
                data[pos + 1:pos + 3],
                "big"
            )

            pos += 3

            if pos + name_len > end:
                return None

            name = data[
                pos:pos + name_len
            ]

            pos += name_len

            if name_type == 0:

                try:
                    return name.decode(
                        "utf-8",
                        errors="ignore"
                    ).lower()

                except Exception:
                    return None

    except Exception:
        return None

    return None


def parse_alpn(data):

    values = []

    try:

        if len(data) < 2:
            return values

        total = int.from_bytes(
            data[0:2],
            "big"
        )

        pos = 2

        end = min(
            pos + total,
            len(data)
        )

        while pos < end:

            length = data[pos]

            pos += 1

            if pos + length > end:
                break

            value = data[
                pos:pos + length
            ]

            pos += length

            values.append(
                value.decode(
                    "ascii",
                    errors="ignore"
                )
            )

    except Exception:
        pass

    return values


def parse_u16_vector(data):

    values = []

    if len(data) < 2:
        return values

    total = int.from_bytes(
        data[0:2],
        "big"
    )

    pos = 2

    end = min(
        pos + total,
        len(data)
    )

    while pos + 2 <= end:

        values.append(
            int.from_bytes(
                data[pos:pos + 2],
                "big"
            )
        )

        pos += 2

    return values


def build_tls_fingerprint(tls):

    cipher_part = "-".join(
        tls["cipher_suites"]
    )

    extension_part = "-".join(
        str(x)
        for x in tls["extensions"]
    )

    group_part = "-".join(
        str(x)
        for x in tls["supported_groups"]
    )

    alpn_part = "-".join(
        tls["alpn"]
    )

    raw = "|".join([
        cipher_part,
        extension_part,
        group_part,
        alpn_part,
    ])

    return hashlib.sha256(
        raw.encode()
    ).hexdigest()


# ============================================================
# DNS ANALYSIS
# ============================================================

def parse_dns(packet):

    result = {

        "query": None,
        "query_type": None,

        "answers": [],

        "rcode": None,
    }

    if DNS not in packet:
        return result

    dns = packet[DNS]

    try:

        result["rcode"] = int(
            dns.rcode
        )

    except Exception:
        pass

    try:

        if dns.qdcount > 0 and DNSQR in dns:

            q = dns.qd

            result["query"] = normalize_domain(
                q.qname.decode(
                    "utf-8",
                    errors="ignore"
                )
            )

            result["query_type"] = (
                int(q.qtype)
            )

    except Exception:
        pass

    try:

        if dns.ancount > 0:

            for i in range(
                int(dns.ancount)
            ):

                rr = dns.an[i]

                if hasattr(rr, "rdata"):

                    value = rr.rdata

                    if isinstance(
                        value,
                        bytes
                    ):

                        value = value.decode(
                            "utf-8",
                            errors="ignore"
                        )

                    result["answers"].append(
                        str(value)
                    )

    except Exception:
        pass

    return result


# ============================================================
# APPLICATION DETECTION
# ============================================================

def detect_application(
    user_agent=None,
    alpn=None,
):

    result = {

        "application": "Unknown",

        "confidence": "UNKNOWN",

        "evidence": [],
    }

    ua = (
        user_agent.lower()
        if user_agent
        else ""
    )

    if "edg/" in ua:

        result.update({

            "application":
                "Microsoft Edge",

            "confidence":
                "HIGH",

            "evidence":
                ["HTTP User-Agent"],
        })

        return result

    if (
        "chrome/" in ua
        and "chromium" not in ua
    ):

        result.update({

            "application":
                "Google Chrome",

            "confidence":
                "HIGH",

            "evidence":
                ["HTTP User-Agent"],
        })

        return result

    if "firefox/" in ua:

        result.update({

            "application":
                "Mozilla Firefox",

            "confidence":
                "HIGH",

            "evidence":
                ["HTTP User-Agent"],
        })

        return result

    if (
        "safari/" in ua
        and "chrome" not in ua
    ):

        result.update({

            "application":
                "Apple Safari",

            "confidence":
                "HIGH",

            "evidence":
                ["HTTP User-Agent"],
        })

        return result

    if alpn:

        if "h2" in alpn:

            result.update({

                "application":
                    "HTTP/2-capable client",

                "confidence":
                    "LOW",

                "evidence":
                    ["TLS ALPN = h2"],
            })

        elif "http/1.1" in alpn:

            result.update({

                "application":
                    "HTTP/1.1-capable client",

                "confidence":
                    "LOW",

                "evidence":
                    ["TLS ALPN = http/1.1"],
            })

    return result


# ============================================================
# FLOW STATE
# ============================================================

def new_flow(key):

    return {

        "flow_key":
            key,

        "packets": 0,

        "bytes": 0,

        "first_timestamp": None,

        "last_timestamp": None,

        "timestamps": [],

        "packet_lengths": [],

        "directions": Counter(),

        "tcp_seq_seen": set(),

        "tcp_ranges": [],

        "tcp_ack_values": [],

        "retransmissions": 0,

        "duplicate_packets": 0,

        "sequence_anomalies": 0,

        "possible_gaps": 0,

        "rst_count": 0,

        "syn_count": 0,

        "fin_count": 0,

        "psh_count": 0,

        "dns_queries": [],

        "sni_values": [],

        "alpn_values": [],

        "tls_fingerprints": [],

        "domains": set(),

        "payload_hashes": [],

        "payload_changes": 0,

        "payload_count": 0,

        "large_payloads": 0,

        "inter_arrivals": [],
    }


# ============================================================
# PACKET ANALYSIS
# ============================================================

def analyze_packet(
    packet,
    index,
    flows,
    packet_records,
    previous_timestamp,
):

    timestamp = safe_float(
        packet.time
    )

    if timestamp is None:
        timestamp = 0.0

    global_gap = None

    if previous_timestamp is not None:

        global_gap = (
            timestamp -
            previous_timestamp
        )

    flow_key = make_flow_key(
        packet
    )

    canonical = canonical_flow_key(
        flow_key
    )

    if canonical is not None:

        if canonical not in flows:

            flows[canonical] = new_flow(
                canonical
            )

        flow = flows[canonical]

        flow["packets"] += 1

        flow["bytes"] += len(packet)

        flow["timestamps"].append(
            timestamp
        )

        flow["packet_lengths"].append(
            len(packet)
        )

        if flow["first_timestamp"] is None:

            flow["first_timestamp"] = (
                timestamp
            )

        flow["last_timestamp"] = (
            timestamp
        )

        if (
            len(flow["timestamps"]) >= 2
        ):

            delta = (
                flow["timestamps"][-1]
                -
                flow["timestamps"][-2]
            )

            flow["inter_arrivals"].append(
                delta
            )

    # --------------------------------------------------------
    # Packet record
    # --------------------------------------------------------

    record = {

        "capture_index":
            index,

        "timestamp":
            timestamp,

        "length":
            len(packet),

        "flow":
            flow_key,

        "protocol":
            None,

        "tcp":
            None,

        "udp":
            None,

        "payload_sha256":
            None,

        "dns":
            None,

        "tls":
            None,

        "global_interarrival":
            global_gap,
    }

    # --------------------------------------------------------
    # IP
    # --------------------------------------------------------

    if IP in packet:

        record["protocol"] = (
            "IPv4"
        )

    elif IPv6 in packet:

        record["protocol"] = (
            "IPv6"
        )

    # --------------------------------------------------------
    # TCP
    # --------------------------------------------------------

    if TCP in packet:

        tcp = packet[TCP]

        flags = tcp_flags(
            tcp
        )

        payload = b""

        if Raw in packet:

            payload = bytes(
                packet[Raw].load
            )

        seq = int(
            tcp.seq
        )

        ack = int(
            tcp.ack
        )

        record["tcp"] = {

            "seq":
                seq,

            "ack":
                ack,

            "flags":
                flags,

            "window":
                int(tcp.window),

            "sport":
                int(tcp.sport),

            "dport":
                int(tcp.dport),
        }

        if canonical is not None:

            flow = flows[canonical]

            if "SYN" in flags:

                flow["syn_count"] += 1

            if "RST" in flags:

                flow["rst_count"] += 1

            if "FIN" in flags:

                flow["fin_count"] += 1

            if "PSH" in flags:

                flow["psh_count"] += 1

            flow["tcp_ack_values"].append(
                ack
            )

            payload_length = len(
                payload
            )

            # Sequence range.
            seq_end = (
                seq +
                payload_length
            )

            if (
                payload_length > 0
            ):

                # Exact duplicate/retransmission
                # indicator.
                sequence_key = (
                    seq,
                    seq_end,
                    sha256_bytes(payload),
                )

                if sequence_key in flow[
                    "tcp_seq_seen"
                ]:

                    flow[
                        "duplicate_packets"
                    ] += 1

                    flow[
                        "retransmissions"
                    ] += 1

                else:

                    flow[
                        "tcp_seq_seen"
                    ].add(
                        sequence_key
                    )

                flow[
                    "tcp_ranges"
                ].append(
                    (
                        seq,
                        seq_end,
                        index
                    )
                )

    # --------------------------------------------------------
    # UDP
    # --------------------------------------------------------

    if UDP in packet:

        udp = packet[UDP]

        record["udp"] = {

            "sport":
                int(udp.sport),

            "dport":
                int(udp.dport),
        }

    # --------------------------------------------------------
    # Payload hash
    # --------------------------------------------------------

    payload = b""

    if Raw in packet:

        try:
            payload = bytes(
                packet[Raw].load
            )
        except Exception:
            payload = b""

    if payload:

        payload_hash = sha256_bytes(
            payload
        )

        record[
            "payload_sha256"
        ] = payload_hash

        if canonical is not None:

            flow = flows[canonical]

            flow[
                "payload_hashes"
            ].append(
                payload_hash
            )

            flow[
                "payload_count"
            ] += 1

            if len(payload) >= 4096:

                flow[
                    "large_payloads"
                ] += 1

    # --------------------------------------------------------
    # DNS
    # --------------------------------------------------------

    if DNS in packet:

        dns_info = parse_dns(
            packet
        )

        record["dns"] = dns_info

        if canonical is not None:

            flow = flows[canonical]

            if dns_info.get("query"):

                flow[
                    "dns_queries"
                ].append(
                    dns_info["query"]
                )

                flow[
                    "domains"
                ].add(
                    dns_info["query"]
                )

    # --------------------------------------------------------
    # TLS
    # --------------------------------------------------------

    tls_info = None

    if payload:

        tls_info = parse_tls_client_hello(
            payload
        )

        if tls_info.get("detected"):

            record["tls"] = tls_info

            if canonical is not None:

                flow = flows[canonical]

                if tls_info.get("sni"):

                    flow[
                        "sni_values"
                    ].append(
                        tls_info["sni"]
                    )

                    flow[
                        "domains"
                    ].add(
                        tls_info["sni"]
                    )

                for alpn in tls_info.get(
                    "alpn",
                    []
                ):

                    flow[
                        "alpn_values"
                    ].append(
                        alpn
                    )

                if tls_info.get(
                    "fingerprint"
                ):

                    flow[
                        "tls_fingerprints"
                    ].append(
                        tls_info[
                            "fingerprint"
                        ]
                    )

    # --------------------------------------------------------
    # Packet records
    # --------------------------------------------------------

    if len(packet_records) < MAX_PACKET_RECORDS:

        packet_records.append(
            record
        )


# ============================================================
# TCP GAP ANALYSIS
# ============================================================

def analyze_tcp_gaps(flow):

    ranges = flow[
        "tcp_ranges"
    ]

    if len(ranges) < 2:

        return {

            "possible_gaps": 0,

            "overlaps": 0,

            "out_of_order_indicators": 0,
        }

    ordered = sorted(
        ranges,
        key=lambda x: (
            x[0],
            x[2]
        )
    )

    gaps = 0
    overlaps = 0
    out_of_order = 0

    previous_start = None
    previous_end = None
    previous_index = None

    for start, end, index in ordered:

        if previous_end is not None:

            if start > previous_end:

                # A sequence gap is an indicator,
                # not proof that a packet was lost:
                # capture filters and asymmetric
                # captures can create apparent gaps.
                gaps += 1

            elif start < previous_end:

                overlaps += 1

        if (
            previous_start is not None
            and start < previous_start
            and index > previous_index
        ):

            out_of_order += 1

        previous_start = start
        previous_end = max(
            previous_end or end,
            end
        )

        previous_index = index

    return {

        "possible_gaps":
            gaps,

        "overlaps":
            overlaps,

        "out_of_order_indicators":
            out_of_order,
    }


# ============================================================
# TIMING ANALYSIS
# ============================================================

def analyze_timing(flow):

    values = [
        x for x in flow[
            "inter_arrivals"
        ]
        if x >= 0
    ]

    result = {

        "samples":
            len(values),

        "median_seconds":
            median_or_none(values),

        "mean_seconds":
            None,

        "stddev_seconds":
            None,

        "periodic_score":
            0.0,

        "periodic_behavior":
            False,

        "timing_anomaly":
            False,
    }

    if len(values) < TIMING_MIN_SAMPLES:

        return result

    result["mean_seconds"] = (
        statistics.mean(values)
    )

    if len(values) >= 2:

        result["stddev_seconds"] = (
            statistics.pstdev(values)
        )

    mean = result[
        "mean_seconds"
    ]

    std = result[
        "stddev_seconds"
    ]

    if mean and mean > 0:

        coefficient = (
            std / mean
            if std is not None
            else 999
        )

        periodic_score = max(
            0.0,
            min(
                1.0,
                1.0 - coefficient
            )
        )

        result[
            "periodic_score"
        ] = round(
            periodic_score,
            3
        )

        if (
            len(values)
            >= PERIODICITY_MIN_SAMPLES
            and coefficient
            <= PERIODICITY_TOLERANCE
        ):

            result[
                "periodic_behavior"
            ] = True

    # Very large gaps relative to median.
    median = result[
        "median_seconds"
    ]

    if median and median > 0:

        abnormal = sum(
            1
            for x in values
            if x > median * 10
        )

        if abnormal > 0:

            result[
                "timing_anomaly"
            ] = True

    return result


# ============================================================
# PAYLOAD CONSISTENCY
# ============================================================

def analyze_payload_consistency(flow):

    hashes = flow[
        "payload_hashes"
    ]

    result = {

        "payloads":
            len(hashes),

        "unique_payload_hashes":
            len(set(hashes)),

        "repeated_payload_pattern":
            False,
    }

    if len(hashes) >= 4:

        counts = Counter(
            hashes
        )

        most_common = (
            counts.most_common(1)[0][1]
        )

        if most_common >= 3:

            result[
                "repeated_payload_pattern"
            ] = True

    return result


# ============================================================
# FLOW SUMMARY
# ============================================================

def summarize_flow(
    flow,
    ip_cache,
):

    gap_info = analyze_tcp_gaps(
        flow
    )

    timing = analyze_timing(
        flow
    )

    payload = analyze_payload_consistency(
        flow
    )

    flow["possible_gaps"] = (
        gap_info["possible_gaps"]
    )

    flow["sequence_anomalies"] = (
        gap_info["out_of_order_indicators"]
    )

    src_ip = flow[
        "flow_key"
    ][0]

    dst_ip = flow[
        "flow_key"
    ][2]

    src_info = ip_cache.get(
        src_ip
    )

    dst_info = ip_cache.get(
        dst_ip
    )

    domains = sorted(
        flow["domains"]
    )

    service_results = []

    for domain in domains:

        service_results.append(
            find_service(domain)
        )

    return {

        "flow_key":
            flow["flow_key"],

        "packets":
            flow["packets"],

        "bytes":
            flow["bytes"],

        "first_timestamp":
            flow["first_timestamp"],

        "last_timestamp":
            flow["last_timestamp"],

        "duration_seconds":
            (
                flow["last_timestamp"]
                -
                flow["first_timestamp"]
            )
            if (
                flow["first_timestamp"]
                is not None
                and
                flow["last_timestamp"]
                is not None
            )
            else None,

        "tcp": {

            "retransmissions":
                flow["retransmissions"],

            "duplicates":
                flow["duplicate_packets"],

            "possible_gaps":
                flow["possible_gaps"],

            "sequence_anomalies":
                flow["sequence_anomalies"],

            "rst_count":
                flow["rst_count"],

            "syn_count":
                flow["syn_count"],

            "fin_count":
                flow["fin_count"],

            "psh_count":
                flow["psh_count"],
        },

        "timing":
            timing,

        "payload":
            payload,

        "domains":
            domains,

        "sni":
            sorted(
                set(
                    flow["sni_values"]
                )
            ),

        "alpn":
            sorted(
                set(
                    flow["alpn_values"]
                )
            ),

        "tls_fingerprints":
            sorted(
                set(
                    flow[
                        "tls_fingerprints"
                    ]
                )
            ),

        "dns_queries":
            sorted(
                set(
                    flow[
                        "dns_queries"
                    ]
                )
            ),

        "services":
            service_results,

        "source_ip_intelligence":
            src_info,

        "destination_ip_intelligence":
            dst_info,
    }


# ============================================================
# RISK ENGINE
# ============================================================

def score_flow(flow_summary):

    score = 0

    indicators = []

    tcp = flow_summary[
        "tcp"
    ]

    timing = flow_summary[
        "timing"
    ]

    payload = flow_summary[
        "payload"
    ]

    dst_info = flow_summary.get(
        "destination_ip_intelligence"
    ) or {}

    # --------------------------------------------------------
    # Repeated retransmission
    # --------------------------------------------------------

    retrans = tcp[
        "retransmissions"
    ]

    if retrans >= 10:

        score += 8

        indicators.append(
            "High retransmission count"
        )

    elif retrans >= 3:

        score += 3

        indicators.append(
            "Retransmissions observed"
        )

    # --------------------------------------------------------
    # Sequence gaps
    # --------------------------------------------------------

    gaps = tcp[
        "possible_gaps"
    ]

    if gaps >= 10:

        score += 12

        indicators.append(
            "Multiple TCP sequence gaps"
        )

    elif gaps >= 3:

        score += 5

        indicators.append(
            "TCP sequence gaps observed"
        )

    # --------------------------------------------------------
    # Out-of-order
    # --------------------------------------------------------

    out_of_order = tcp[
        "sequence_anomalies"
    ]

    if out_of_order >= 5:

        score += 6

        indicators.append(
            "Multiple out-of-order indicators"
        )

    # --------------------------------------------------------
    # RST
    # --------------------------------------------------------

    if tcp["rst_count"] >= 3:

        score += 4

        indicators.append(
            "Repeated TCP resets"
        )

    # --------------------------------------------------------
    # Timing / periodic behavior
    # --------------------------------------------------------

    if timing[
        "periodic_behavior"
    ]:

        score += 12

        indicators.append(
            "Regular periodic connection timing"
        )

    if timing[
        "timing_anomaly"
    ]:

        score += 6

        indicators.append(
            "Timing anomaly detected"
        )

    # --------------------------------------------------------
    # Repeated payload pattern
    # --------------------------------------------------------

    if payload[
        "repeated_payload_pattern"
    ]:

        score += 8

        indicators.append(
            "Repeated payload pattern"
        )

    # --------------------------------------------------------
    # VPN / Proxy / Tor / Hosting
    # --------------------------------------------------------

    for field, points, label in [

        (
            "vpn",
            4,
            "VPN-associated destination"
        ),

        (
            "proxy",
            6,
            "Proxy-associated destination"
        ),

        (
            "tor",
            12,
            "Tor-associated destination"
        ),

        (
            "hosting",
            3,
            "Hosting-associated destination"
        ),

    ]:

        if dst_info.get(field) == "LIKELY":

            score += points

            indicators.append(
                label
            )

    # --------------------------------------------------------
    # Cap
    # --------------------------------------------------------

    score = min(
        100,
        score
    )

    if score >= 80:

        severity = "CRITICAL"

    elif score >= 60:

        severity = "HIGH"

    elif score >= 30:

        severity = "MEDIUM"

    else:

        severity = "LOW"

    if severity in (
        "HIGH",
        "CRITICAL"
    ):

        conclusion = (
            "Potentially suspicious network behavior; "
            "further investigation recommended."
        )

    elif severity == "MEDIUM":

        conclusion = (
            "Some unusual indicators detected; "
            "contextual investigation recommended."
        )

    else:

        conclusion = (
            "No strong suspicious behavior detected "
            "by the available passive indicators."
        )

    return {

        "score":
            score,

        "severity":
            severity,

        "indicators":
            indicators,

        "conclusion":
            conclusion,

        "important_note":
            (
                "Risk score is heuristic. "
                "It does not prove malware, C2, "
                "packet tampering, or compromise."
            ),
    }


# ============================================================
# GLOBAL ANALYSIS
# ============================================================

def analyze_global_packet_patterns(
    packet_records
):

    result = {

        "packet_count":
            len(packet_records),

        "total_bytes":
            sum(
                r["length"]
                for r in packet_records
            ),

        "global_timing_anomalies":
            0,

        "duplicate_payloads":
            0,
    }

    previous = None

    for record in packet_records:

        current = record[
            "timestamp"
        ]

        if previous is not None:

            delta = (
                current - previous
            )

            if delta > 10:

                result[
                    "global_timing_anomalies"
                ] += 1

        previous = current

    hashes = [

        r["payload_sha256"]

        for r in packet_records

        if r["payload_sha256"]
    ]

    counts = Counter(
        hashes
    )

    result[
        "duplicate_payloads"
    ] = sum(
        count - 1
        for count in counts.values()
        if count > 1
    )

    return result


# ============================================================
# MAIN ANALYZER
# ============================================================

def analyze_pcap(
    filename,
    enable_ip_lookup=True,
):

    if not os.path.exists(filename):

        raise FileNotFoundError(
            f"PCAP not found: {filename}"
        )

    print(
        f"[+] Reading PCAP: {filename}"
    )

    try:

        packets = rdpcap(
            filename
        )

    except Exception as exc:

        raise RuntimeError(
            f"Could not read PCAP: {exc}"
        )

    flows = {}

    packet_records = []

    previous_timestamp = None

    ip_cache = {}

    # --------------------------------------------------------
    # Packet pass
    # --------------------------------------------------------

    for index, packet in enumerate(
        packets,
        start=1
    ):

        analyze_packet(
            packet=packet,
            index=index,
            flows=flows,
            packet_records=packet_records,
            previous_timestamp=
                previous_timestamp,
        )

        try:
            previous_timestamp = float(
                packet.time
            )
        except Exception:
            pass

        # Collect public IPs for later intelligence.
        for layer in (
            IP,
            IPv6
        ):

            if layer in packet:

                for ip in (
                    packet[layer].src,
                    packet[layer].dst
                ):

                    if ip not in ip_cache:

                        if enable_ip_lookup:

                            print(
                                f"[+] IP intelligence: "
                                f"{ip}"
                            )

                            ip_cache[ip] = (
                                get_ip_intelligence(
                                    ip
                                )
                            )

                        else:

                            ip_cache[ip] = (
                                classify_ip(
                                    ip
                                )
                            )

    # --------------------------------------------------------
    # Flow summaries
    # --------------------------------------------------------

    flow_summaries = []

    for flow in flows.values():

        summary = summarize_flow(
            flow,
            ip_cache
        )

        risk = score_flow(
            summary
        )

        summary["risk"] = risk

        flow_summaries.append(
            summary
        )

    # Highest risk first.
    flow_summaries.sort(
        key=lambda x:
            x["risk"]["score"],
        reverse=True
    )

    global_analysis = (
        analyze_global_packet_patterns(
            packet_records
        )
    )

    # --------------------------------------------------------
    # Overall risk
    # --------------------------------------------------------

    if flow_summaries:

        overall_score = max(
            f["risk"]["score"]
            for f in flow_summaries
        )

    else:

        overall_score = 0

    if overall_score >= 80:
        overall_severity = "CRITICAL"

    elif overall_score >= 60:
        overall_severity = "HIGH"

    elif overall_score >= 30:
        overall_severity = "MEDIUM"

    else:
        overall_severity = "LOW"

    return {

        "analyzer": {
            "name":
                "Nightmare PCAP Analyzer",

            "version":
                REPORT_VERSION,

            "mode":
                "PASSIVE / DEFENSIVE",
        },

        "input": {

            "pcap":
                os.path.abspath(
                    filename
                ),

            "packet_count":
                len(packets),
        },

        "global_analysis":
            global_analysis,

        "ip_intelligence":
            ip_cache,

        "flow_count":
            len(flow_summaries),

        "overall_risk": {

            "score":
                overall_score,

            "severity":
                overall_severity,

            "note":
                (
                    "Heuristic assessment; "
                    "not proof of compromise."
                ),
        },

        "flows":
            flow_summaries,

        "packets":
            packet_records,
    }


# ============================================================
# HUMAN READABLE OUTPUT
# ============================================================

def separator(
    char="=",
    length=78
):

    print(
        char * length
    )


def print_report(report):

    print()

    separator()

    print(
        "        NIGHTMARE PCAP SECURITY ANALYZER"
    )

    print(
        "        PASSIVE / DEFENSIVE MODE"
    )

    separator()

    print(
        f"PCAP    : "
        f"{report['input']['pcap']}"
    )

    print(
        f"Packets : "
        f"{report['input']['packet_count']}"
    )

    print(
        f"Flows   : "
        f"{report['flow_count']}"
    )

    overall = report[
        "overall_risk"
    ]

    print()

    print(
        "[OVERALL RISK]"
    )

    print(
        f"Score    : "
        f"{overall['score']}/100"
    )

    print(
        f"Severity : "
        f"{overall['severity']}"
    )

    separator("-")

    global_info = report[
        "global_analysis"
    ]

    print(
        "[GLOBAL ANALYSIS]"
    )

    print(
        f"Total Bytes           : "
        f"{global_info['total_bytes']}"
    )

    print(
        f"Timing anomalies      : "
        f"{global_info['global_timing_anomalies']}"
    )

    print(
        f"Repeated payloads     : "
        f"{global_info['duplicate_payloads']}"
    )

    # --------------------------------------------------------
    # Top flows
    # --------------------------------------------------------

    print()

    print(
        "[FLOW ANALYSIS]"
    )

    separator("-")

    for number, flow in enumerate(
        report["flows"][:25],
        start=1
    ):

        key = flow[
            "flow_key"
        ]

        risk = flow[
            "risk"
        ]

        print()

        print(
            f"FLOW #{number}"
        )

        print(
            f"  Source       : "
            f"{key[0]}:{key[1]}"
        )

        print(
            f"  Destination  : "
            f"{key[2]}:{key[3]}"
        )

        print(
            f"  Protocol     : "
            f"{key[4]}"
        )

        print(
            f"  Packets      : "
            f"{flow['packets']}"
        )

        print(
            f"  Bytes        : "
            f"{flow['bytes']}"
        )

        print(
            f"  Duration     : "
            f"{flow['duration_seconds']}"
        )

        tcp = flow[
            "tcp"
        ]

        print()

        print(
            "  [TCP INTEGRITY]"
        )

        print(
            f"    Retransmissions : "
            f"{tcp['retransmissions']}"
        )

        print(
            f"    Duplicates      : "
            f"{tcp['duplicates']}"
        )

        print(
            f"    Sequence gaps   : "
            f"{tcp['possible_gaps']}"
        )

        print(
            f"    Out-of-order    : "
            f"{tcp['sequence_anomalies']}"
        )

        print(
            f"    RST             : "
            f"{tcp['rst_count']}"
        )

        timing = flow[
            "timing"
        ]

        print()

        print(
            "  [TIMING]"
        )

        print(
            f"    Median IAT      : "
            f"{timing['median_seconds']}"
        )

        print(
            f"    Periodic        : "
            f"{timing['periodic_behavior']}"
        )

        print(
            f"    Periodic score  : "
            f"{timing['periodic_score']}"
        )

        print(
            f"    Timing anomaly  : "
            f"{timing['timing_anomaly']}"
        )

        print()

        print(
            "  [DNS / TLS]"
        )

        print(
            f"    DNS             : "
            f"{flow['dns_queries']}"
        )

        print(
            f"    SNI             : "
            f"{flow['sni']}"
        )

        print(
            f"    ALPN            : "
            f"{flow['alpn']}"
        )

        print(
            f"    TLS fingerprints: "
            f"{flow['tls_fingerprints']}"
        )

        print()

        print(
            "  [SERVICE]"
        )

        for service in flow[
            "services"
        ]:

            print(
                f"    {service.get('service')} "
                f"| {service.get('provider')} "
                f"| {service.get('match_type')}"
            )

        print()

        print(
            "  [RISK]"
        )

        print(
            f"    Score    : "
            f"{risk['score']}/100"
        )

        print(
            f"    Severity : "
            f"{risk['severity']}"
        )

        for indicator in risk[
            "indicators"
        ]:

            print(
                f"    - {indicator}"
            )

        print(
            f"    Conclusion: "
            f"{risk['conclusion']}"
        )

    separator()

    print(
        "IMPORTANT:"
    )

    print(
        "Risk results are heuristic. "
        "A suspicious score does not by itself "
        "prove malware, C2, MITM, packet replacement, "
        "or compromise."
    )

    separator()


# ============================================================
# JSON OUTPUT
# ============================================================

def save_json(
    report,
    filename
):

    with open(
        filename,
        "w",
        encoding="utf-8"
    ) as file:

        json.dump(
            report,
            file,
            indent=2,
            ensure_ascii=False,
            default=str
        )


# ============================================================
# CLI
# ============================================================

def main():

    parser = argparse.ArgumentParser(

        description=(
            "Nightmare passive PCAP security "
            "and network behavior analyzer."
        )
    )

    parser.add_argument(

        "pcap",

        nargs="?",

        default="capture.pcap",

        help=(
            "Input PCAP/PCAPNG file "
            "(default: capture.pcap)"
        ),
    )

    parser.add_argument(

        "--json",

        dest="json_file",

        default=None,

        help=(
            "Save complete analysis to JSON"
        ),
    )

    parser.add_argument(

        "--no-ip-lookup",

        action="store_true",

        help=(
            "Disable external IP intelligence lookups"
        ),
    )

    args = parser.parse_args()

    try:

        report = analyze_pcap(

            filename=args.pcap,

            enable_ip_lookup=(
                not args.no_ip_lookup
            ),
        )

        print_report(
            report
        )

        if args.json_file:

            save_json(
                report,
                args.json_file
            )

            print()

            print(
                f"[+] JSON report saved: "
                f"{args.json_file}"
            )

        return 0

    except FileNotFoundError as exc:

        print(
            f"ERROR: {exc}"
        )

        return 1

    except Exception as exc:

        print(
            f"ERROR: {exc}"
        )

        return 1


# ============================================================
# ENTRY POINT
# ============================================================

if __name__ == "__main__":

    raise SystemExit(
        main()
    )
