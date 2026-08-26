import argparse
import json
import os
import re
import html
from collections import Counter
from datetime import datetime

import pyshark


# ============================================================
# CONFIGURATION
# ============================================================

MAX_HEX_BYTES = 1024
MAX_FIELD_LENGTH = 3000


# ============================================================
# BASIC HELPERS
# ============================================================

def safe_str(value):
    try:
        return str(value)
    except Exception:
        return "<unavailable>"


def truncate(value, limit=MAX_FIELD_LENGTH):
    value = safe_str(value)

    if len(value) > limit:
        return value[:limit] + "...[truncated]"

    return value


def get_layer(packet, name):
    try:
        return getattr(packet, name.lower())
    except Exception:
        return None


def get_field(layer, *names):
    if layer is None:
        return None

    for name in names:
        try:
            value = getattr(layer, name)

            if value is not None:
                return safe_str(value)

        except Exception:
            pass

    return None


def get_all_fields(layer):
    result = {}

    if layer is None:
        return result

    try:
        fields = layer.field_names
    except Exception:
        return result

    for field in sorted(fields):

        try:
            value = getattr(layer, field)
            result[field] = truncate(value)

        except Exception:
            result[field] = "<unavailable>"

    return result


def packet_time(packet):
    try:
        return packet.sniff_time.isoformat()
    except Exception:
        return None


def packet_length(packet):
    try:
        return int(packet.length)
    except Exception:
        try:
            return int(packet.frame_info.len)
        except Exception:
            return 0


def layer_names(packet):
    result = []

    try:
        for layer in packet.layers:
            try:
                result.append(layer.layer_name)
            except Exception:
                pass
    except Exception:
        pass

    return result


def raw_bytes(packet):
    try:
        return packet.get_raw_packet()
    except Exception:
        return b""


def hex_dump(packet):
    data = raw_bytes(packet)

    if not data:
        return ""

    data = data[:MAX_HEX_BYTES]

    return " ".join(
        f"{b:02X}" for b in data
    )


def ascii_dump(packet):
    data = raw_bytes(packet)

    if not data:
        return ""

    data = data[:MAX_HEX_BYTES]

    return "".join(
        chr(b) if 32 <= b <= 126 else "."
        for b in data
    )


# ============================================================
# FILE SIGNATURE DATABASE
# ============================================================

FILE_SIGNATURES = [
    {
        "type": "PDF",
        "extension": ".pdf",
        "mime": "application/pdf",
        "magic": b"%PDF-",
    },

    {
        "type": "PNG Image",
        "extension": ".png",
        "mime": "image/png",
        "magic": b"\x89PNG\r\n\x1a\n",
    },

    {
        "type": "JPEG Image",
        "extension": ".jpg",
        "mime": "image/jpeg",
        "magic": b"\xff\xd8\xff",
    },

    {
        "type": "GIF Image",
        "extension": ".gif",
        "mime": "image/gif",
        "magic": b"GIF8",
    },

    {
        "type": "BMP Image",
        "extension": ".bmp",
        "mime": "image/bmp",
        "magic": b"BM",
    },

    {
        "type": "WEBP Image",
        "extension": ".webp",
        "mime": "image/webp",
        "magic": b"RIFF",
    },

    {
        "type": "ZIP Archive",
        "extension": ".zip",
        "mime": "application/zip",
        "magic": b"PK\x03\x04",
    },

    {
        "type": "GZIP Archive",
        "extension": ".gz",
        "mime": "application/gzip",
        "magic": b"\x1f\x8b",
    },

    {
        "type": "RAR Archive",
        "extension": ".rar",
        "mime": "application/vnd.rar",
        "magic": b"Rar!",
    },

    {
        "type": "7-Zip Archive",
        "extension": ".7z",
        "mime": "application/x-7z-compressed",
        "magic": b"7z\xbc\xaf'\x1c",
    },

    {
        "type": "Windows PE Executable",
        "extension": ".exe",
        "mime": "application/vnd.microsoft.portable-executable",
        "magic": b"MZ",
    },

    {
        "type": "ELF Executable",
        "extension": ".elf",
        "mime": "application/x-elf",
        "magic": b"\x7fELF",
    },

    {
        "type": "MP3 Audio",
        "extension": ".mp3",
        "mime": "audio/mpeg",
        "magic": b"ID3",
    },

    {
        "type": "WAV Audio",
        "extension": ".wav",
        "mime": "audio/wav",
        "magic": b"RIFF",
    },

    {
        "type": "MP4 Video",
        "extension": ".mp4",
        "mime": "video/mp4",
        "magic": b"ftyp",
    },

    {
        "type": "FLAC Audio",
        "extension": ".flac",
        "mime": "audio/flac",
        "magic": b"fLaC",
    },

    {
        "type": "SQLite Database",
        "extension": ".sqlite",
        "mime": "application/x-sqlite3",
        "magic": b"SQLite format 3",
    },
]


TEXT_EXTENSIONS = {
    ".txt",
    ".csv",
    ".log",
    ".json",
    ".xml",
    ".html",
    ".htm",
    ".css",
    ".js",
    ".py",
    ".c",
    ".cpp",
    ".h",
    ".java",
    ".md",
    ".yaml",
    ".yml",
    ".ini",
    ".conf",
}


# ============================================================
# FILE TYPE DETECTION
# ============================================================

def detect_file_signature(data):
    if not data:
        return None

    for signature in FILE_SIGNATURES:

        magic = signature["magic"]

        # Normal beginning-of-file signature
        if data.startswith(magic):

            return {
                "type": signature["type"],
                "extension": signature["extension"],
                "mime": signature["mime"],
                "detection": "magic_bytes",
            }

        # Some formats such as MP4/WebP have signatures
        # at an offset rather than byte zero.
        if signature["type"] in (
            "MP4 Video",
            "WEBP Image",
            "WAV Audio",
        ):

            if len(data) >= 12:

                if (
                    signature["type"] == "MP4 Video"
                    and data[4:8] == b"ftyp"
                ):
                    return {
                        "type": signature["type"],
                        "extension": signature["extension"],
                        "mime": signature["mime"],
                        "detection": "container_signature",
                    }

                if (
                    signature["type"] == "WEBP Image"
                    and data[0:4] == b"RIFF"
                    and data[8:12] == b"WEBP"
                ):
                    return {
                        "type": signature["type"],
                        "extension": signature["extension"],
                        "mime": signature["mime"],
                        "detection": "container_signature",
                    }

                if (
                    signature["type"] == "WAV Audio"
                    and data[0:4] == b"RIFF"
                    and data[8:12] == b"WAVE"
                ):
                    return {
                        "type": signature["type"],
                        "extension": signature["extension"],
                        "mime": signature["mime"],
                        "detection": "container_signature",
                    }

    return None


def filename_from_disposition(value):
    if not value:
        return None

    patterns = [
        r'filename="([^"]+)"',
        r"filename='([^']+)'",
        r"filename=([^;\s]+)",
    ]

    for pattern in patterns:

        match = re.search(
            pattern,
            value,
            re.IGNORECASE
        )

        if match:
            return match.group(1)

    return None


def extension_from_filename(filename):
    if not filename:
        return None

    return os.path.splitext(filename)[1].lower()


def is_text_file(filename):
    ext = extension_from_filename(filename)

    return ext in TEXT_EXTENSIONS if ext else False


# ============================================================
# ETHERNET
# ============================================================

def analyze_ethernet(packet):

    eth = get_layer(packet, "ETH")

    if not eth:
        return {}

    return {
        "source_mac": get_field(eth, "src"),
        "destination_mac": get_field(eth, "dst"),
        "type": get_field(eth, "type"),
        "fields": get_all_fields(eth),
    }


# ============================================================
# IP
# ============================================================

def analyze_ip(packet):

    ip = get_layer(packet, "IP")

    if ip:

        return {
            "version": "IPv4",
            "source": get_field(ip, "src"),
            "destination": get_field(ip, "dst"),
            "ttl": get_field(ip, "ttl"),
            "protocol": get_field(ip, "proto"),
            "header_length": get_field(ip, "hdr_len"),
            "total_length": get_field(ip, "len"),
            "fragment_offset": get_field(ip, "frag_offset"),
            "dscp": get_field(ip, "dsfield"),
        }

    ipv6 = get_layer(packet, "IPv6")

    if ipv6:

        return {
            "version": "IPv6",
            "source": get_field(ipv6, "src"),
            "destination": get_field(ipv6, "dst"),
            "hop_limit": get_field(ipv6, "hlim"),
            "next_header": get_field(ipv6, "nxt"),
            "payload_length": get_field(ipv6, "plen"),
        }

    return {}


# ============================================================
# TCP
# ============================================================

def tcp_flags(tcp):

    if not tcp:
        return []

    mapping = {
        "syn": "SYN",
        "ack": "ACK",
        "fin": "FIN",
        "rst": "RST",
        "psh": "PSH",
        "urg": "URG",
        "ece": "ECE",
        "cwr": "CWR",
    }

    result = []

    for field, name in mapping.items():

        value = get_field(tcp, field)

        if value in ("1", "True", "true"):
            result.append(name)

    return result


def analyze_tcp(packet):

    tcp = get_layer(packet, "TCP")

    if not tcp:
        return {}

    return {
        "source_port": get_field(tcp, "srcport"),
        "destination_port": get_field(tcp, "dstport"),
        "sequence": get_field(tcp, "seq"),
        "acknowledgment": get_field(tcp, "ack"),
        "window": get_field(
            tcp,
            "window_size",
            "window_size_value"
        ),
        "header_length": get_field(tcp, "hdr_len"),
        "flags": tcp_flags(tcp),
        "mss": get_field(tcp, "options_mss_val"),
        "sack": get_field(tcp, "options_sack"),
        "timestamp": get_field(
            tcp,
            "options_timestamp"
        ),
        "fields": get_all_fields(tcp),
    }


# ============================================================
# UDP
# ============================================================

def analyze_udp(packet):

    udp = get_layer(packet, "UDP")

    if not udp:
        return {}

    return {
        "source_port": get_field(udp, "srcport"),
        "destination_port": get_field(
            udp,
            "dstport"
        ),
        "length": get_field(udp, "length"),
        "checksum": get_field(udp, "checksum"),
        "fields": get_all_fields(udp),
    }


# ============================================================
# DNS
# ============================================================

def analyze_dns(packet):

    dns = get_layer(packet, "DNS")

    if not dns:
        return {}

    return {
        "transaction_id": get_field(dns, "id"),
        "query": get_field(
            dns,
            "qry_name",
            "qry_name_raw"
        ),
        "query_type": get_field(
            dns,
            "qry_type"
        ),
        "response": get_field(
            dns,
            "flags_response"
        ),
        "answer_count": get_field(
            dns,
            "count_answers"
        ),
        "fields": get_all_fields(dns),
    }


# ============================================================
# HTTP
# ============================================================

def analyze_http(packet):

    http_layer = get_layer(packet, "HTTP")

    if not http_layer:
        return {}

    return {
        "method": get_field(
            http_layer,
            "request_method"
        ),

        "uri": get_field(
            http_layer,
            "request_uri"
        ),

        "host": get_field(
            http_layer,
            "host"
        ),

        "user_agent": get_field(
            http_layer,
            "user_agent"
        ),

        "status_code": get_field(
            http_layer,
            "response_code"
        ),

        "content_type": get_field(
            http_layer,
            "content_type"
        ),

        "content_length": get_field(
            http_layer,
            "content_length"
        ),

        "content_disposition": get_field(
            http_layer,
            "content_disposition"
        ),

        "fields": get_all_fields(http_layer),
    }


# ============================================================
# TLS
# ============================================================

def classify_cipher(cipher):

    if not cipher:
        return {
            "algorithm": None,
            "construction": None,
        }

    value = cipher.upper()

    if "CHACHA20" in value:

        return {
            "algorithm": "ChaCha20",
            "construction": "ChaCha20-Poly1305",
        }

    if "AES_128_GCM" in value:

        return {
            "algorithm": "AES-128",
            "construction": "AES-GCM",
        }

    if "AES_256_GCM" in value:

        return {
            "algorithm": "AES-256",
            "construction": "AES-GCM",
        }

    if "AES_128_CCM" in value:

        return {
            "algorithm": "AES-128",
            "construction": "AES-CCM",
        }

    if "AES_256_CCM" in value:

        return {
            "algorithm": "AES-256",
            "construction": "AES-CCM",
        }

    return {
        "algorithm": "Unknown",
        "construction": "Unknown",
    }


def tls_message_name(tls):

    value = get_field(
        tls,
        "handshake_type"
    )

    if not value:
        return None

    mapping = {
        "1": "ClientHello",
        "2": "ServerHello",
        "4": "NewSessionTicket",
        "8": "EncryptedExtensions",
        "11": "Certificate",
        "15": "CertificateVerify",
        "20": "Finished",
    }

    return mapping.get(
        value,
        value
    )


def analyze_tls(packet):

    tls = get_layer(packet, "TLS")

    if not tls:
        return {}

    cipher = get_field(
        tls,
        "handshake_ciphersuite",
        "handshake_ciphersuite_id",
        "handshake_ciphersuite_raw"
    )

    return {

        "version": get_field(
            tls,
            "record_version",
            "handshake_version",
            "handshake_version_raw"
        ),

        "handshake_message":
            tls_message_name(tls),

        "handshake_type":
            get_field(tls, "handshake_type"),

        "cipher_suite":
            cipher,

        "cipher_classification":
            classify_cipher(cipher),

        "sni":
            get_field(
                tls,
                "handshake_extensions_server_name",
                "handshake_extensions_server_name_list"
            ),

        "alpn":
            get_field(
                tls,
                "handshake_extensions_alpn_str",
                "handshake_extensions_alpn"
            ),

        "supported_groups":
            get_field(
                tls,
                "handshake_extensions_supported_group",
                "handshake_extensions_supported_groups"
            ),

        "signature_algorithms":
            get_field(
                tls,
                "handshake_sig_hash_alg",
                "handshake_extensions_signature_algorithms"
            ),

        "key_share":
            get_field(
                tls,
                "handshake_extensions_key_share_group",
                "handshake_extensions_key_share"
            ),

        "certificate_public_key":
            get_field(
                tls,
                "x509af_subjectPublicKeyInfo_algorithm",
                "x509af_subjectPublicKeyInfo_algorithm_id"
            ),

        "fields":
            get_all_fields(tls),
    }


# ============================================================
# FILE ANALYSIS
# ============================================================

def analyze_file(packet):

    http = packet.get("http", {})
    data = raw_bytes_from_packet(packet)

    if not data and not http:
        return None

    content_type = http.get(
        "content_type"
    )

    disposition = http.get(
        "content_disposition"
    )

    filename = filename_from_disposition(
        disposition
    )

    signature = detect_file_signature(
        data
    )

    extension = extension_from_filename(
        filename
    )

    # MIME-based identification
    mime_type = content_type

    detected_type = None

    if signature:

        detected_type = signature["type"]

        if not mime_type:
            mime_type = signature["mime"]

    elif content_type:

        content_type_lower = content_type.lower()

        if content_type_lower.startswith(
            "text/"
        ):
            detected_type = "Text File"

        elif content_type_lower.startswith(
            "image/"
        ):
            detected_type = "Image"

        elif content_type_lower.startswith(
            "audio/"
        ):
            detected_type = "Audio"

        elif content_type_lower.startswith(
            "video/"
        ):
            detected_type = "Video"

        elif "pdf" in content_type_lower:
            detected_type = "PDF Document"

        elif "json" in content_type_lower:
            detected_type = "JSON Document"

        elif "xml" in content_type_lower:
            detected_type = "XML Document"

        elif "zip" in content_type_lower:
            detected_type = "ZIP Archive"

    elif filename:

        if extension in TEXT_EXTENSIONS:
            detected_type = "Text File"

        elif extension in (
            ".pdf",
        ):
            detected_type = "PDF Document"

        elif extension in (
            ".png",
            ".jpg",
            ".jpeg",
            ".gif",
            ".bmp",
            ".webp",
        ):
            detected_type = "Image"

    # Don't report ordinary HTTP packets as files
    if not any([
        filename,
        content_type,
        signature,
    ]):
        return None

    return {

        "filename": filename,

        "extension": extension,

        "type": detected_type,

        "mime_type": mime_type,

        "content_length": http.get(
            "content_length"
        ),

        "uri": http.get(
            "uri"
        ),

        "detection": (
            signature["detection"]
            if signature
            else "metadata"
        ),

        "magic_signature": (
            signature
            if signature
            else None
        ),

        "text_file": is_text_file(
            filename
        ),

        "packet_number":
            packet.get("packet_number"),

        "direction":
            packet.get("direction"),

        "connection_id":
            packet.get("connection_id"),
    }


def raw_bytes_from_packet(packet):

    # Packet object is not retained in JSON.
    # During packet analysis we temporarily attach raw bytes.
    value = packet.get("_raw_bytes")

    if isinstance(value, bytes):
        return value

    return b""


# ============================================================
# APPLICATION PROTOCOL
# ============================================================

def application_protocol(packet):

    layers = [
        x.upper()
        for x in packet.get(
            "layers",
            []
        )
    ]

    priority = [
        "TLS",
        "HTTP2",
        "HTTP",
        "DNS",
        "SSH",
        "FTP",
        "SMTP",
        "SMB",
        "ICMP",
        "UDP",
        "TCP",
    ]

    for protocol in priority:

        if protocol in layers:
            return protocol

    return (
        layers[-1]
        if layers
        else "UNKNOWN"
    )


# ============================================================
# CONNECTION HELPERS
# ============================================================

SERVER_PORTS = {
    "20",
    "21",
    "22",
    "23",
    "25",
    "53",
    "80",
    "110",
    "143",
    "443",
    "445",
    "587",
    "993",
    "995",
    "3306",
    "3389",
    "8080",
}


def connection_key(packet):

    ip = packet.get("ip", {})

    if not ip:
        return None

    src = ip.get("source")
    dst = ip.get("destination")

    tcp = packet.get("tcp", {})
    udp = packet.get("udp", {})

    if tcp:

        protocol = "TCP"
        src_port = tcp.get("source_port")
        dst_port = tcp.get("destination_port")

    elif udp:

        protocol = "UDP"
        src_port = udp.get("source_port")
        dst_port = udp.get("destination_port")

    else:

        protocol = "IP"
        src_port = None
        dst_port = None

    endpoints = sorted([
        (src, src_port),
        (dst, dst_port),
    ])

    return (
        protocol,
        endpoints[0],
        endpoints[1],
    )


def client_server(packet):

    ip = packet.get("ip", {})
    tcp = packet.get("tcp", {})
    udp = packet.get("udp", {})

    src_ip = ip.get("source")
    dst_ip = ip.get("destination")

    if tcp:

        src_port = tcp.get(
            "source_port"
        )

        dst_port = tcp.get(
            "destination_port"
        )

    elif udp:

        src_port = udp.get(
            "source_port"
        )

        dst_port = udp.get(
            "destination_port"
        )

    else:

        src_port = None
        dst_port = None

    if dst_port in SERVER_PORTS:

        return {
            "client_ip": src_ip,
            "client_port": src_port,
            "server_ip": dst_ip,
            "server_port": dst_port,
        }

    if src_port in SERVER_PORTS:

        return {
            "client_ip": dst_ip,
            "client_port": dst_port,
            "server_ip": src_ip,
            "server_port": src_port,
        }

    return {
        "client_ip": src_ip,
        "client_port": src_port,
        "server_ip": dst_ip,
        "server_port": dst_port,
    }


def packet_direction(packet, connection):

    ip = packet.get("ip", {})

    tcp = packet.get("tcp", {})
    udp = packet.get("udp", {})

    src_ip = ip.get("source")

    if tcp:
        src_port = tcp.get(
            "source_port"
        )
    elif udp:
        src_port = udp.get(
            "source_port"
        )
    else:
        src_port = None

    if (
        src_ip == connection["client_ip"]
        and src_port == connection["client_port"]
    ):
        return "Client → Server"

    return "Server → Client"


# ============================================================
# PACKET ANALYZER
# ============================================================

def analyze_packet(packet, number):

    raw = raw_bytes(packet)

    result = {

        "packet_number":
            number,

        "timestamp":
            packet_time(packet),

        "length":
            packet_length(packet),

        "layers":
            layer_names(packet),

        "ethernet":
            analyze_ethernet(packet),

        "ip":
            analyze_ip(packet),

        "tcp":
            analyze_tcp(packet),

        "udp":
            analyze_udp(packet),

        "dns":
            analyze_dns(packet),

        "http":
            analyze_http(packet),

        "tls":
            analyze_tls(packet),

        "raw": {
            "hex":
                " ".join(
                    f"{b:02X}"
                    for b in raw[:MAX_HEX_BYTES]
                ),

            "ascii":
                "".join(
                    chr(b)
                    if 32 <= b <= 126
                    else "."
                    for b in raw[:MAX_HEX_BYTES]
                ),
        },

        # Temporary internal field.
        "_raw_bytes":
            raw,
    }

    result["application_protocol"] = (
        application_protocol(result)
    )

    return result


# ============================================================
# ANOMALY DETECTION
# ============================================================

def tcp_anomalies(connection):

    warnings = []

    syn = 0
    syn_ack = 0
    ack = 0
    rst = 0
    fin = 0

    for packet in connection["packets"]:

        flags = packet.get(
            "tcp",
            {}
        ).get(
            "flags",
            []
        )

        if (
            "SYN" in flags
            and "ACK" not in flags
        ):
            syn += 1

        if (
            "SYN" in flags
            and "ACK" in flags
        ):
            syn_ack += 1

        if "ACK" in flags:
            ack += 1

        if "RST" in flags:
            rst += 1

        if "FIN" in flags:
            fin += 1

    if syn >= 5 and syn_ack == 0:

        warnings.append({
            "severity": "WARNING",
            "type": "TCP",
            "message":
                "High number of SYN packets without observed SYN-ACK responses."
        })

    if syn > 3 and syn_ack == 0:

        warnings.append({
            "severity": "WARNING",
            "type": "TCP",
            "message":
                "Possible incomplete TCP connections."
        })

    if rst:

        warnings.append({
            "severity": "INFO",
            "type": "TCP",
            "message":
                f"{rst} TCP RST packet(s) observed."
        })

    if rst >= 5:

        warnings.append({
            "severity": "WARNING",
            "type": "TCP",
            "message":
                "High number of TCP resets detected."
        })

    if syn and syn_ack and not ack:

        warnings.append({
            "severity": "WARNING",
            "type": "TCP",
            "message":
                "TCP handshake appears incomplete."
        })

    return warnings


def tls_anomalies(connection):

    warnings = []

    messages = []

    for packet in connection["packets"]:

        message = packet.get(
            "tls",
            {}
        ).get(
            "handshake_message"
        )

        if message:
            messages.append(message)

    if (
        "ClientHello" in messages
        and "ServerHello" not in messages
    ):

        warnings.append({
            "severity": "WARNING",
            "type": "TLS",
            "message":
                "TLS ClientHello observed but ServerHello was not observed."
        })

    if (
        "ServerHello" in messages
        and "ClientHello" not in messages
    ):

        warnings.append({
            "severity": "WARNING",
            "type": "TLS",
            "message":
                "TLS ServerHello observed without ClientHello."
        })

    if (
        "ClientHello" in messages
        and "Finished" not in messages
    ):

        warnings.append({
            "severity": "INFO",
            "type": "TLS",
            "message":
                "TLS handshake may be incomplete in the capture."
        })

    return warnings


def packet_anomalies(packet):

    warnings = []

    layers = [
        x.upper()
        for x in packet.get(
            "layers",
            []
        )
    ]

    if "MALFORMED" in layers:

        warnings.append({
            "severity": "WARNING",
            "type": "PROTOCOL",
            "message":
                "Malformed protocol field reported by dissector."
        })

    return warnings


# ============================================================
# MAIN ANALYZER
# ============================================================

class DeepAnalyzer:

    def __init__(self, filename):

        self.filename = filename

        self.packets = []

        self.connections = {}

        self.files = []

        self.protocols = Counter()

        self.total_bytes = 0

        self.global_warnings = []

    def process(self):

        print(
            f"Analyzing: {self.filename}"
        )

        capture = pyshark.FileCapture(
            self.filename,
            keep_packets=False,
        )

        try:

            for number, packet in enumerate(
                capture,
                start=1
            ):

                data = analyze_packet(
                    packet,
                    number
                )

                self.packets.append(
                    data
                )

                self.total_bytes += (
                    data["length"]
                )

                for protocol in data["layers"]:

                    self.protocols[
                        protocol.upper()
                    ] += 1

                self.global_warnings.extend(
                    packet_anomalies(data)
                )

                self.add_connection(
                    data
                )

        finally:

            capture.close()

        self.finalize()

    def add_connection(self, packet):

        key = connection_key(packet)

        if not key:
            return

        if key not in self.connections:

            endpoints = client_server(
                packet
            )

            connection_id = (
                len(self.connections) + 1
            )

            self.connections[key] = {

                "connection_id":
                    connection_id,

                "client_ip":
                    endpoints["client_ip"],

                "client_port":
                    endpoints["client_port"],

                "server_ip":
                    endpoints["server_ip"],

                "server_port":
                    endpoints["server_port"],

                "protocol":
                    key[0],

                "packets": [],

                "total_bytes":
                    0,

                "client_packets":
                    0,

                "server_packets":
                    0,

                "client_bytes":
                    0,

                "server_bytes":
                    0,

                "start_time":
                    packet["timestamp"],

                "end_time":
                    packet["timestamp"],
            }

        connection = self.connections[key]

        packet["connection_id"] = (
            connection["connection_id"]
        )

        direction = packet_direction(
            packet,
            connection
        )

        packet["direction"] = direction

        connection["packets"].append(
            packet
        )

        connection["total_bytes"] += (
            packet["length"]
        )

        connection["end_time"] = (
            packet["timestamp"]
        )

        if direction == "Client → Server":

            connection["client_packets"] += 1

            connection["client_bytes"] += (
                packet["length"]
            )

        else:

            connection["server_packets"] += 1

            connection["server_bytes"] += (
                packet["length"]
            )

        file_info = analyze_file(
            packet
        )

        if file_info:

            self.files.append(
                file_info
            )

    def finalize(self):

        for connection in self.connections.values():

            packets = connection["packets"]

            connection["application_protocols"] = sorted(
                set(
                    p.get(
                        "application_protocol"
                    )
                    for p in packets
                    if p.get(
                        "application_protocol"
                    )
                )
            )

            tls_messages = []

            tls_versions = []

            ciphers = []

            sni = None
            alpn = None
            groups = None
            signatures = None
            key_share = None

            certificate_key = None

            for packet in packets:

                tls = packet.get(
                    "tls",
                    {}
                )

                message = tls.get(
                    "handshake_message"
                )

                if message:
                    tls_messages.append(
                        message
                    )

                version = tls.get(
                    "version"
                )

                if version:
                    tls_versions.append(
                        version
                    )

                cipher = tls.get(
                    "cipher_suite"
                )

                if cipher:
                    ciphers.append(
                        cipher
                    )

                if not sni:
                    sni = tls.get("sni")

                if not alpn:
                    alpn = tls.get("alpn")

                if not groups:
                    groups = tls.get(
                        "supported_groups"
                    )

                if not signatures:
                    signatures = tls.get(
                        "signature_algorithms"
                    )

                if not key_share:
                    key_share = tls.get(
                        "key_share"
                    )

                if not certificate_key:
                    certificate_key = tls.get(
                        "certificate_public_key"
                    )

            connection["tls"] = {

                "versions":
                    list(dict.fromkeys(
                        tls_versions
                    )),

                "handshake_messages":
                    list(dict.fromkeys(
                        tls_messages
                    )),

                "cipher_suites":
                    list(dict.fromkeys(
                        ciphers
                    )),

                "sni":
                    sni,

                "alpn":
                    alpn,

                "supported_groups":
                    groups,

                "signature_algorithms":
                    signatures,

                "key_share":
                    key_share,

                "certificate_public_key":
                    certificate_key,

                "crypto_profile":
                    classify_cipher(
                        ciphers[-1]
                        if ciphers
                        else None
                    ),
            }

            connection["tcp_statistics"] = (
                self.tcp_statistics(
                    packets
                )
            )

            connection["encrypted_statistics"] = (
                self.encrypted_statistics(
                    packets
                )
            )

            connection["anomalies"] = []

            connection["anomalies"].extend(
                tcp_anomalies(
                    connection
                )
            )

            connection["anomalies"].extend(
                tls_anomalies(
                    connection
                )
            )

            connection["duration"] = (
                self.duration(
                    connection["start_time"],
                    connection["end_time"]
                )
            )

        # Remove temporary raw bytes before reports.
        for packet in self.packets:

            packet.pop(
                "_raw_bytes",
                None
            )

    @staticmethod
    def tcp_statistics(packets):

        stats = {
            "SYN": 0,
            "SYN-ACK": 0,
            "ACK": 0,
            "FIN": 0,
            "RST": 0,
        }

        for packet in packets:

            flags = packet.get(
                "tcp",
                {}
            ).get(
                "flags",
                []
            )

            if (
                "SYN" in flags
                and "ACK" not in flags
            ):
                stats["SYN"] += 1

            if (
                "SYN" in flags
                and "ACK" in flags
            ):
                stats["SYN-ACK"] += 1

            if "ACK" in flags:
                stats["ACK"] += 1

            if "FIN" in flags:
                stats["FIN"] += 1

            if "RST" in flags:
                stats["RST"] += 1

        return stats

    @staticmethod
    def encrypted_statistics(packets):

        encrypted = []

        handshake_messages = {
            "ClientHello",
            "ServerHello",
            "Certificate",
            "CertificateVerify",
            "Finished",
            "EncryptedExtensions",
            "NewSessionTicket",
        }

        for packet in packets:

            tls = packet.get(
                "tls",
                {}
            )

            if not tls:
                continue

            message = tls.get(
                "handshake_message"
            )

            if message not in handshake_messages:

                encrypted.append(
                    packet
                )

        return {

            "packets":
                len(encrypted),

            "bytes":
                sum(
                    p.get(
                        "length",
                        0
                    )
                    for p in encrypted
                ),

            "status":
                "Encrypted traffic observed; not decrypted.",
        }

    @staticmethod
    def duration(start, end):

        if not start or not end:
            return None

        try:

            a = datetime.fromisoformat(
                start
            )

            b = datetime.fromisoformat(
                end
            )

            return (
                b - a
            ).total_seconds()

        except Exception:

            return None

    def report(self):

        connections = []

        for connection in self.connections.values():

            connections.append({

                "connection_id":
                    connection["connection_id"],

                "client": {
                    "ip":
                        connection["client_ip"],
                    "port":
                        connection["client_port"],
                },

                "server": {
                    "ip":
                        connection["server_ip"],
                    "port":
                        connection["server_port"],
                },

                "protocol":
                    connection["protocol"],

                "start_time":
                    connection["start_time"],

                "end_time":
                    connection["end_time"],

                "duration":
                    connection["duration"],

                "total_packets":
                    len(connection["packets"]),

                "total_bytes":
                    connection["total_bytes"],

                "client_packets":
                    connection["client_packets"],

                "server_packets":
                    connection["server_packets"],

                "client_bytes":
                    connection["client_bytes"],

                "server_bytes":
                    connection["server_bytes"],

                "application_protocols":
                    connection[
                        "application_protocols"
                    ],

                "tls":
                    connection["tls"],

                "tcp_statistics":
                    connection[
                        "tcp_statistics"
                    ],

                "encrypted_statistics":
                    connection[
                        "encrypted_statistics"
                    ],

                "anomalies":
                    connection["anomalies"],

                "packets":
                    connection["packets"],
            })

        return {

            "tool":
                "Deep Network Packet Analyzer",

            "capture":
                os.path.basename(
                    self.filename
                ),

            "generated_at":
                datetime.now().isoformat(),

            "capture_statistics": {

                "total_packets":
                    len(self.packets),

                "total_bytes":
                    self.total_bytes,

                "connections":
                    len(self.connections),

                "protocols":
                    dict(self.protocols),

                "files_detected":
                    len(self.files),
            },

            "files":
                self.files,

            "global_warnings":
                self.global_warnings,

            "connections":
                connections,

            "packets":
                self.packets,
        }


# ============================================================
# TXT REPORT
# ============================================================

def write_txt(report, filename):

    with open(
        filename,
        "w",
        encoding="utf-8"
    ) as f:

        f.write(
            "=" * 90
            + "\n"
        )

        f.write(
            "              DEEP NETWORK PACKET ANALYZER\n"
        )

        f.write(
            "=" * 90
            + "\n\n"
        )

        stats = report[
            "capture_statistics"
        ]

        f.write(
            "[CAPTURE SUMMARY]\n"
        )

        f.write(
            "-" * 90
            + "\n"
        )

        f.write(
            f"File             : "
            f"{report['capture']}\n"
        )

        f.write(
            f"Packets          : "
            f"{stats['total_packets']}\n"
        )

        f.write(
            f"Bytes            : "
            f"{stats['total_bytes']}\n"
        )

        f.write(
            f"Connections      : "
            f"{stats['connections']}\n"
        )

        f.write(
            f"Files Detected   : "
            f"{stats['files_detected']}\n"
        )

        f.write(
            "\n[PROTOCOL STATISTICS]\n"
        )

        for protocol, count in sorted(
            stats["protocols"].items()
        ):

            f.write(
                f"{protocol:<20} {count}\n"
            )

        # ====================================================
        # FILES
        # ====================================================

        f.write(
            "\n\n"
            + "=" * 90
            + "\n"
        )

        f.write(
            "                         FILE ANALYSIS\n"
        )

        f.write(
            "=" * 90
            + "\n"
        )

        if not report["files"]:

            f.write(
                "No identifiable file metadata observed.\n"
            )

        for index, file_info in enumerate(
            report["files"],
            start=1
        ):

            f.write(
                f"\nFILE #{index}\n"
            )

            f.write(
                "-" * 60
                + "\n"
            )

            f.write(
                f"Name          : "
                f"{file_info.get('filename')}\n"
            )

            f.write(
                f"Type          : "
                f"{file_info.get('type')}\n"
            )

            f.write(
                f"Extension     : "
                f"{file_info.get('extension')}\n"
            )

            f.write(
                f"MIME Type     : "
                f"{file_info.get('mime_type')}\n"
            )

            f.write(
                f"Content Size  : "
                f"{file_info.get('content_length')}\n"
            )

            f.write(
                f"Direction     : "
                f"{file_info.get('direction')}\n"
            )

            f.write(
                f"Connection    : "
                f"{file_info.get('connection_id')}\n"
            )

            f.write(
                f"Packet        : "
                f"{file_info.get('packet_number')}\n"
            )

            f.write(
                f"Detection     : "
                f"{file_info.get('detection')}\n"
            )

            f.write(
                f"Text File     : "
                f"{file_info.get('text_file')}\n"
            )

            f.write(
                f"Magic Bytes   : "
                f"{file_info.get('magic_signature')}\n"
            )

            f.write(
                f"URI           : "
                f"{file_info.get('uri')}\n"
            )

        # ====================================================
        # CONNECTIONS
        # ====================================================

        for connection in report[
            "connections"
        ]:

            f.write(
                "\n\n"
                + "=" * 90
                + "\n"
            )

            f.write(
                f"                       CONNECTION #"
                f"{connection['connection_id']}\n"
            )

            f.write(
                "=" * 90
                + "\n"
            )

            f.write(
                "\n[1] NETWORK CONNECTION\n"
            )

            f.write(
                f"Client       : "
                f"{connection['client']['ip']}:"
                f"{connection['client']['port']}\n"
            )

            f.write(
                f"Server       : "
                f"{connection['server']['ip']}:"
                f"{connection['server']['port']}\n"
            )

            f.write(
                f"Protocol     : "
                f"{connection['protocol']}\n"
            )

            f.write(
                f"Start        : "
                f"{connection['start_time']}\n"
            )

            f.write(
                f"End          : "
                f"{connection['end_time']}\n"
            )

            f.write(
                f"Duration     : "
                f"{connection['duration']}\n"
            )

            f.write(
                f"Packets      : "
                f"{connection['total_packets']}\n"
            )

            f.write(
                f"Bytes        : "
                f"{connection['total_bytes']}\n"
            )

            f.write(
                "\n[2] DIRECTION STATISTICS\n"
            )

            f.write(
                f"Client → Server Packets : "
                f"{connection['client_packets']}\n"
            )

            f.write(
                f"Server → Client Packets : "
                f"{connection['server_packets']}\n"
            )

            f.write(
                f"Client → Server Bytes   : "
                f"{connection['client_bytes']}\n"
            )

            f.write(
                f"Server → Client Bytes   : "
                f"{connection['server_bytes']}\n"
            )

            f.write(
                "\n[3] APPLICATION PROTOCOLS\n"
            )

            for protocol in connection[
                "application_protocols"
            ]:

                f.write(
                    f"  {protocol}\n"
                )

            # TLS
            tls = connection["tls"]

            if tls["versions"]:

                f.write(
                    "\n[4] TLS ANALYSIS\n"
                )

                f.write(
                    f"TLS Versions       : "
                    f"{tls['versions']}\n"
                )

                f.write(
                    f"Handshake Messages : "
                    f"{tls['handshake_messages']}\n"
                )

                f.write(
                    f"Cipher Suites      : "
                    f"{tls['cipher_suites']}\n"
                )

                f.write(
                    f"SNI                : "
                    f"{tls['sni']}\n"
                )

                f.write(
                    f"ALPN               : "
                    f"{tls['alpn']}\n"
                )

                f.write(
                    f"Supported Groups   : "
                    f"{tls['supported_groups']}\n"
                )

                f.write(
                    f"Signature Algorithms: "
                    f"{tls['signature_algorithms']}\n"
                )

                f.write(
                    f"Key Share          : "
                    f"{tls['key_share']}\n"
                )

                f.write(
                    "\nCryptographic Profile:\n"
                )

                for key, value in tls[
                    "crypto_profile"
                ].items():

                    f.write(
                        f"  {key:<25}: "
                        f"{value}\n"
                    )

                f.write(
                    f"Certificate Public Key: "
                    f"{tls['certificate_public_key']}\n"
                )

            # TCP
            f.write(
                "\n[5] TCP STATISTICS\n"
            )

            for key, value in connection[
                "tcp_statistics"
            ].items():

                f.write(
                    f"{key:<15}: {value}\n"
                )

            # Encryption
            f.write(
                "\n[6] ENCRYPTED TRAFFIC\n"
            )

            for key, value in connection[
                "encrypted_statistics"
            ].items():

                f.write(
                    f"{key:<20}: {value}\n"
                )

            # Anomalies
            f.write(
                "\n[7] OBSERVATIONS / WARNINGS\n"
            )

            if not connection["anomalies"]:

                f.write(
                    "No unusual observations.\n"
                )

            for warning in connection[
                "anomalies"
            ]:

                f.write(
                    f"[{warning['severity']}] "
                    f"{warning['type']} - "
                    f"{warning['message']}\n"
                )

            # Packets
            f.write(
                "\n[8] PACKET-BY-PACKET DETAILS\n"
            )

            for packet in connection[
                "packets"
            ]:

                f.write(
                    "\n"
                    + "-" * 70
                    + "\n"
                )

                f.write(
                    f"Packet #{packet['packet_number']}\n"
                )

                f.write(
                    f"Time       : "
                    f"{packet['timestamp']}\n"
                )

                f.write(
                    f"Direction  : "
                    f"{packet.get('direction')}\n"
                )

                f.write(
                    f"Length     : "
                    f"{packet['length']}\n"
                )

                f.write(
                    f"Protocol   : "
                    f"{packet['application_protocol']}\n"
                )

                f.write(
                    f"Layers     : "
                    f"{packet['layers']}\n"
                )

                if packet["ip"]:

                    f.write(
                        f"Source IP  : "
                        f"{packet['ip'].get('source')}\n"
                    )

                    f.write(
                        f"Dest IP    : "
                        f"{packet['ip'].get('destination')}\n"
                    )

                if packet["tcp"]:

                    f.write(
                        f"TCP        : "
                        f"{packet['tcp'].get('source_port')}"
                        f" → "
                        f"{packet['tcp'].get('destination_port')}\n"
                    )

                    f.write(
                        f"Flags      : "
                        f"{packet['tcp'].get('flags')}\n"
                    )

                    f.write(
                        f"Sequence   : "
                        f"{packet['tcp'].get('sequence')}\n"
                    )

                    f.write(
                        f"ACK        : "
                        f"{packet['tcp'].get('acknowledgment')}\n"
                    )

                if packet["tls"]:

                    f.write(
                        f"TLS Message: "
                        f"{packet['tls'].get('handshake_message')}\n"
                    )

                    f.write(
                        f"TLS Version: "
                        f"{packet['tls'].get('version')}\n"
                    )

                    f.write(
                        f"Cipher     : "
                        f"{packet['tls'].get('cipher_suite')}\n"
                    )

                if packet["http"]:

                    f.write(
                        f"HTTP URI   : "
                        f"{packet['http'].get('uri')}\n"
                    )

                    f.write(
                        f"HTTP Type  : "
                        f"{packet['http'].get('content_type')}\n"
                    )

                f.write(
                    f"RAW HEX    : "
                    f"{packet['raw']['hex']}\n"
                )


# ============================================================
# JSON REPORT
# ============================================================

def write_json(report, filename):

    with open(
        filename,
        "w",
        encoding="utf-8"
    ) as f:

        json.dump(
            report,
            f,
            indent=2,
            ensure_ascii=False
        )


# ============================================================
# HTML REPORT
# ============================================================

def write_html(report, filename):

    stats = report[
        "capture_statistics"
    ]

    parts = []

    parts.append("""
<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8">

<title>Deep Network Packet Analyzer</title>

<style>

body {
    background: #0d1117;
    color: #e6edf3;
    font-family: Arial, sans-serif;
    margin: 30px;
}

h1 {
    color: #58a6ff;
}

h2 {
    color: #79c0ff;
}

h3 {
    color: #d2a8ff;
}

.card {
    background: #161b22;
    border: 1px solid #30363d;
    border-radius: 10px;
    padding: 20px;
    margin-bottom: 20px;
}

table {
    border-collapse: collapse;
    width: 100%;
}

th, td {
    border: 1px solid #30363d;
    padding: 8px;
    vertical-align: top;
}

th {
    background: #21262d;
}

.warning {
    color: #ffcc00;
}

.info {
    color: #58a6ff;
}

pre {
    background: #010409;
    padding: 12px;
    overflow-x: auto;
    white-space: pre-wrap;
    word-break: break-word;
}

.file {
    border-left: 4px solid #3fb950;
    padding-left: 15px;
    margin: 15px 0;
}

details {
    margin: 10px 0;
}

summary {
    cursor: pointer;
    color: #58a6ff;
}

</style>

</head>

<body>
""")

    parts.append(
        "<h1>Deep Network Packet Analyzer</h1>"
    )

    # --------------------------------------------------------
    # SUMMARY
    # --------------------------------------------------------

    parts.append(
        "<div class='card'>"
        "<h2>Capture Summary</h2>"
    )

    parts.append(
        f"<p><b>File:</b> "
        f"{html.escape(report['capture'])}</p>"
    )

    parts.append(
        f"<p><b>Total Packets:</b> "
        f"{stats['total_packets']}</p>"
    )

    parts.append(
        f"<p><b>Total Bytes:</b> "
        f"{stats['total_bytes']}</p>"
    )

    parts.append(
        f"<p><b>Connections:</b> "
        f"{stats['connections']}</p>"
    )

    parts.append(
        f"<p><b>Files Detected:</b> "
        f"{stats['files_detected']}</p>"
    )

    parts.append(
        "</div>"
    )

    # --------------------------------------------------------
    # FILE ANALYSIS
    # --------------------------------------------------------

    parts.append(
        "<div class='card'>"
        "<h2>File Analysis</h2>"
    )

    if not report["files"]:

        parts.append(
            "<p>No identifiable file metadata observed.</p>"
        )

    for index, file_info in enumerate(
        report["files"],
        start=1
    ):

        parts.append(
            "<div class='file'>"
        )

        parts.append(
            f"<h3>File #{index}</h3>"
        )

        parts.append(
            "<table>"
        )

        fields = {
            "Name":
                file_info.get("filename"),

            "Type":
                file_info.get("type"),

            "Extension":
                file_info.get("extension"),

            "MIME":
                file_info.get("mime_type"),

            "Content Size":
                file_info.get("content_length"),

            "Direction":
                file_info.get("direction"),

            "Connection":
                file_info.get("connection_id"),

            "Packet":
                file_info.get("packet_number"),

            "Detection":
                file_info.get("detection"),

            "URI":
                file_info.get("uri"),
        }

        for key, value in fields.items():

            parts.append(
                "<tr>"
                f"<td><b>{html.escape(str(key))}</b></td>"
                f"<td>{html.escape(str(value))}</td>"
                "</tr>"
            )

        parts.append(
            "</table>"
        )

        parts.append(
            "</div>"
        )

    parts.append(
        "</div>"
    )

    # --------------------------------------------------------
    # CONNECTIONS
    # --------------------------------------------------------

    for connection in report[
        "connections"
    ]:

        parts.append(
            "<div class='card'>"
        )

        parts.append(
            f"<h2>Connection #{connection['connection_id']}</h2>"
        )

        parts.append(
            "<table>"
        )

        overview = {
            "Protocol":
                connection["protocol"],

            "Client":
                f"{connection['client']['ip']}:"
                f"{connection['client']['port']}",

            "Server":
                f"{connection['server']['ip']}:"
                f"{connection['server']['port']}",

            "Start":
                connection["start_time"],

            "End":
                connection["end_time"],

            "Duration":
                connection["duration"],

            "Packets":
                connection["total_packets"],

            "Bytes":
                connection["total_bytes"],

            "Client → Server Packets":
                connection["client_packets"],

            "Server → Client Packets":
                connection["server_packets"],

            "Client → Server Bytes":
                connection["client_bytes"],

            "Server → Client Bytes":
                connection["server_bytes"],
        }

        for key, value in overview.items():

            parts.append(
                f"<tr>"
                f"<td><b>{html.escape(str(key))}</b></td>"
                f"<td>{html.escape(str(value))}</td>"
                f"</tr>"
            )

        parts.append(
            "</table>"
        )

        # TLS
        tls = connection["tls"]

        if tls["versions"]:

            parts.append(
                "<h3>TLS Analysis</h3>"
            )

            parts.append(
                "<pre>"
                + html.escape(
                    json.dumps(
                        tls,
                        indent=2,
                        ensure_ascii=False
                    )
                )
                + "</pre>"
            )

        # TCP
        parts.append(
            "<h3>TCP Statistics</h3>"
        )

        parts.append(
            "<pre>"
            + html.escape(
                json.dumps(
                    connection[
                        "tcp_statistics"
                    ],
                    indent=2
                )
            )
            + "</pre>"
        )

        # Encryption
        parts.append(
            "<h3>Encrypted Traffic</h3>"
        )

        parts.append(
            "<pre>"
            + html.escape(
                json.dumps(
                    connection[
                        "encrypted_statistics"
                    ],
                    indent=2
                )
            )
            + "</pre>"
        )

        # Warnings
        parts.append(
            "<h3>Observations / Warnings</h3>"
        )

        if not connection[
            "anomalies"
        ]:

            parts.append(
                "<p class='info'>"
                "No unusual observations."
                "</p>"
            )

        for warning in connection[
            "anomalies"
        ]:

            cls = (
                "warning"
                if warning["severity"]
                == "WARNING"
                else "info"
            )

            parts.append(
                f"<p class='{cls}'>"
                f"<b>{html.escape(warning['severity'])}</b> "
                f"{html.escape(warning['message'])}"
                "</p>"
            )

        # Packets
        parts.append(
            "<h3>Packet Details</h3>"
        )

        for packet in connection[
            "packets"
        ]:

            parts.append(
                "<details>"
            )

            parts.append(
                f"<summary>"
                f"Packet #{packet['packet_number']} "
                f"| {packet['length']} bytes "
                f"| {packet['application_protocol']} "
                f"| {packet.get('direction')}"
                f"</summary>"
            )

            parts.append(
                "<pre>"
                + html.escape(
                    json.dumps(
                        packet,
                        indent=2,
                        ensure_ascii=False
                    )
                )
                + "</pre>"
            )

            parts.append(
                "</details>"
            )

        parts.append(
            "</div>"
        )

    parts.append(
        "</body></html>"
    )

    with open(
        filename,
        "w",
        encoding="utf-8"
    ) as f:

        f.write(
            "".join(parts)
        )


# ============================================================
# COMMAND LINE
# ============================================================

def main():

    parser = argparse.ArgumentParser(
        description=(
            "Deep PCAP/PCAPNG network "
            "packet analyzer"
        )
    )

    parser.add_argument(
        "pcap",
        help="PCAP or PCAPNG file"
    )

    parser.add_argument(
        "--output",
        default="reports",
        help="Output directory"
    )

    args = parser.parse_args()

    if not os.path.isfile(
        args.pcap
    ):

        print(
            f"ERROR: File not found: "
            f"{args.pcap}"
        )

        return 1

    os.makedirs(
        args.output,
        exist_ok=True
    )

    analyzer = DeepAnalyzer(
        args.pcap
    )

    analyzer.process()

    report = analyzer.report()

    base = os.path.splitext(
        os.path.basename(
            args.pcap
        )
    )[0]

    txt_file = os.path.join(
        args.output,
        f"{base}_report.txt"
    )

    json_file = os.path.join(
        args.output,
        f"{base}_report.json"
    )

    html_file = os.path.join(
        args.output,
        f"{base}_report.html"
    )

    write_txt(
        report,
        txt_file
    )

    write_json(
        report,
        json_file
    )

    write_html(
        report,
        html_file
    )

    print()
    print("=" * 160)
    print("ANALYSIS COMPLETE")
    print("=" * 160)
    print(f"TXT  : {txt_file}")
    print(f"JSON : {json_file}")
    print(f"HTML : {html_file}")
    print(
        f"Files: "
        f"{report['capture_statistics']['files_detected']}"
    )
    print(
        f"Connections: "
        f"{report['capture_statistics']['connections']}"
    )

    return 0


if __name__ == "__main__":
    raise SystemExit(
        main()
    )
