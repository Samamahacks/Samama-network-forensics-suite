# ============================================================
# pcap_organizer.py
#
# Standalone defensive PCAP organizer / forensic analyzer
#
# Input:
#     capture.pcap
#
# Output:
#     organized_report.json
#
# Features:
#   - Streaming PCAP processing
#   - Small batch processing
#   - Flow / 5-tuple grouping
#   - TCP sequence tracking
#   - ACK tracking
#   - Out-of-order detection
#   - Retransmission detection
#   - Duplicate detection
#   - Sequence-gap detection
#   - Overlap detection
#   - TCP handshake detection
#   - Unexpected endpoint detection
#   - Payload SHA-256
#   - Human-readable terminal report
#   - JSON forensic report
#
# Defensive PCAP analysis only.
# ============================================================

import argparse
import hashlib
import ipaddress
import json
import os
import sys
from collections import defaultdict

from scapy.utils import PcapReader
from scapy.layers.inet import IP, TCP, UDP


# ============================================================
# CONFIGURATION
# ============================================================

# Important:
# Ye "maximum PCAP size" nahi hai.
# Sirf ek waqt mein processing batch ka size hai.

BATCH_SIZE = 200

# Memory safety limits
MAX_ACTIVE_FLOWS = 100_000

# Per-flow sequence information limit.
MAX_SEGMENTS_PER_FLOW = 20_000

# Maximum number of suspicious events kept per flow.
MAX_EVENTS_PER_FLOW = 500

# Output file
DEFAULT_OUTPUT = "organized_report.json"


# ============================================================
# FLOW STATE
# ============================================================

class FlowState:

    def __init__(self, flow_id, key):

        self.flow_id = flow_id

        self.key = key

        self.client_ip = None
        self.client_port = None

        self.server_ip = None
        self.server_port = None

        self.protocol = key[4]

        self.packet_count = 0

        self.first_packet = None
        self.last_packet = None

        self.first_timestamp = None
        self.last_timestamp = None

        self.syn_seen = False
        self.syn_ack_seen = False
        self.ack_seen = False

        self.handshake_complete = False

        self.next_expected_seq = {
            0: None,
            1: None
        }

        self.seen_segments = {
            0: set(),
            1: set()
        }

        self.sequence_ranges = {
            0: [],
            1: []
        }

        self.events = []

        self.retransmissions = 0
        self.duplicates = 0
        self.out_of_order = 0
        self.sequence_gaps = 0
        self.overlaps = 0

        self.unexpected_endpoints = 0

    def add_event(self, event):

        if len(self.events) >= MAX_EVENTS_PER_FLOW:
            return

        self.events.append(event)


# ============================================================
# IP HELPERS
# ============================================================

def is_private_ip(value):

    try:
        return ipaddress.ip_address(value).is_private

    except ValueError:
        return False


# ============================================================
# FLOW KEY
# ============================================================

def make_flow_key(packet):

    if IP not in packet:
        return None

    ip_layer = packet[IP]

    src = ip_layer.src
    dst = ip_layer.dst

    protocol = ip_layer.proto

    if TCP in packet:

        tcp = packet[TCP]

        sport = tcp.sport
        dport = tcp.dport

    elif UDP in packet:

        udp = packet[UDP]

        sport = udp.sport
        dport = udp.dport

    else:

        sport = 0
        dport = 0

    # Direction-independent key.
    endpoint_a = (src, sport)
    endpoint_b = (dst, dport)

    if endpoint_a <= endpoint_b:

        return (
            endpoint_a[0],
            endpoint_b[0],
            endpoint_a[1],
            endpoint_b[1],
            protocol,
        )

    return (
        endpoint_b[0],
        endpoint_a[0],
        endpoint_b[1],
        endpoint_a[1],
        protocol,
    )


# ============================================================
# DIRECTION
# ============================================================

def get_direction(flow, src, sport):

    if flow.client_ip is None:

        flow.client_ip = src
        flow.client_port = sport

        return 0

    if (
        src == flow.client_ip
        and sport == flow.client_port
    ):

        return 0

    if flow.server_ip is None:

        flow.server_ip = src
        flow.server_port = sport

        return 1

    if (
        src == flow.server_ip
        and sport == flow.server_port
    ):

        return 1

    return -1


# ============================================================
# PAYLOAD HASH
# ============================================================

def payload_hash(packet):

    try:

        raw_payload = bytes(
            packet.payload.payload
        )

        if not raw_payload:
            return None

        return hashlib.sha256(
            raw_payload
        ).hexdigest()

    except Exception:

        return None


# ============================================================
# TCP HANDSHAKE
# ============================================================

def process_handshake(
    flow,
    packet,
    capture_index,
):

    tcp = packet[TCP]

    flags = int(tcp.flags)

    # SYN
    if flags & 0x02 and not flags & 0x10:

        if not flow.syn_seen:

            flow.syn_seen = True

            flow.add_event({
                "type": "TCP_HANDSHAKE",
                "stage": "SYN",
                "packet": capture_index,
                "severity": "INFO",
            })

    # SYN + ACK
    elif flags & 0x12 == 0x12:

        if not flow.syn_ack_seen:

            flow.syn_ack_seen = True

            flow.add_event({
                "type": "TCP_HANDSHAKE",
                "stage": "SYN-ACK",
                "packet": capture_index,
                "severity": "INFO",
            })

    # ACK after SYN/SYN-ACK
    elif flags & 0x10:

        if (
            flow.syn_seen
            and flow.syn_ack_seen
            and not flow.ack_seen
        ):

            flow.ack_seen = True

            flow.handshake_complete = True

            flow.add_event({
                "type": "TCP_HANDSHAKE",
                "stage": "ACK",
                "packet": capture_index,
                "severity": "INFO",
            })


# ============================================================
# TCP SEGMENT ANALYSIS
# ============================================================

def process_tcp_segment(
    flow,
    packet,
    capture_index,
    timestamp,
    direction,
):

    tcp = packet[TCP]

    seq = int(tcp.seq)

    ack = int(tcp.ack)

    flags = str(tcp.flags)

    payload = bytes(tcp.payload)

    length = len(payload)

    end_seq = seq + length

    # Handshake
    process_handshake(
        flow,
        packet,
        capture_index,
    )

    # No payload means there is no payload
    # sequence range to reconstruct.
    if length == 0:

        return {
            "seq": seq,
            "ack": ack,
            "length": 0,
            "flags": flags,
            "payload_hash": None,
        }

    segment_key = (
        seq,
        end_seq,
        hashlib.sha256(
            payload
        ).hexdigest(),
    )

    # --------------------------------------------------------
    # Duplicate / retransmission
    # --------------------------------------------------------

    if segment_key in flow.seen_segments[direction]:

        flow.duplicates += 1

        flow.add_event({

            "type": "DUPLICATE_OR_RETRANSMISSION",

            "packet": capture_index,

            "sequence": seq,

            "end_sequence": end_seq,

            "severity": "LOW",
        })

    else:

        flow.seen_segments[direction].add(
            segment_key
        )

    # --------------------------------------------------------
    # Segment limit
    # --------------------------------------------------------

    if (
        len(flow.seen_segments[direction])
        <= MAX_SEGMENTS_PER_FLOW
    ):

        flow.sequence_ranges[
            direction
        ].append(
            (
                seq,
                end_seq,
                capture_index,
            )
        )

    # --------------------------------------------------------
    # Expected sequence
    # --------------------------------------------------------

    expected = flow.next_expected_seq[
        direction
    ]

    if expected is None:

        flow.next_expected_seq[
            direction
        ] = end_seq

    else:

        # Perfect continuation
        if seq == expected:

            flow.next_expected_seq[
                direction
            ] = end_seq

        # Future sequence -> gap / out-of-order
        elif seq > expected:

            flow.sequence_gaps += 1

            flow.out_of_order += 1

            flow.add_event({

                "type": "SEQUENCE_GAP",

                "packet": capture_index,

                "expected_sequence": expected,

                "received_sequence": seq,

                "missing_bytes": seq - expected,

                "severity": "MEDIUM",
            })

        # Earlier sequence
        elif seq < expected:

            flow.out_of_order += 1

            # Does it overlap the already observed range?
            if end_seq > expected:

                flow.overlaps += 1

                flow.add_event({

                    "type": "SEQUENCE_OVERLAP",

                    "packet": capture_index,

                    "expected_sequence": expected,

                    "received_sequence": seq,

                    "end_sequence": end_seq,

                    "severity": "MEDIUM",
                })

    return {

        "seq": seq,

        "ack": ack,

        "length": length,

        "flags": flags,

        "payload_hash":
            hashlib.sha256(
                payload
            ).hexdigest(),
    }


# ============================================================
# PACKET PROCESSOR
# ============================================================

def process_packet(
    packet,
    capture_index,
    flows,
    ordered_packets,
    unexpected_ips,
):

    if IP not in packet:

        return

    ip_layer = packet[IP]

    src = ip_layer.src
    dst = ip_layer.dst

    # --------------------------------------------------------
    # Flow
    # --------------------------------------------------------

    flow_key = make_flow_key(packet)

    if flow_key is None:

        return

    # --------------------------------------------------------
    # New flow
    # --------------------------------------------------------

    if flow_key not in flows:

        if len(flows) >= MAX_ACTIVE_FLOWS:

            # Prevent uncontrolled memory growth.
            return

        flow_id = len(flows) + 1

        flows[flow_key] = FlowState(
            flow_id,
            flow_key
        )

    flow = flows[flow_key]

    flow.packet_count += 1

    # --------------------------------------------------------
    # Timestamp
    # --------------------------------------------------------

    try:

        timestamp = float(
            packet.time
        )

    except Exception:

        timestamp = None

    if flow.first_packet is None:

        flow.first_packet = capture_index
        flow.first_timestamp = timestamp

    flow.last_packet = capture_index
    flow.last_timestamp = timestamp

    # --------------------------------------------------------
    # Direction
    # --------------------------------------------------------

    if TCP in packet:

        sport = int(packet[TCP].sport)

    elif UDP in packet:

        sport = int(packet[UDP].sport)

    else:

        sport = 0

    direction = get_direction(
        flow,
        src,
        sport
    )

    # --------------------------------------------------------
    # Unexpected endpoint
    # --------------------------------------------------------

    if direction == -1:

        flow.unexpected_endpoints += 1

        unexpected_ips.add(src)
        unexpected_ips.add(dst)

        flow.add_event({

            "type":
                "UNEXPECTED_ENDPOINT",

            "packet":
                capture_index,

            "source_ip":
                src,

            "destination_ip":
                dst,

            "severity":
                "HIGH",
        })

    # --------------------------------------------------------
    # TCP
    # --------------------------------------------------------

    tcp_data = None

    if TCP in packet and direction >= 0:

        tcp_data = process_tcp_segment(

            flow,

            packet,

            capture_index,

            timestamp,

            direction,
        )

    # --------------------------------------------------------
    # Packet record
    # --------------------------------------------------------

    record = {

        "capture_index":
            capture_index,

        "timestamp":
            timestamp,

        "src_ip":
            src,

        "dst_ip":
            dst,

        "protocol":
            "TCP"
            if TCP in packet
            else
            "UDP"
            if UDP in packet
            else
            str(ip_layer.proto),

        "flow_id":
            flow.flow_id,

        "length":
            len(bytes(packet)),

        "payload_hash":
            payload_hash(packet),
    }

    if tcp_data:

        record.update({

            "tcp_sequence":
                tcp_data["seq"],

            "tcp_ack":
                tcp_data["ack"],

            "tcp_payload_length":
                tcp_data["length"],

            "tcp_flags":
                tcp_data["flags"],

        })

    ordered_packets.append(record)


# ============================================================
# FLOW SUMMARY
# ============================================================

def build_flow_summary(flows):

    result = []

    for flow in flows.values():

        result.append({

            "flow_id":
                flow.flow_id,

            "client":
                (
                    f"{flow.client_ip}:"
                    f"{flow.client_port}"
                    if flow.client_ip
                    else None
                ),

            "server":
                (
                    f"{flow.server_ip}:"
                    f"{flow.server_port}"
                    if flow.server_ip
                    else None
                ),

            "protocol":
                flow.protocol,

            "first_packet":
                flow.first_packet,

            "last_packet":
                flow.last_packet,

            "packet_count":
                flow.packet_count,

            "tcp_handshake": {

                "syn":
                    flow.syn_seen,

                "syn_ack":
                    flow.syn_ack_seen,

                "ack":
                    flow.ack_seen,

                "complete":
                    flow.handshake_complete,
            },

            "reassembly_analysis": {

                "retransmissions":
                    flow.retransmissions,

                "duplicates":
                    flow.duplicates,

                "out_of_order":
                    flow.out_of_order,

                "sequence_gaps":
                    flow.sequence_gaps,

                "overlaps":
                    flow.overlaps,

            },

            "unexpected_endpoints":
                flow.unexpected_endpoints,

            "events":
                flow.events,
        })

    return result


# ============================================================
# PCAP ANALYSIS
# ============================================================

def analyze_pcap(
    filename,
    output_filename,
):

    if not os.path.isfile(filename):

        print(
            f"ERROR: PCAP not found: {filename}"
        )

        return False

    print()
    print("=" * 72)
    print("              PCAP ORGANIZER / ANALYZER")
    print("=" * 72)

    print(
        f"[+] Input : {filename}"
    )

    print(
        f"[+] Batch : {BATCH_SIZE} packets"
    )

    print(
        "[+] Mode  : Streaming"
    )

    print()

    flows = {}

    ordered_packets = []

    unexpected_ips = set()

    packet_count = 0

    batch_count = 0

    malformed = 0

    try:

        with PcapReader(filename) as reader:

            batch = []

            for packet in reader:

                batch.append(packet)

                if len(batch) >= BATCH_SIZE:

                    batch_count += 1

                    for item in batch:

                        packet_count += 1

                        try:

                            process_packet(

                                item,

                                packet_count,

                                flows,

                                ordered_packets,

                                unexpected_ips,
                            )

                        except Exception as exc:

                            malformed += 1

                    batch.clear()

                    if (
                        batch_count % 50
                        == 0
                    ):

                        print(
                            f"\r[+] Processed: "
                            f"{packet_count:,} packets",
                            end="",
                            flush=True,
                        )

            # Remaining packets
            for item in batch:

                packet_count += 1

                try:

                    process_packet(

                        item,

                        packet_count,

                        flows,

                        ordered_packets,

                        unexpected_ips,
                    )

                except Exception:

                    malformed += 1

    except Exception as exc:

        print()

        print(
            f"\nERROR while reading PCAP: {exc}"
        )

        return False

    print()

    # --------------------------------------------------------
    # Sort packet records
    # --------------------------------------------------------

    ordered_packets.sort(

        key=lambda x: (

            x.get("flow_id", 0),

            x.get(
                "tcp_sequence",
                -1
            ),

            x.get(
                "capture_index",
                0
            ),

        )
    )

    # --------------------------------------------------------
    # Report
    # --------------------------------------------------------

    report = {

        "tool":
            "PCAP Organizer / Defensive Analyzer",

        "input_file":
            os.path.abspath(filename),

        "configuration": {

            "batch_size":
                BATCH_SIZE,

            "max_active_flows":
                MAX_ACTIVE_FLOWS,

            "max_segments_per_flow":
                MAX_SEGMENTS_PER_FLOW,

        },

        "statistics": {

            "packets_processed":
                packet_count,

            "malformed_or_failed":
                malformed,

            "flows":
                len(flows),

            "unexpected_ip_count":
                len(unexpected_ips),

        },

        "flows":
            build_flow_summary(flows),

        "unexpected_ips":
            sorted(unexpected_ips),

        "ordered_packets":
            ordered_packets,
    }

    # --------------------------------------------------------
    # JSON
    # --------------------------------------------------------

    try:

        with open(
            output_filename,
            "w",
            encoding="utf-8",
        ) as file:

            json.dump(
                report,
                file,
                indent=2,
                ensure_ascii=False,
            )

    except Exception as exc:

        print(
            f"ERROR writing JSON: {exc}"
        )

        return False

    # --------------------------------------------------------
    # Console summary
    # --------------------------------------------------------

    print()
    print("=" * 72)
    print("                         SUMMARY")
    print("=" * 72)

    print(
        f"Packets processed : "
        f"{packet_count:,}"
    )

    print(
        f"Flows detected    : "
        f"{len(flows):,}"
    )

    print(
        f"Malformed/errors   : "
        f"{malformed:,}"
    )

    print(
        f"Unexpected IPs    : "
        f"{len(unexpected_ips):,}"
    )

    print()

    print(
        "TCP HANDSHAKES"
    )

    print("-" * 72)

    handshake_count = 0

    for flow in flows.values():

        if flow.handshake_complete:

            handshake_count += 1

            print(
                f"\033[1;32m"
                f"[HANDSHAKE] "
                f"Flow #{flow.flow_id} "
                f"{flow.client_ip}:"
                f"{flow.client_port} -> "
                f"{flow.server_ip}:"
                f"{flow.server_port}"
                f"\033[0m"
            )

    if handshake_count == 0:

        print("No complete TCP handshake detected.")

    print()

    print(
        "ANOMALIES"
    )

    print("-" * 72)

    anomaly_count = 0

    for flow in flows.values():

        if (
            flow.sequence_gaps
            or flow.overlaps
            or flow.out_of_order
            or flow.unexpected_endpoints
        ):

            anomaly_count += 1

            print(
                f"\033[1;33m"
                f"[FLOW #{flow.flow_id}] "
                f"gap={flow.sequence_gaps}, "
                f"overlap={flow.overlaps}, "
                f"out_of_order={flow.out_of_order}, "
                f"unexpected_ip="
                f"{flow.unexpected_endpoints}"
                f"\033[0m"
            )

    if anomaly_count == 0:

        print(
            "\033[1;32m"
            "No sequence/endpoint anomalies detected."
            "\033[0m"
        )

    print()

    print(
        f"[+] JSON report written to:"
    )

    print(
        f"    {output_filename}"
    )

    print("=" * 72)

    return True


# ============================================================
# MAIN
# ============================================================

def main():

    parser = argparse.ArgumentParser(

        description=(
            "Streaming defensive PCAP "
            "organizer and TCP sequence analyzer."
        )
    )

    parser.add_argument(

        "pcap",

        nargs="?",

        default="capture.pcap",

        help=(
            "Input PCAP file "
            "(default: capture.pcap)"
        ),
    )

    parser.add_argument(

        "--output",

        default=DEFAULT_OUTPUT,

        help=(
            "JSON output filename "
            "(default: organized_report.json)"
        ),
    )

    args = parser.parse_args()

    success = analyze_pcap(

        args.pcap,

        args.output,
    )

    return 0 if success else 1


# ============================================================
# ENTRY POINT
# ============================================================

if __name__ == "__main__":

    raise SystemExit(
        main()
    )
