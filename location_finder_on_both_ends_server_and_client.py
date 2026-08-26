# ============================================================
# ip_intelligence.py
# Standalone IP / Domain / Service Intelligence Analyzer
# ============================================================

import argparse
import ipaddress
import json
import re
import sys
from functools import lru_cache

import requests


# ============================================================
# CONFIGURATION
# ============================================================

API_TIMEOUT = 8

USER_AGENT = (
    "Standalone-IP-Intelligence-Analyzer/1.0"
)


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
# IP CLASSIFICATION
# ============================================================

def classify_ip(ip):
    """
    IP ko PUBLIC / PRIVATE / LOOPBACK / LINK-LOCAL
    etc. mein classify karta hai.
    """

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
# IP GEOLOCATION
# ============================================================

@lru_cache(maxsize=2048)
def get_ip_geolocation(ip):
    """
    Public IP ki approximate geolocation aur network
    information retrieve karta hai.

    Private/local IP ke liye Internet geolocation
    applicable nahi hoti.
    """

    classification = classify_ip(ip)

    result = {
        "ip": ip,
        "type": classification["type"],

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

    # --------------------------------------------------------
    # Local/private IP
    # --------------------------------------------------------

    if not classification["is_public"]:

        result["confidence"] = "HIGH"

        result["source"] = (
            "Local IP classification"
        )

        result["note"] = (
            "Internet geolocation is not applicable "
            "to this address."
        )

        return result

    # --------------------------------------------------------
    # Public IP lookup
    # --------------------------------------------------------

    try:

        url = f"https://ipwho.is/{ip}"

        response = requests.get(
            url,
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
                "IP intelligence service",
        })

    except requests.RequestException as exc:

        result["error"] = (
            f"Network/API error: {exc}"
        )

    except Exception as exc:

        result["error"] = str(exc)

    return result


def security_flag(value):
    """
    Security provider ke boolean result ko
    readable classification mein convert karta hai.
    """

    if value is True:
        return "LIKELY"

    if value is False:
        return "NO EVIDENCE"

    return "UNKNOWN"


# ============================================================
# DOMAIN NORMALIZATION
# ============================================================

def normalize_domain(domain):

    if not domain:
        return None

    domain = str(domain).strip().lower()

    # URL accidentally pass ho to hostname extract
    domain = re.sub(
        r"^https?://",
        "",
        domain
    )

    domain = domain.split("/")[0]

    # Port remove
    domain = domain.split(":")[0]

    # Wildcard remove
    domain = domain.lstrip("*.")

    # Trailing dot remove
    domain = domain.rstrip(".")

    return domain or None


# ============================================================
# DOMAIN SERVICE MATCHING
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

    # --------------------------------------------------------
    # Exact match
    # --------------------------------------------------------

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

            "note":
                "Observed domain exactly matches "
                "a known service domain.",
        })

        return result

    # --------------------------------------------------------
    # Subdomain match
    # --------------------------------------------------------

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

                "note":
                    "Observed hostname is a subdomain "
                    "of a known service domain.",
            })

            return result

    # --------------------------------------------------------
    # Related infrastructure
    # --------------------------------------------------------

    for known_domain, info in SERVICE_DATABASE.items():

        for related_domain in info.get(
            "related_domains",
            []
        ):

            if (
                domain == related_domain
                or domain.endswith(
                    "." + related_domain
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
                        "Domain is associated with known "
                        "service infrastructure, but does "
                        "not prove the exact website/page.",
                })

                return result

    return result


# ============================================================
# DOMAIN INPUT ANALYSIS
# ============================================================

def analyze_domain(domain):

    domain = normalize_domain(domain)

    service = find_service(domain)

    return {
        "domain": domain,
        "service_intelligence": service,
    }


# ============================================================
# CLIENT APPLICATION DETECTION
# ============================================================

def detect_application(
    user_agent=None,
    alpn=None,
):
    """
    Browser/application identification.

    User-Agent available ho to confidence HIGH hota hai.
    Sirf ALPN se browser prove nahi hota.
    """

    result = {
        "application": "Unknown",
        "confidence": "UNKNOWN",
        "evidence": [],
        "note": None,
    }

    ua = (
        user_agent.lower()
        if user_agent
        else ""
    )

    alpn_value = (
        alpn.lower()
        if alpn
        else ""
    )

    # --------------------------------------------------------
    # User-Agent based detection
    # --------------------------------------------------------

    if "edg/" in ua:

        return {
            "application":
                "Microsoft Edge",

            "confidence":
                "HIGH",

            "evidence": [
                "HTTP User-Agent"
            ],

            "note":
                "Browser identified from HTTP User-Agent.",
        }

    if (
        "chrome/" in ua
        and "chromium" not in ua
    ):

        return {
            "application":
                "Google Chrome",

            "confidence":
                "HIGH",

            "evidence": [
                "HTTP User-Agent"
            ],

            "note":
                "Browser identified from HTTP User-Agent.",
        }

    if "firefox/" in ua:

        return {
            "application":
                "Mozilla Firefox",

            "confidence":
                "HIGH",

            "evidence": [
                "HTTP User-Agent"
            ],

            "note":
                "Browser identified from HTTP User-Agent.",
        }

    if "safari/" in ua and "chrome" not in ua:

        return {
            "application":
                "Apple Safari",

            "confidence":
                "HIGH",

            "evidence": [
                "HTTP User-Agent"
            ],

            "note":
                "Browser identified from HTTP User-Agent.",
        }

    # --------------------------------------------------------
    # ALPN
    # --------------------------------------------------------

    if "h2" in alpn_value:

        return {
            "application":
                "HTTP/2-capable client",

            "confidence":
                "LOW",

            "evidence": [
                "TLS ALPN = h2"
            ],

            "note":
                "ALPN does not prove a specific browser.",
        }

    if "http/1.1" in alpn_value:

        return {
            "application":
                "HTTP/1.1-capable client",

            "confidence":
                "LOW",

            "evidence": [
                "TLS ALPN = http/1.1"
            ],

            "note":
                "ALPN does not prove a specific browser.",
        }

    return result


# ============================================================
# COMPLETE ANALYSIS
# ============================================================

def analyze(
    ip=None,
    domain=None,
    user_agent=None,
    alpn=None,
):
    """
    Complete standalone intelligence analysis.
    """

    result = {
        "analyzer":
            "Standalone IP / Domain Intelligence",

        "input": {
            "ip": ip,
            "domain": domain,
            "user_agent": user_agent,
            "alpn": alpn,
        },

        "ip_intelligence": None,

        "domain_intelligence": None,

        "application_intelligence": None,
    }

    if ip:

        result["ip_intelligence"] = (
            get_ip_geolocation(ip)
        )

    if domain:

        result["domain_intelligence"] = (
            analyze_domain(domain)
        )

    result["application_intelligence"] = (
        detect_application(
            user_agent=user_agent,
            alpn=alpn,
        )
    )

    return result


# ============================================================
# HUMAN-READABLE OUTPUT
# ============================================================

def print_separator(char="=", length=70):

    print(char * length)


def print_ip_result(info):

    print_separator()

    print("[IP INTELLIGENCE]")

    print_separator("-")

    print(
        f"IP Address       : "
        f"{info.get('ip')}"
    )

    print(
        f"IP Type          : "
        f"{info.get('type')}"
    )

    print(
        f"Country          : "
        f"{info.get('country')}"
    )

    print(
        f"Country Code     : "
        f"{info.get('country_code')}"
    )

    print(
        f"Region           : "
        f"{info.get('region')}"
    )

    print(
        f"City             : "
        f"{info.get('city')}"
    )

    print(
        f"Postal Code      : "
        f"{info.get('postal')}"
    )

    print(
        f"Timezone         : "
        f"{info.get('timezone')}"
    )

    print(
        f"ISP              : "
        f"{info.get('isp')}"
    )

    print(
        f"Organization     : "
        f"{info.get('organization')}"
    )

    print(
        f"ASN              : "
        f"{info.get('asn')}"
    )

    print(
        f"Hosting          : "
        f"{info.get('hosting')}"
    )

    print(
        f"VPN              : "
        f"{info.get('vpn')}"
    )

    print(
        f"Proxy            : "
        f"{info.get('proxy')}"
    )

    print(
        f"Tor              : "
        f"{info.get('tor')}"
    )

    print(
        f"Latitude         : "
        f"{info.get('latitude')}"
    )

    print(
        f"Longitude        : "
        f"{info.get('longitude')}"
    )

    print(
        f"Confidence       : "
        f"{info.get('confidence')}"
    )

    print(
        f"Source           : "
        f"{info.get('source')}"
    )

    if info.get("note"):

        print(
            f"Note             : "
            f"{info.get('note')}"
        )

    if info.get("error"):

        print(
            f"Error            : "
            f"{info.get('error')}"
        )


def print_domain_result(info):

    print_separator()

    print("[DOMAIN / SERVICE INTELLIGENCE]")

    print_separator("-")

    print(
        f"Observed Domain  : "
        f"{info.get('domain')}"
    )

    service = info.get(
        "service_intelligence",
        {}
    )

    print(
        f"Service          : "
        f"{service.get('service')}"
    )

    print(
        f"Provider         : "
        f"{service.get('provider')}"
    )

    print(
        f"Category         : "
        f"{service.get('category')}"
    )

    print(
        f"Match Type       : "
        f"{service.get('match_type')}"
    )

    print(
        f"Matched Domain   : "
        f"{service.get('matched_domain')}"
    )

    print(
        f"Confidence       : "
        f"{service.get('confidence')}"
    )

    print(
        f"Related Domains  : "
        f"{service.get('related_domains')}"
    )

    if service.get("note"):

        print(
            f"Note             : "
            f"{service.get('note')}"
        )


def print_application_result(info):

    print_separator()

    print("[APPLICATION INTELLIGENCE]")

    print_separator("-")

    print(
        f"Application      : "
        f"{info.get('application')}"
    )

    print(
        f"Confidence       : "
        f"{info.get('confidence')}"
    )

    print(
        f"Evidence         : "
        f"{info.get('evidence')}"
    )

    if info.get("note"):

        print(
            f"Note             : "
            f"{info.get('note')}"
        )


def print_full_result(result):

    print()

    print_separator()

    print(
        "      STANDALONE NETWORK INTELLIGENCE ANALYZER"
    )

    print_separator()

    ip_info = result.get(
        "ip_intelligence"
    )

    if ip_info:

        print_ip_result(
            ip_info
        )

    domain_info = result.get(
        "domain_intelligence"
    )

    if domain_info:

        print_domain_result(
            domain_info
        )

    app_info = result.get(
        "application_intelligence"
    )

    if app_info:

        print_application_result(
            app_info
        )

    print_separator()


# ============================================================
# JSON OUTPUT
# ============================================================

def write_json(data, filename):

    with open(
        filename,
        "w",
        encoding="utf-8"
    ) as file:

        json.dump(
            data,
            file,
            indent=2,
            ensure_ascii=False
        )


# ============================================================
# COMMAND LINE
# ============================================================

def main():

    parser = argparse.ArgumentParser(
        description=(
            "Standalone IP / Domain / "
            "Service Intelligence Analyzer"
        )
    )

    parser.add_argument(
        "--ip",
        help="Public or private IP address"
    )

    parser.add_argument(
        "--domain",
        help="Observed domain / TLS SNI / HTTP Host"
    )

    parser.add_argument(
        "--user-agent",
        help="HTTP User-Agent"
    )

    parser.add_argument(
        "--alpn",
        help="TLS ALPN value, e.g. h2"
    )

    parser.add_argument(
        "--json",
        dest="json_file",
        help="Write JSON result to file"
    )

    args = parser.parse_args()

    if not any([
        args.ip,
        args.domain,
        args.user_agent,
        args.alpn,
    ]):

        parser.print_help()

        return 1

    # Validate IP if supplied.
    if args.ip:

        classification = classify_ip(
            args.ip
        )

        if classification["type"] == "INVALID":

            print(
                f"ERROR: Invalid IP address: "
                f"{args.ip}"
            )

            return 1

    result = analyze(
        ip=args.ip,
        domain=args.domain,
        user_agent=args.user_agent,
        alpn=args.alpn,
    )

    print_full_result(
        result
    )

    if args.json_file:

        write_json(
            result,
            args.json_file
        )

        print()
        print(
            f"JSON report: "
            f"{args.json_file}"
        )

    return 0


# ============================================================
# PROGRAM ENTRY
# ============================================================

if __name__ == "__main__":

    raise SystemExit(
        main()
    )
