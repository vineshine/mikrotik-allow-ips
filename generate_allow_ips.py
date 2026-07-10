from __future__ import annotations

import datetime
import hashlib
import ipaddress
import json
import pathlib
import urllib.request
from typing import Iterable
from zoneinfo import ZoneInfo

REGION_CODES = {
    "500000": "Chongqing",
    "510000": "Sichuan",
}

# GitHub Actions 运行环境可直接访问 GitHub，因此优先 raw；jsDelivr 仅作为备用源。
SOURCE_TEMPLATES = [
    "https://raw.githubusercontent.com/metowolf/iplist/master/data/cncity/{code}.txt",
    "https://metowolf.github.io/iplist/data/cncity/{code}.txt",
    "https://cdn.jsdelivr.net/gh/metowolf/iplist@master/data/cncity/{code}.txt",
]

OUT_DIR = pathlib.Path("dist")
OUT_FILE = OUT_DIR / "allow_ips.rsc"
META_FILE = OUT_DIR / "allow_ips.meta.json"
STATUS_FILE = OUT_DIR / "last_check.json"

MIN_NETWORKS_PER_REGION = 10
MIN_NETWORKS_AFTER_COLLAPSE = 50
MAX_NETWORKS_AFTER_COLLAPSE = 10000


def fetch_text(url: str) -> str:
    request = urllib.request.Request(
        url,
        headers={"User-Agent": "mikrotik-allow-ips-generator/2.1"},
    )
    with urllib.request.urlopen(request, timeout=45) as response:
        if response.status != 200:
            raise RuntimeError(f"HTTP {response.status} from {url}")
        return response.read().decode("utf-8", errors="ignore")


def parse_ipv4_networks(text: str, region_code: str) -> list[ipaddress.IPv4Network]:
    networks: list[ipaddress.IPv4Network] = []
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        line = line.split()[0].strip()
        try:
            network = ipaddress.ip_network(line, strict=False)
        except ValueError:
            print(f"Skip invalid line from region {region_code}: {line}")
            continue
        if isinstance(network, ipaddress.IPv4Network):
            networks.append(network)
    return networks


def fetch_region(region_code: str) -> list[ipaddress.IPv4Network]:
    last_error: Exception | None = None
    for template in SOURCE_TEMPLATES:
        url = template.format(code=region_code)
        try:
            print(f"Fetching region {region_code} from {url}")
            networks = parse_ipv4_networks(fetch_text(url), region_code)
            if len(networks) < MIN_NETWORKS_PER_REGION:
                raise RuntimeError(
                    f"Region {region_code}: too few valid networks ({len(networks)})"
                )
            print(f"Region {region_code}: got {len(networks)} IPv4 networks")
            return networks
        except Exception as exc:
            last_error = exc
            print(f"Failed region {region_code} from {url}: {exc}")
    raise RuntimeError(f"All sources failed for region {region_code}: {last_error}")


def collapse_networks(
    networks: Iterable[ipaddress.IPv4Network],
) -> list[ipaddress.IPv4Network]:
    collapsed = list(ipaddress.collapse_addresses(networks))
    return sorted(collapsed, key=lambda n: (int(n.network_address), n.prefixlen))


def network_sha256(networks: list[ipaddress.IPv4Network]) -> str:
    payload = "\n".join(str(network) for network in networks) + "\n"
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def existing_network_sha256() -> str | None:
    if not META_FILE.exists():
        return None
    try:
        metadata = json.loads(META_FILE.read_text(encoding="utf-8"))
        value = metadata.get("network_sha256")
        return value if isinstance(value, str) else None
    except (OSError, json.JSONDecodeError):
        return None


def build_routeros_rsc(
    networks: list[ipaddress.IPv4Network],
    generated_at: str,
    digest: str,
) -> str:
    region_text = ",".join(REGION_CODES.keys())
    digest_short = digest[:16]
    lines: list[str] = [
        f':log warning "allow_ips: update begin generated={generated_at} regions={region_text} sha256={digest_short}"',
        '/ip firewall address-list remove [find list=allow_ips_new]',
    ]

    for network in networks:
        lines.append(
            '/ip firewall address-list add '
            f'list=allow_ips_new address={network} '
            f'comment="auto cncity {region_text} {generated_at}"'
        )

    lines.append(
        ':local allowIpsNewCount '
        '[/ip firewall address-list print count-only where list=allow_ips_new]'
    )
    lines.append(
        f':if (($allowIpsNewCount < {MIN_NETWORKS_AFTER_COLLAPSE}) || '
        f'($allowIpsNewCount > {MAX_NETWORKS_AFTER_COLLAPSE})) do={{ '
        ':log error ("allow_ips: invalid new entry count=" . $allowIpsNewCount); '
        '/ip firewall address-list remove [find list=allow_ips_new]; '
        ':error "allow_ips_new count validation failed"; }'
    )
    lines.append('/ip firewall address-list remove [find list=allow_ips]')
    lines.append(
        '/ip firewall address-list set [find list=allow_ips_new] list=allow_ips'
    )
    lines.append(
        ':local allowIpsFinalCount '
        '[/ip firewall address-list print count-only where list=allow_ips]'
    )
    lines.append(
        f':log warning ("allow_ips: update end count=" . $allowIpsFinalCount . '
        f'" generated={generated_at} sha256={digest_short}")'
    )
    return "\n".join(lines) + "\n"


def main() -> None:
    checked_at = datetime.datetime.now(ZoneInfo("Asia/Shanghai")).strftime(
        "%Y-%m-%d_%H:%M:%S_Beijing"
    )
    all_networks: list[ipaddress.IPv4Network] = []
    source_counts: dict[str, int] = {}

    for region_code in REGION_CODES:
        region_networks = fetch_region(region_code)
        source_counts[region_code] = len(region_networks)
        all_networks.extend(region_networks)

    collapsed = collapse_networks(all_networks)
    if not (
        MIN_NETWORKS_AFTER_COLLAPSE
        <= len(collapsed)
        <= MAX_NETWORKS_AFTER_COLLAPSE
    ):
        raise RuntimeError(
            f"Invalid collapsed network count: {len(collapsed)}. Refuse to generate."
        )

    digest = network_sha256(collapsed)
    previous_digest = existing_network_sha256()
    cidr_changed = previous_digest != digest or not OUT_FILE.exists()

    OUT_DIR.mkdir(parents=True, exist_ok=True)

    if cidr_changed:
        generated_at = checked_at
        rsc_content = build_routeros_rsc(collapsed, generated_at, digest)
        OUT_FILE.write_text(rsc_content, encoding="utf-8", newline="\n")

        metadata = {
            "generated_at": generated_at,
            "timezone": "Asia/Shanghai",
            "regions": REGION_CODES,
            "source_templates": SOURCE_TEMPLATES,
            "source_counts": source_counts,
            "network_count_after_collapse": len(collapsed),
            "network_sha256": digest,
            "output_file": str(OUT_FILE),
        }
        META_FILE.write_text(
            json.dumps(metadata, ensure_ascii=False, indent=2) + "\n",
            encoding="utf-8",
            newline="\n",
        )
        print(f"CIDR changed; generated {OUT_FILE} and {META_FILE}")
    else:
        print("CIDR content is unchanged; keep existing RSC and metadata.")

    status = {
        "checked_at": checked_at,
        "timezone": "Asia/Shanghai",
        "cidr_changed": cidr_changed,
        "source_counts": source_counts,
        "network_count_after_collapse": len(collapsed),
        "network_sha256": digest,
    }
    STATUS_FILE.write_text(
        json.dumps(status, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
        newline="\n",
    )

    print(f"Updated {STATUS_FILE}")
    print(f"Total networks after collapse: {len(collapsed)}")
    print(f"Checked at: {checked_at}")
    print(f"network_sha256: {digest}")


if __name__ == "__main__":
    main()
