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

SOURCE_TEMPLATES = [
    "https://cdn.jsdelivr.net/gh/metowolf/iplist@master/data/cncity/{code}.txt",
    "https://metowolf.github.io/iplist/data/cncity/{code}.txt",
    "https://raw.githubusercontent.com/metowolf/iplist/master/data/cncity/{code}.txt",
]

OUT_DIR = pathlib.Path("dist")
OUT_FILE = OUT_DIR / "allow_ips.rsc"
META_FILE = OUT_DIR / "allow_ips.meta.json"

MIN_NETWORKS_AFTER_COLLAPSE = 10


def fetch_text(url: str) -> str:
    req = urllib.request.Request(
        url,
        headers={
            "User-Agent": "mikrotik-allow-ips-generator/1.0"
        },
    )

    with urllib.request.urlopen(req, timeout=45) as resp:
        if resp.status != 200:
            raise RuntimeError(f"HTTP {resp.status} from {url}")
        return resp.read().decode("utf-8", errors="ignore")


def parse_ipv4_networks(text: str, region_code: str) -> list[ipaddress.IPv4Network]:
    networks: list[ipaddress.IPv4Network] = []

    for raw_line in text.splitlines():
        line = raw_line.strip()

        if not line:
            continue
        if line.startswith("#"):
            continue

        # 防止来源文件行尾出现注释或额外字段，只取第一段
        line = line.split()[0].strip()

        try:
            net = ipaddress.ip_network(line, strict=False)
        except ValueError:
            print(f"Skip invalid line from region {region_code}: {line}")
            continue

        if isinstance(net, ipaddress.IPv4Network):
            networks.append(net)

    return networks


def fetch_region(region_code: str) -> list[ipaddress.IPv4Network]:
    last_error: Exception | None = None

    for template in SOURCE_TEMPLATES:
        url = template.format(code=region_code)

        try:
            print(f"Fetching region {region_code} from {url}")
            text = fetch_text(url)
            networks = parse_ipv4_networks(text, region_code)

            if networks:
                print(f"Region {region_code}: got {len(networks)} IPv4 networks")
                return networks

            raise RuntimeError(f"Region {region_code}: no valid IPv4 networks from {url}")

        except Exception as exc:
            last_error = exc
            print(f"Failed region {region_code} from {url}: {exc}")

    raise RuntimeError(f"All sources failed for region {region_code}: {last_error}")


def collapse_networks(networks: Iterable[ipaddress.IPv4Network]) -> list[ipaddress.IPv4Network]:
    collapsed = list(ipaddress.collapse_addresses(networks))
    return sorted(collapsed, key=lambda n: (int(n.network_address), n.prefixlen))


def build_routeros_rsc(networks: list[ipaddress.IPv4Network], generated_at: str) -> str:
    region_text = ",".join(REGION_CODES.keys())

    lines: list[str] = []

    lines.append(f':log warning "allow_ips: update begin generated={generated_at} regions={region_text}"')
    lines.append('/ip firewall address-list remove [find list=allow_ips_new]')

    for net in networks:
        lines.append(
            f'/ip firewall address-list add list=allow_ips_new '
            f'address={net} comment="auto cncity {region_text} {generated_at}"'
        )

    # 二次保护：
    # 先导入 allow_ips_new，如果数量异常过少，则拒绝替换旧 allow_ips。
    lines.append(':local allowIpsNewCount [/ip firewall address-list print count-only where list=allow_ips_new]')
    lines.append(
        f':if ($allowIpsNewCount < {MIN_NETWORKS_AFTER_COLLAPSE}) do={{ '
        f':log error ("allow_ips: too few new entries, count=" . $allowIpsNewCount); '
        f'/ip firewall address-list remove [find list=allow_ips_new]; '
        f':error "allow_ips_new too few"; '
        f'}}'
    )

    # 只有 allow_ips_new 完整导入后，才删除旧 allow_ips 并切换。
    # 这可以避免下载到异常文件时把旧白名单清空。
    lines.append('/ip firewall address-list remove [find list=allow_ips]')
    lines.append('/ip firewall address-list set [find list=allow_ips_new] list=allow_ips')

    lines.append(':local allowIpsFinalCount [/ip firewall address-list print count-only where list=allow_ips]')
    lines.append(f':log warning ("allow_ips: update end count=" . $allowIpsFinalCount . " generated={generated_at}")')

    return "\n".join(lines) + "\n"


def main() -> None:
    all_networks: list[ipaddress.IPv4Network] = []

    for region_code in REGION_CODES:
        all_networks.extend(fetch_region(region_code))

    collapsed = collapse_networks(all_networks)

    if len(collapsed) < MIN_NETWORKS_AFTER_COLLAPSE:
        raise RuntimeError(
            f"Too few networks after collapse: {len(collapsed)}. Refuse to generate."
        )

    beijing_now = datetime.datetime.now(ZoneInfo("Asia/Shanghai"))
    generated_at = beijing_now.strftime("%Y-%m-%d_%H:%M:%S_Beijing")

    rsc_content = build_routeros_rsc(collapsed, generated_at)

    OUT_DIR.mkdir(parents=True, exist_ok=True)
    OUT_FILE.write_text(rsc_content, encoding="utf-8", newline="\n")

    sha256 = hashlib.sha256(rsc_content.encode("utf-8")).hexdigest()

    meta = {
        "generated_at": generated_at,
        "timezone": "Asia/Shanghai",
        "regions": REGION_CODES,
        "source_templates": SOURCE_TEMPLATES,
        "network_count_after_collapse": len(collapsed),
        "output_file": str(OUT_FILE),
        "sha256": sha256,
    }

    META_FILE.write_text(
        json.dumps(meta, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
        newline="\n",
    )

    print(f"Generated {OUT_FILE}")
    print(f"Generated {META_FILE}")
    print(f"Total networks after collapse: {len(collapsed)}")
    print(f"Generated at: {generated_at}")
    print(f"SHA256: {sha256}")


if __name__ == "__main__":
    main()
