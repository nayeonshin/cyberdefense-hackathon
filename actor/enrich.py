"""Who hosts it and who to tell: DNS plus RDAP for the domain and the IP."""
import ipaddress
import socket
from dataclasses import asdict, dataclass, field
from functools import lru_cache

import requests

RDAP = "https://rdap.org"
TIMEOUT = 8


@dataclass
class Enrichment:
    domain: str = ""
    ips: list = field(default_factory=list)
    registrar: str = ""
    registrar_abuse: list = field(default_factory=list)
    host_network: str = ""
    host_abuse: list = field(default_factory=list)
    errors: list = field(default_factory=list)

    def to_dict(self) -> dict:
        return asdict(self)


def is_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


INTERNAL_NETWORKS = [ipaddress.ip_network(n) for n in (
    "0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16",
    "172.16.0.0/12", "192.168.0.0/16", "224.0.0.0/3", "::1/128", "fc00::/7", "fe80::/10")]


def is_internal(address: str) -> bool:
    """Private, loopback, link-local and similar addresses that no report may name."""
    try:
        ip = ipaddress.ip_address(address)
    except ValueError:
        return False
    return any(ip in network for network in INTERNAL_NETWORKS if network.version == ip.version)


def resolve(host: str) -> list:
    if is_ip(host):
        return [host]
    try:
        infos = socket.getaddrinfo(host, None, proto=socket.IPPROTO_TCP)
    except OSError:
        return []
    return sorted({info[4][0] for info in infos})


def _walk(entities, found):
    """Collect (roles, name, emails) from nested RDAP entities."""
    for entity in entities or []:
        vcard = entity.get("vcardArray", [None, []])[1]
        name = next((v[3] for v in vcard if v[0] == "fn" and v[3]), "")
        emails = [v[3] for v in vcard if v[0] == "email" and v[3]]
        found.append((entity.get("roles", []), name, emails))
        _walk(entity.get("entities"), found)


@lru_cache(maxsize=512)
def _rdap(kind: str, value: str):
    response = requests.get(f"{RDAP}/{kind}/{value}", timeout=TIMEOUT,
                            headers={"Accept": "application/rdap+json"})
    if response.status_code != 200:
        return None
    return response.json()


def _rdap_domain(host: str):
    """RDAP knows registrable domains only, so strip labels until one answers."""
    labels = host.split(".")
    while len(labels) >= 2:
        data = _rdap("domain", ".".join(labels))
        if data:
            return data
        labels = labels[1:]
    return None


def enrich(host: str, offline: bool = False) -> Enrichment:
    result = Enrichment(domain=host)
    if offline or not host:
        return result
    result.ips = resolve(host)

    if not is_ip(host):
        try:
            data = _rdap_domain(host)
            found = []
            _walk((data or {}).get("entities"), found)
            for roles, name, emails in found:
                if "registrar" in roles and name and not result.registrar:
                    result.registrar = name
                if "abuse" in roles:
                    result.registrar_abuse += [e for e in emails if e not in result.registrar_abuse]
        except (requests.RequestException, ValueError) as exc:
            result.errors.append(f"rdap domain: {exc}")

    if result.ips:
        try:
            data = _rdap("ip", result.ips[0]) or {}
            result.host_network = data.get("name", "")
            found = []
            _walk(data.get("entities"), found)
            for roles, _name, emails in found:
                if "abuse" in roles:
                    result.host_abuse += [e for e in emails if e not in result.host_abuse]
        except (requests.RequestException, ValueError) as exc:
            result.errors.append(f"rdap ip: {exc}")
    return result
