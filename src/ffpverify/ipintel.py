"""IP reputation: is this egress a datacenter / VPN / proxy?

The MVP ships a small static list so the pipeline is testable end to end. In production
swap `StaticIpIntel` for a provider-backed implementation (MaxMind GeoIP2 Anonymous IP,
IPinfo privacy detection, Spur) loaded into memory - lookups must stay in-process
because they sit on the hot path.
"""

import bisect
import ipaddress
from dataclasses import dataclass

# Sample hosting / VPN ranges. NOT exhaustive - placeholders for a real feed.
DEFAULT_DATACENTER_CIDRS = (
    "3.0.0.0/9",          # AWS (partial)
    "34.64.0.0/10",       # Google Cloud (partial)
    "104.131.0.0/16",     # DigitalOcean
    "159.65.0.0/16",      # DigitalOcean
    "167.99.0.0/16",      # DigitalOcean
    "5.9.0.0/16",         # Hetzner
    "88.198.0.0/16",      # Hetzner
    "51.38.0.0/16",       # OVH
    "185.156.172.0/22",   # M247 (common commercial-VPN egress)
    "198.51.100.0/24",    # TEST-NET-2: used by the simulator as "known VPN"
)


@dataclass(frozen=True)
class IpInfo:
    is_datacenter: bool
    network: str | None = None


class StaticIpIntel:
    def __init__(self, cidrs: tuple[str, ...] = DEFAULT_DATACENTER_CIDRS):
        nets = sorted((ipaddress.ip_network(c) for c in cidrs if ":" not in c),
                      key=lambda n: int(n.network_address))
        self._starts = [int(n.network_address) for n in nets]
        self._nets = nets

    def lookup(self, ip: str) -> IpInfo:
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return IpInfo(False)
        if addr.version != 4:
            return IpInfo(False)
        i = bisect.bisect_right(self._starts, int(addr)) - 1
        if i >= 0 and addr in self._nets[i]:
            return IpInfo(True, str(self._nets[i]))
        return IpInfo(False)
