# pyscan/models.py

from dataclasses import dataclass

@dataclass(slots=True)
class PortResult:
    port: int
    service: str
    banner: str


@dataclass(slots=True)
class Host:
    ip: str
    hostname: str = "N/A"
    mac: str = "N/A"
    method: str = "N/A"
    interface: str = "N/A"
    flags: str = "N/A"
    link_type: str = "N/A"
    state: str = "N/A"