from typing import Literal

from scopelens.domain.targets import DomainModel, IPv4, Port


class ServiceEndpoint(DomainModel):
    address: IPv4
    transport: Literal["tcp", "udp", "sctp"]
    port: Port
