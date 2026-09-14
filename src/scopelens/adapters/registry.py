from scopelens.adapters.base import ScannerAdapter
from scopelens.adapters.httpx import HttpxAdapter
from scopelens.adapters.nmap import NmapAdapter
from scopelens.adapters.nuclei import NucleiAdapter


def adapter_for(name: str) -> ScannerAdapter:
    adapters: dict[str, ScannerAdapter] = {
        "nmap": NmapAdapter(),
        "httpx": HttpxAdapter(),
        "nuclei": NucleiAdapter(),
    }
    try:
        return adapters[name]
    except KeyError:
        raise ValueError("unsupported scanner") from None
