"""Leitura de pacotes com Scapy: captura ao vivo ou arquivo pcap/pcapng.

Transforma pacotes TCP em chamadas ao BeaconDetector:
- SYN sem ACK      -> nova conexão (on_connection)
- dados do cliente -> anexados à conexão (on_payload)
- FIN ou RST       -> conexão encerrada (on_close)
"""

from __future__ import annotations

from collections import OrderedDict
from dataclasses import dataclass, field
from datetime import datetime
from typing import Callable, Iterable, Optional, Set

from .detector import BeaconDetector, Event

SYN, ACK, FIN, RST = 0x02, 0x10, 0x01, 0x04


@dataclass
class PortFilter:
    """Quais portas de destino observar. Vazio em `only` significa todas."""

    only: Set[int] = field(default_factory=set)
    ignore: Set[int] = field(default_factory=set)

    def accepts(self, port: int) -> bool:
        if port in self.ignore:
            return False
        return not self.only or port in self.only

    def bpf(self) -> str:
        """Filtro BPF para o Npcap/libpcap descartar o resto já no kernel."""
        if self.only:
            return "tcp and (" + " or ".join(f"port {p}" for p in sorted(self.only)) + ")"
        return "tcp"


class PacketHandler:
    """Liga os pacotes do Scapy ao detector e avisa quem estiver ouvindo."""

    def __init__(
        self,
        detector: BeaconDetector,
        ports: PortFilter,
        on_event: Optional[Callable[[Event], None]] = None,
        on_payload: Optional[Callable[[Event], None]] = None,
        live: bool = False,
    ):
        self.detector = detector
        self.ports = ports
        self.on_event = on_event
        self.on_payload = on_payload
        self.live = live
        self.packets_seen = 0
        # No loopback do Linux cada pacote aparece duas vezes (saída e entrada).
        # Guardamos as assinaturas recentes para contar cada um só uma vez.
        self._recent: "OrderedDict[tuple, None]" = OrderedDict()

    def _duplicate(self, signature: tuple) -> bool:
        if signature in self._recent:
            return True
        self._recent[signature] = None
        if len(self._recent) > 4096:
            self._recent.popitem(last=False)
        return False

    def __call__(self, pkt) -> None:
        from scapy.all import IP, IPv6, TCP, Raw

        if not pkt.haslayer(TCP):
            return
        if pkt.haslayer(IP):
            src, dst = pkt[IP].src, pkt[IP].dst
        elif pkt.haslayer(IPv6):
            src, dst = pkt[IPv6].src, pkt[IPv6].dst
        else:
            return
        tcp = pkt[TCP]
        flags = int(tcp.flags)
        sport, dport = int(tcp.sport), int(tcp.dport)
        size = len(pkt[Raw].load) if pkt.haslayer(Raw) else 0
        if self._duplicate((src, sport, dst, dport, int(tcp.seq), int(tcp.ack), flags, size)):
            return
        self.packets_seen += 1
        ts = datetime.now() if self.live else datetime.fromtimestamp(float(pkt.time))

        if flags & SYN and not flags & ACK:
            if self.ports.accepts(dport):
                event = self.detector.on_connection(ts, src, sport, dst, dport)
                if self.on_event:
                    self.on_event(event)
            return

        if pkt.haslayer(Raw) and self.ports.accepts(dport):
            event = self.detector.on_payload(src, sport, dst, dport, bytes(pkt[Raw].load))
            if event and self.on_payload:
                self.on_payload(event)

        if flags & (FIN | RST):
            self.detector.on_close(src, sport, dst, dport)


def read_pcap(path: str, handler: PacketHandler) -> None:
    # scapy.all registra todos os tipos de enlace (Ethernet, loopback do Npcap, etc.)
    from scapy.all import PcapReader

    with PcapReader(path) as reader:
        for pkt in reader:
            handler(pkt)


def find_loopback_interface() -> Optional[str]:
    """Procura o adaptador de loopback (Npcap no Windows, lo no Linux)."""
    from scapy.all import conf, get_if_list

    names: Iterable[str] = get_if_list()
    for name in names:
        low = name.lower()
        if "npf_loopback" in low or low == "lo" or "loopback" in low:
            return name
    try:
        for iface in conf.ifaces.data.values():
            desc = f"{getattr(iface, 'name', '')} {getattr(iface, 'description', '')}".lower()
            if "loopback" in desc:
                return iface.name
    except Exception:
        pass
    return None


def sniff_live(iface: Optional[str], handler: PacketHandler, stop: Callable[[], bool],
               on_warning: Optional[Callable[[str], None]] = None) -> None:
    """Captura em blocos curtos: no Windows o Ctrl+C só é atendido entre blocos.

    O filtro BPF descarta o tráfego não TCP antes de chegar ao Python. Sem libpcap
    (Linux sem o pacote instalado) o filtro não compila; nesse caso a captura segue
    sem ele e a filtragem fica só no handler.
    """
    from scapy.all import sniff
    from scapy.error import Scapy_Exception

    bpf: Optional[str] = handler.ports.bpf()
    while not stop():
        try:
            sniff(filter=bpf, prn=handler, store=False, timeout=2, iface=iface,
                  stop_filter=lambda _pkt: stop())
        except Scapy_Exception as exc:
            if bpf and "filter" in str(exc).lower():
                bpf = None
                if on_warning:
                    on_warning("filtro BPF indisponível (sem libpcap); filtrando os pacotes no Python")
                continue
            raise
