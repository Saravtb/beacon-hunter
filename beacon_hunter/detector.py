"""Núcleo do beacon-hunter: identifica conexões que se repetem em intervalos regulares.

Este módulo não depende do Scapy nem de rede. Ele recebe eventos já extraídos
dos pacotes (uma conexão nova, um trecho de dados) e mantém o estado de cada
fluxo. Por isso pode ser testado com dados sintéticos e reaproveitado com
qualquer fonte de eventos (captura ao vivo, pcap, logs de firewall).

Um fluxo é a combinação (IP de origem, IP de destino, porta de destino).
A porta de origem fica de fora de propósito: um agente que abre um socket novo
a cada ciclo usa uma porta efêmera diferente em cada conexão, e agrupar por ela
esconderia a repetição.
"""

from __future__ import annotations

import statistics
from dataclasses import dataclass, field
from datetime import datetime
from typing import Dict, List, Optional, Tuple

FlowKey = Tuple[str, str, int]  # (ip_origem, ip_destino, porta_destino)
ConnKey = Tuple[str, int, str, int]  # (ip_origem, porta_origem, ip_destino, porta_destino)


@dataclass
class Settings:
    """Parâmetros da detecção.

    max_cv: coeficiente de variação máximo (desvio padrão / média dos intervalos)
        para um fluxo ser considerado periódico. 0.15 aceita até 15% de jitter.
    min_events: número mínimo de conexões antes de classificar. Com 3 conexões
        já existem 2 intervalos para comparar.
    min_interval: intervalo médio mínimo, em segundos. Evita marcar rajadas
        (várias conexões em menos de um segundo) como beacon.
    """

    max_cv: float = 0.15
    min_events: int = 3
    min_interval: float = 1.0


@dataclass
class Event:
    """Uma conexão nova observada em um fluxo."""

    timestamp: datetime
    src_ip: str
    src_port: int
    dst_ip: str
    dst_port: int
    sequence: int  # posição desta conexão dentro do fluxo (1, 2, 3...)
    interval: Optional[float] = None  # segundos desde a conexão anterior do fluxo
    mean: Optional[float] = None
    stdev: Optional[float] = None
    cv: Optional[float] = None
    periodic: bool = False
    payload: bytes = b""

    @property
    def flow(self) -> FlowKey:
        return (self.src_ip, self.dst_ip, self.dst_port)

    @property
    def payload_text(self) -> str:
        return self.payload.decode("utf-8", errors="replace")

    @property
    def cleartext(self) -> Optional[bool]:
        """True se o payload parece texto legível, None se não houve dados."""
        if not self.payload:
            return None
        return looks_like_text(self.payload)

    def as_dict(self) -> dict:
        return {
            "timestamp": self.timestamp.isoformat(timespec="milliseconds"),
            "src_ip": self.src_ip,
            "src_port": self.src_port,
            "dst_ip": self.dst_ip,
            "dst_port": self.dst_port,
            "sequence": self.sequence,
            "interval_s": round(self.interval, 4) if self.interval is not None else None,
            "mean_s": round(self.mean, 4) if self.mean is not None else None,
            "stdev_s": round(self.stdev, 4) if self.stdev is not None else None,
            "cv": round(self.cv, 4) if self.cv is not None else None,
            "periodic": self.periodic,
            "payload_bytes": len(self.payload),
            "cleartext": self.cleartext,
            "payload": self.payload_text if self.cleartext else None,
        }


@dataclass
class Flow:
    """Histórico de um fluxo."""

    key: FlowKey
    timestamps: List[datetime] = field(default_factory=list)
    events: List[Event] = field(default_factory=list)

    @property
    def intervals(self) -> List[float]:
        t = self.timestamps
        return [(t[i] - t[i - 1]).total_seconds() for i in range(1, len(t))]


@dataclass
class FlowSummary:
    src_ip: str
    dst_ip: str
    dst_port: int
    connections: int
    mean: Optional[float]
    stdev: Optional[float]
    cv: Optional[float]
    periodic: bool
    cleartext: Optional[bool]
    first_seen: datetime
    last_seen: datetime

    def as_dict(self) -> dict:
        return {
            "src_ip": self.src_ip,
            "dst_ip": self.dst_ip,
            "dst_port": self.dst_port,
            "connections": self.connections,
            "mean_s": round(self.mean, 4) if self.mean is not None else None,
            "stdev_s": round(self.stdev, 4) if self.stdev is not None else None,
            "cv": round(self.cv, 4) if self.cv is not None else None,
            "periodic": self.periodic,
            "cleartext": self.cleartext,
            "first_seen": self.first_seen.isoformat(timespec="seconds"),
            "last_seen": self.last_seen.isoformat(timespec="seconds"),
        }


def looks_like_text(data: bytes, threshold: float = 0.9) -> bool:
    """Heurística: payload com 90% ou mais de caracteres imprimíveis é texto claro.

    Não prova ausência de criptografia (um texto pode estar codificado em base64,
    por exemplo), mas separa bem o texto legível de um fluxo cifrado ou binário.
    """
    if not data:
        return False
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        return False
    printable = sum(1 for c in text if c.isprintable() or c in "\r\n\t")
    return printable / len(text) >= threshold


def classify(intervals: List[float], settings: Settings) -> Tuple[bool, Optional[float], Optional[float], Optional[float]]:
    """Retorna (periódico, média, desvio, cv) para uma lista de intervalos."""
    if len(intervals) < 1:
        return False, None, None, None
    mean = statistics.mean(intervals)
    stdev = statistics.pstdev(intervals)
    cv = stdev / mean if mean > 0 else float("inf")
    enough = len(intervals) + 1 >= settings.min_events
    periodic = enough and cv <= settings.max_cv and mean >= settings.min_interval
    return periodic, mean, stdev, cv


class BeaconDetector:
    """Mantém o estado dos fluxos e classifica cada conexão nova."""

    def __init__(self, settings: Optional[Settings] = None):
        self.settings = settings or Settings()
        self.flows: Dict[FlowKey, Flow] = {}
        self._open: Dict[ConnKey, Event] = {}

    def on_connection(self, ts: datetime, src_ip: str, src_port: int, dst_ip: str, dst_port: int) -> Event:
        """Registra uma conexão nova (SYN) e devolve o evento já classificado."""
        key: FlowKey = (src_ip, dst_ip, dst_port)
        flow = self.flows.setdefault(key, Flow(key))
        flow.timestamps.append(ts)

        intervals = flow.intervals
        periodic, mean, stdev, cv = classify(intervals, self.settings)
        event = Event(
            timestamp=ts,
            src_ip=src_ip,
            src_port=src_port,
            dst_ip=dst_ip,
            dst_port=dst_port,
            sequence=len(flow.timestamps),
            interval=intervals[-1] if intervals else None,
            mean=mean,
            stdev=stdev,
            cv=cv,
            periodic=periodic,
        )
        flow.events.append(event)
        self._open[(src_ip, src_port, dst_ip, dst_port)] = event
        return event

    def on_payload(self, src_ip: str, src_port: int, dst_ip: str, dst_port: int, data: bytes) -> Optional[Event]:
        """Anexa dados enviados pelo cliente à conexão correspondente.

        Devolve o evento atualizado, ou None se a conexão não foi vista abrindo
        (por exemplo, quando a captura começou no meio dela).
        """
        event = self._open.get((src_ip, src_port, dst_ip, dst_port))
        if event is None or not data:
            return None
        first_chunk = not event.payload
        event.payload += data
        return event if first_chunk else None

    def on_close(self, src_ip: str, src_port: int, dst_ip: str, dst_port: int) -> None:
        self._open.pop((src_ip, src_port, dst_ip, dst_port), None)

    def summaries(self) -> List[FlowSummary]:
        result = []
        for flow in self.flows.values():
            periodic, mean, stdev, cv = classify(flow.intervals, self.settings)
            clear = [e.cleartext for e in flow.events if e.cleartext is not None]
            result.append(
                FlowSummary(
                    src_ip=flow.key[0],
                    dst_ip=flow.key[1],
                    dst_port=flow.key[2],
                    connections=len(flow.timestamps),
                    mean=mean,
                    stdev=stdev,
                    cv=cv,
                    periodic=periodic,
                    cleartext=(all(clear) if clear else None),
                    first_seen=flow.timestamps[0],
                    last_seen=flow.timestamps[-1],
                )
            )
        # periódicos primeiro, depois os fluxos com mais conexões
        result.sort(key=lambda s: (not s.periodic, -s.connections))
        return result

    @property
    def events(self) -> List[Event]:
        all_events = [e for f in self.flows.values() for e in f.events]
        return sorted(all_events, key=lambda e: e.timestamp)
