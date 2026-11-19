"""Saída no terminal (rich) e exportação para JSON e CSV."""

from __future__ import annotations

import csv
import json
from typing import Iterable, List

from rich.console import Console
from rich.table import Table
from rich.text import Text

from . import __version__
from .detector import Event, FlowSummary

BANNER_WIDE = """
██████╗ ███████╗ █████╗  ██████╗ ██████╗ ███╗   ██╗      ██╗  ██╗██╗   ██╗███╗   ██╗████████╗███████╗██████╗
██╔══██╗██╔════╝██╔══██╗██╔════╝██╔═══██╗████╗  ██║      ██║  ██║██║   ██║████╗  ██║╚══██╔══╝██╔════╝██╔══██╗
██████╔╝█████╗  ███████║██║     ██║   ██║██╔██╗ ██║█████╗███████║██║   ██║██╔██╗ ██║   ██║   █████╗  ██████╔╝
██╔══██╗██╔══╝  ██╔══██║██║     ██║   ██║██║╚██╗██║╚════╝██╔══██║██║   ██║██║╚██╗██║   ██║   ██╔══╝  ██╔══██╗
██████╔╝███████╗██║  ██║╚██████╗╚██████╔╝██║ ╚████║      ██║  ██║╚██████╔╝██║ ╚████║   ██║   ███████╗██║  ██║
╚═════╝ ╚══════╝╚═╝  ╚═╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝      ╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═══╝   ╚═╝   ╚══════╝╚═╝  ╚═╝
"""

BANNER_NARROW = r"""
 _                             _            _
| |__  ___ __ _ __ ___ _ _ ___| |_ _  _ _ _| |_ ___ _ _
| '_ \/ -_) _` / _/ _ \ ' \___| ' \ || | ' \  _/ -_) '_|
|_.__/\___\__,_\__\___/_||_|  |_||_\_,_|_||_\__\___|_|
"""

GREEN = "bold green"
DIM = "grey50"


def _fmt(value, digits=3, suffix=""):
    if value is None:
        return "-"
    return f"{value:.{digits}f}{suffix}".replace(".", ",")


class Reporter:
    def __init__(self, console: Console, show_payload: bool = True, quiet: bool = False):
        self.console = console
        self.show_payload = show_payload
        self.quiet = quiet

    def banner(self, subtitle: str) -> None:
        banner = BANNER_WIDE if self.console.width >= 112 else BANNER_NARROW
        self.console.print(Text(banner, style="green"), highlight=False)
        self.console.print(
            f"  [green]v{__version__}[/]  [{DIM}]detecção de beaconing por periodicidade de conexões[/]"
        )
        self.console.print(f"  [{DIM}]{subtitle}[/]\n")

    def info(self, message: str) -> None:
        self.console.print(f"[{DIM}][*][/] {message}")

    def warn(self, message: str) -> None:
        self.console.print(f"[yellow][!][/] {message}")

    def event(self, ev: Event) -> None:
        if self.quiet and not ev.periodic:
            return
        when = ev.timestamp.strftime("%H:%M:%S")
        flow = f"{ev.src_ip}:{ev.src_port} -> {ev.dst_ip}:{ev.dst_port}"
        if ev.periodic:
            tag = "[bold white on dark_green] BEACON [/]"
            cv = ev.cv * 100 if ev.cv is not None else None
            stats = f"[green]#{ev.sequence} +{_fmt(ev.interval, 2, 's')} (média {_fmt(ev.mean, 2, 's')}, cv {_fmt(cv, 1, '%')})[/]"
        else:
            tag = f"[{DIM}] conexão [/]"
            delta = f" +{_fmt(ev.interval, 2, 's')}" if ev.interval is not None else " primeira do fluxo"
            stats = f"[{DIM}]#{ev.sequence}{delta}[/]"
        self.console.print(f"[{DIM}]{when}[/] {tag} {flow} {stats}", highlight=False, overflow="ellipsis", no_wrap=True)

    def payload(self, ev: Event) -> None:
        if not self.show_payload or (self.quiet and not ev.periodic):
            return
        if ev.cleartext:
            text = ev.payload_text.strip().replace("\r", " ").replace("\n", " ")
            line = f"         [{DIM}]└─ {len(ev.payload)} B texto claro:[/] [white]{text}[/]"
        else:
            line = f"         [{DIM}]└─ {len(ev.payload)} B não legível (cifrado ou binário)[/]"
        self.console.print(line, highlight=False, overflow="ellipsis", no_wrap=True)

    def summary(self, flows: List[FlowSummary], packets: int) -> None:
        periodic = [f for f in flows if f.periodic]
        self.console.print()
        table = Table(
            title="Resumo dos fluxos",
            title_style="bold green",
            header_style="bold green",
            border_style="green",
        )
        table.add_column("Fluxo", overflow="fold")
        table.add_column("Conex.", justify="right", no_wrap=True, min_width=6)
        table.add_column("Média", justify="right", no_wrap=True, min_width=8)
        table.add_column("CV", justify="right", no_wrap=True, min_width=6)
        table.add_column("Dados", no_wrap=True, min_width=11)
        table.add_column("Veredito", no_wrap=True, min_width=8)
        for f in flows:
            content = "-" if f.cleartext is None else ("texto claro" if f.cleartext else "não legível")
            verdict = "[bold green]BEACON[/]" if f.periodic else f"[{DIM}]normal[/]"
            table.add_row(
                f"{f.src_ip} -> {f.dst_ip}:{f.dst_port}",
                str(f.connections),
                _fmt(f.mean, 2, " s"),
                _fmt(f.cv * 100 if f.cv is not None else None, 1, "%"),
                content,
                verdict,
            )
        if flows:
            self.console.print(table)
        def plural(n, one, many):
            return f"{n} {one if n == 1 else many}"

        self.console.print(
            f"\n[{DIM}]{plural(packets, 'pacote TCP analisado', 'pacotes TCP analisados')}, "
            f"{plural(len(flows), 'fluxo', 'fluxos')}, [/]"
            f"[bold green]{len(periodic)} com comportamento de beacon[/]"
        )


def export_json(path: str, events: Iterable[Event], flows: Iterable[FlowSummary]) -> None:
    data = {"flows": [f.as_dict() for f in flows], "events": [e.as_dict() for e in events]}
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(data, fh, ensure_ascii=False, indent=2)


def export_csv(path: str, events: Iterable[Event]) -> None:
    rows = [e.as_dict() for e in events]
    if not rows:
        return
    with open(path, "w", encoding="utf-8", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=list(rows[0].keys()))
        writer.writeheader()
        writer.writerows(rows)
