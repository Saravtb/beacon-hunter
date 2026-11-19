"""Interface de linha de comando do beacon-hunter."""

from __future__ import annotations

import argparse
import signal
import sys

from rich.console import Console

from . import __version__
from .capture import PacketHandler, PortFilter, find_loopback_interface, read_pcap, sniff_live
from .detector import BeaconDetector, Settings
from .output import Reporter, export_csv, export_json
from .storage import open_storage


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="beacon-hunter",
        description="Detecta conexões TCP periódicas (beaconing de C2) ao vivo ou em arquivos pcap.",
        epilog=(
            "exemplos:\n"
            "  beacon-hunter -r samples/beacon_sample.pcap\n"
            "  beacon-hunter -i \\Device\\NPF_Loopback -p 9000 --db beacons.db\n"
            "  beacon-hunter --loopback --json saida.json\n"
            "  beacon-hunter -r captura.pcapng --db mysql://127.0.0.1:3306/seguranca_lab"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    src = p.add_argument_group("fonte dos pacotes (padrão: captura ao vivo na interface padrão)")
    src.add_argument("-r", "--read", metavar="PCAP", help="analisa um arquivo .pcap ou .pcapng")
    src.add_argument("-i", "--iface", help="interface para captura ao vivo")
    src.add_argument("--loopback", action="store_true", help="captura no adaptador de loopback (Npcap ou lo)")

    flt = p.add_argument_group("filtros")
    flt.add_argument("-p", "--port", type=int, action="append", default=[], metavar="PORTA",
                     help="observa só esta porta de destino (pode repetir); sem -p, todas as portas")
    flt.add_argument("--ignore-port", type=int, action="append", default=[], metavar="PORTA",
                     help="ignora esta porta de destino (pode repetir)")

    det = p.add_argument_group("detecção")
    det.add_argument("--tolerance", type=float, default=0.15, metavar="CV",
                     help="coeficiente de variação máximo para considerar periódico (padrão 0.15 = 15%%)")
    det.add_argument("--min-events", type=int, default=3, metavar="N",
                     help="conexões mínimas antes de classificar (padrão 3)")
    det.add_argument("--min-interval", type=float, default=1.0, metavar="S",
                     help="intervalo médio mínimo em segundos (padrão 1.0)")

    out = p.add_argument_group("saída")
    out.add_argument("--db", metavar="DESTINO", help="grava as detecções: arquivo .db (SQLite) ou mysql://host:porta/banco")
    out.add_argument("--json", metavar="ARQUIVO", help="exporta fluxos e eventos em JSON ao final")
    out.add_argument("--csv", metavar="ARQUIVO", help="exporta os eventos em CSV ao final")
    out.add_argument("-q", "--quiet", action="store_true", help="mostra só as conexões classificadas como beacon")
    out.add_argument("--no-payload", action="store_true", help="não mostra o conteúdo das conexões")
    out.add_argument("--no-color", action="store_true", help="saída sem cores")
    p.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    return p


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    console = Console(no_color=args.no_color, highlight=False)
    reporter = Reporter(console, show_payload=not args.no_payload, quiet=args.quiet)

    settings = Settings(max_cv=args.tolerance, min_events=args.min_events, min_interval=args.min_interval)
    detector = BeaconDetector(settings)
    ports = PortFilter(only=set(args.port), ignore=set(args.ignore_port))
    storage = open_storage(args.db)

    def on_event(ev):
        reporter.event(ev)
        if storage:
            storage.save(ev)

    def on_payload(ev):
        reporter.payload(ev)
        if storage:
            storage.update_payload(ev)

    handler = PacketHandler(detector, ports, on_event=on_event, on_payload=on_payload, live=not args.read)
    port_text = ", ".join(map(str, sorted(ports.only))) if ports.only else "todas"
    criteria = f"portas: {port_text} | cv <= {args.tolerance:.0%} | min. {args.min_events} conexões"

    try:
        if args.read:
            reporter.banner(f"arquivo: {args.read} | {criteria}")
            if storage:
                reporter.info(f"gravando em {storage.label}")
            read_pcap(args.read, handler)
        else:
            iface = args.iface
            if args.loopback and not iface:
                iface = find_loopback_interface()
                if not iface:
                    reporter.warn("adaptador de loopback não encontrado; no Windows, instale o Npcap com 'Support loopback traffic'")
            reporter.banner(f"interface: {iface or 'padrão do sistema'} | {criteria}")
            if storage:
                reporter.info(f"gravando em {storage.label}")
            reporter.info("capturando... Ctrl+C para encerrar e ver o resumo\n")
            # o Scapy engole o KeyboardInterrupt dentro do sniff, então o Ctrl+C vira uma flag
            stopping = {"now": False}

            def request_stop(signum, frame):
                stopping["now"] = True

            previous = signal.signal(signal.SIGINT, request_stop)
            try:
                sniff_live(iface, handler, stop=lambda: stopping["now"], on_warning=reporter.warn)
            finally:
                signal.signal(signal.SIGINT, previous)
            console.print()
    except PermissionError:
        reporter.warn("sem permissão para capturar: rode o terminal como Administrador (Windows) ou com sudo (Linux)")
        return 1
    except FileNotFoundError as exc:
        reporter.warn(f"arquivo não encontrado: {exc.filename}")
        return 1
    finally:
        if storage:
            storage.close()

    summaries = detector.summaries()
    reporter.summary(summaries, handler.packets_seen)
    if args.json:
        export_json(args.json, detector.events, summaries)
        reporter.info(f"JSON salvo em {args.json}")
    if args.csv:
        export_csv(args.csv, detector.events)
        reporter.info(f"CSV salvo em {args.csv}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
