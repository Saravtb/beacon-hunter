"""Regenera as imagens do README a partir da saída real do beacon-hunter.

    python docs/make_screenshots.py

Gera um SVG com o rich e converte para PNG com o Chrome em modo headless
(google-chrome ou chromium precisa estar no PATH). Sem Chrome, fica só o SVG.
"""

import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

from rich.console import Console
from rich.terminal_theme import TerminalTheme

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

import beacon_hunter.cli as cli  # noqa: E402

SAMPLE = "samples/beacon_sample.pcap"  # caminho relativo para aparecer limpo nas imagens
IMG = ROOT / "docs" / "img"

THEME = TerminalTheme(
    (18, 22, 20),      # fundo
    (220, 228, 222),   # texto
    [
        (18, 22, 20), (230, 90, 90), (74, 222, 128), (234, 179, 8),
        (96, 165, 250), (192, 132, 252), (45, 212, 191), (210, 218, 212),
    ],
    [
        (110, 118, 112), (248, 113, 113), (134, 239, 172), (250, 204, 21),
        (147, 197, 253), (216, 180, 254), (94, 234, 212), (245, 248, 246),
    ],
)


def browser():
    for name in ("google-chrome", "chromium", "chromium-browser", "chrome"):
        if shutil.which(name):
            return name
    return None


def shot(name, title, argv, width=112):
    console = Console(record=True, width=width, force_terminal=True, color_system="truecolor", highlight=False)
    original = cli.Console
    cli.Console = lambda **kw: console
    try:
        cli.main(argv)
    finally:
        cli.Console = original

    svg_path = IMG / f"{name}.svg"
    svg = console.export_svg(title=title, theme=THEME)
    # fonte do sistema, sem ligaduras: o banner em ASCII depende de cada caractere no lugar
    svg = re.sub(r"@font-face\s*{[^}]*}", "", svg)
    svg = svg.replace("Fira Code", "DejaVu Sans Mono")
    svg = svg.replace("<style>", "<style>\n text { font-variant-ligatures: none; }", 1)
    svg_path.write_text(svg, encoding="utf-8")

    exe = browser()
    if not exe:
        return
    w, h = (round(float(v)) for v in re.search(r'viewBox="0 0 ([\d.]+) ([\d.]+)"', svg).groups())
    subprocess.run(
        [exe, "--headless=new", "--no-sandbox", "--disable-gpu", "--hide-scrollbars",
         "--default-background-color=00000000", "--force-device-scale-factor=1",
         f"--window-size={w},{h}", f"--screenshot={IMG / (name + '.png')}", svg_path.as_uri()],
        check=True, capture_output=True, timeout=60,
    )
    svg_path.unlink()


if __name__ == "__main__":
    os.chdir(ROOT)
    IMG.mkdir(parents=True, exist_ok=True)
    shot("demo", "beacon-hunter -r samples/beacon_sample.pcap -q", ["-r", SAMPLE, "-q"])
    shot("tolerance", "beacon-hunter -r samples/beacon_sample.pcap -q --tolerance 0.35 --min-events 5 --no-payload",
         ["-r", SAMPLE, "-q", "--tolerance", "0.35", "--min-events", "5", "--no-payload"])
    print("imagens geradas em", IMG)
