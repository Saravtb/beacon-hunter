"""Listener de laboratório: o lado do operador, que recebe os contatos do agente.

Baseado no script2.py da atividade de pós-exploração do SENAI.

    python lab/listener.py               # escuta em 127.0.0.1:9000
    python lab/listener.py --port 9001
"""

import argparse
import socket
from datetime import datetime


def main():
    p = argparse.ArgumentParser(description="Listener de laboratório")
    p.add_argument("--bind", default="127.0.0.1",
                   help="endereço de escuta (padrão 127.0.0.1; use 0.0.0.0 só em rede de laboratório)")
    p.add_argument("--port", type=int, default=9000, help="porta de escuta (padrão 9000)")
    args = p.parse_args()

    with socket.socket() as sock:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind((args.bind, args.port))
        sock.listen(5)
        print(f"listener em {args.bind}:{args.port}, aguardando conexões. Ctrl+C para parar.")
        while True:
            client, addr = sock.accept()
            with client:
                data = client.recv(4096)
            print(f"[{datetime.now():%H:%M:%S}] {addr[0]} -> {data.decode(errors='replace')}")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        pass
