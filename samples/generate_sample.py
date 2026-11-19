"""Gera samples/beacon_sample.pcap: tráfego sintético para demonstração e testes.

Nenhum dado real: IPs de faixas privadas e de documentação (RFC 5737),
host e usuário fictícios. O gerador usa semente fixa, então o arquivo sai
sempre igual.

Cenários (todos partindo de 10.10.0.23):

  1. 10.10.0.5:9000      beacon do laboratório, 30 s, texto claro       -> BEACON
  2. 203.0.113.50:443    beacon cifrado, 60 s com 10% de jitter          -> BEACON
  3. 198.51.100.10:443   navegação humana, intervalos irregulares        -> normal
  4. 203.0.113.77:8080   beacon com 50% de jitter                        -> normal no padrão,
                                                                            BEACON com --tolerance 0.35
  5. 198.51.100.20:80    rajada de 8 conexões em menos de 2 s            -> normal (abaixo de --min-interval)

    python samples/generate_sample.py
"""

import random
from pathlib import Path

from scapy.all import IP, TCP, Ether, Raw, wrpcap

SEED = 2026
START = 1_795_000_000.0  # horário base fictício
CLIENT = "10.10.0.23"
CLIENT_MAC = "02:00:00:00:00:23"
GATEWAY_MAC = "02:00:00:00:00:01"

random.seed(SEED)
packets = []
used_ports = set()


def ephemeral_port():
    while True:
        port = random.randint(49152, 65535)
        if port not in used_ports:
            used_ports.add(port)
            return port


def connection(ts, dst, dport, payload):
    """Uma conexão TCP completa: handshake, um envio de dados e encerramento."""
    sport = ephemeral_port()
    seq_c, seq_s = random.randint(1, 2**31), random.randint(1, 2**31)
    c2s = lambda **kw: Ether(src=CLIENT_MAC, dst=GATEWAY_MAC) / IP(src=CLIENT, dst=dst) / TCP(sport=sport, dport=dport, **kw)
    s2c = lambda **kw: Ether(src=GATEWAY_MAC, dst=CLIENT_MAC) / IP(src=dst, dst=CLIENT) / TCP(sport=dport, dport=sport, **kw)
    n = len(payload)
    steps = [
        (0.0000, c2s(flags="S", seq=seq_c)),
        (0.0004, s2c(flags="SA", seq=seq_s, ack=seq_c + 1)),
        (0.0005, c2s(flags="A", seq=seq_c + 1, ack=seq_s + 1)),
        (0.0007, c2s(flags="PA", seq=seq_c + 1, ack=seq_s + 1) / Raw(payload)),
        (0.0009, s2c(flags="A", seq=seq_s + 1, ack=seq_c + 1 + n)),
        (0.0010, c2s(flags="FA", seq=seq_c + 1 + n, ack=seq_s + 1)),
        (0.0012, s2c(flags="FA", seq=seq_s + 1, ack=seq_c + 2 + n)),
        (0.0013, c2s(flags="A", seq=seq_c + 2 + n, ack=seq_s + 2)),
    ]
    for offset, pkt in steps:
        pkt.time = ts + offset
        packets.append(pkt)


def series(dst, dport, start, count, interval, jitter, payload_fn):
    t = start
    for i in range(count):
        connection(t, dst, dport, payload_fn(i, t))
        t += interval + random.uniform(-interval * jitter, interval * jitter)


def lab_payload(i, t):
    from datetime import datetime
    stamp = datetime.fromtimestamp(t).strftime("%Y-%m-%d %H:%M:%S.%f")
    return f"{stamp} | Host=WS-LAB01 | Usuario=aluno | Sistema=Windows".encode()


def random_bytes(size):
    return lambda i, t: bytes(random.getrandbits(8) for _ in range(size))


# 1. beacon do laboratório: 30 s, jitter de 0,01%
series("10.10.0.5", 9000, START + 3, 12, 30.0, 0.0001, lab_payload)

# 2. beacon cifrado: 60 s com 10% de jitter
series("203.0.113.50", 443, START + 11, 10, 60.0, 0.10, random_bytes(96))

# 3. navegação humana: intervalos exponenciais, média de 25 s
t = START + 1
for _ in range(16):
    connection(t, "198.51.100.10", 443, bytes(random.getrandbits(8) for _ in range(random.randint(200, 1400))))
    t += random.expovariate(1 / 25)

# 4. beacon com 50% de jitter: 45 s
series("203.0.113.77", 8080, START + 20, 10, 45.0, 0.50, random_bytes(64))

# 5. rajada: 8 conexões a cada 0,2 s
series("198.51.100.20", 80, START + 200, 8, 0.2, 0.0, lambda i, t: b"GET / HTTP/1.1\r\nHost: example.test\r\n\r\n")

packets.sort(key=lambda p: p.time)
out = Path(__file__).with_name("beacon_sample.pcap")
wrpcap(str(out), packets)
print(f"{len(packets)} pacotes gravados em {out}")
