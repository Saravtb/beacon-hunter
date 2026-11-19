-- Consultas de investigação sobre a tabela detections.
-- Funcionam no SQLite e no MySQL sem alteração.

-- 1. Quantas conexões foram registradas
SELECT COUNT(*) AS total_conexoes
FROM detections;

-- 2. Fluxos classificados como beacon, do mais ativo para o menos ativo
SELECT src_ip, dst_ip, dst_port, COUNT(*) AS conexoes
FROM detections
WHERE periodic = 1
GROUP BY src_ip, dst_ip, dst_port
ORDER BY conexoes DESC;

-- 3. Menor e maior intervalo observado em cada beacon
SELECT dst_ip, dst_port,
       MIN(interval_s) AS menor_intervalo_s,
       MAX(interval_s) AS maior_intervalo_s
FROM detections
WHERE periodic = 1
GROUP BY dst_ip, dst_port;

-- 4. Volume de dados enviado para cada destino
SELECT dst_ip, dst_port, SUM(payload_bytes) AS bytes_enviados
FROM detections
GROUP BY dst_ip, dst_port
ORDER BY bytes_enviados DESC;

-- 5. Beacons que trafegam em texto claro (conteúdo legível por quem observa a rede)
SELECT DISTINCT dst_ip, dst_port
FROM detections
WHERE periodic = 1 AND cleartext = 1;

-- 6. Primeira e última vez que cada beacon foi visto
SELECT dst_ip, dst_port,
       MIN(detected_at) AS primeira_vez,
       MAX(detected_at) AS ultima_vez
FROM detections
WHERE periodic = 1
GROUP BY dst_ip, dst_port;

-- 7. Destinos que recebem conexões de mais de uma máquina (HAVING)
SELECT dst_ip, dst_port
FROM detections
GROUP BY dst_ip, dst_port
HAVING COUNT(DISTINCT src_ip) > 1;

-- 8. Conexões com intervalo acima da média do próprio fluxo (subconsulta correlacionada)
SELECT d.id, d.dst_ip, d.dst_port, d.interval_s
FROM detections d
WHERE d.interval_s > (
    SELECT AVG(x.interval_s)
    FROM detections x
    WHERE x.dst_ip = d.dst_ip AND x.dst_port = d.dst_port
)
ORDER BY d.dst_port, d.interval_s DESC;

-- 9. Portas de destino usadas por beacons
SELECT dst_port, COUNT(DISTINCT dst_ip) AS destinos
FROM detections
WHERE periodic = 1
GROUP BY dst_port
ORDER BY dst_port;

-- 10. O fluxo mais regular de todos (menor coeficiente de variação, subconsulta)
SELECT src_ip, dst_ip, dst_port, cv
FROM detections
WHERE cv = (SELECT MIN(cv) FROM detections WHERE periodic = 1)
  AND periodic = 1
LIMIT 1;
