-- Schema para MySQL. O beacon-hunter cria a tabela sozinho na primeira execução
-- com --db mysql://..., mas o banco precisa existir antes.

CREATE DATABASE IF NOT EXISTS seguranca_lab
    CHARACTER SET utf8mb4
    COLLATE utf8mb4_unicode_ci;

USE seguranca_lab;

CREATE TABLE IF NOT EXISTS detections (
    id             INT AUTO_INCREMENT PRIMARY KEY,
    detected_at    DATETIME(3)  NOT NULL,
    src_ip         VARCHAR(45)  NOT NULL,
    src_port       INT          NOT NULL,
    dst_ip         VARCHAR(45)  NOT NULL,
    dst_port       INT          NOT NULL,
    sequence       INT          NOT NULL,   -- posição da conexão no fluxo
    interval_s     DOUBLE,                  -- segundos desde a conexão anterior
    mean_s         DOUBLE,                  -- média dos intervalos até aqui
    stdev_s        DOUBLE,                  -- desvio padrão dos intervalos
    cv             DOUBLE,                  -- desvio / média
    periodic       TINYINT(1)   NOT NULL DEFAULT 0,
    payload_bytes  INT          NOT NULL DEFAULT 0,
    cleartext      TINYINT(1),              -- 1 texto claro, 0 não legível, NULL sem dados
    payload        TEXT                     -- só preenchido quando é texto claro
);
