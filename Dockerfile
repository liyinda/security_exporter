FROM        quay.io/prometheus/busybox:latest
MAINTAINER  liyinda <liyinda0000@163.com>

COPY security_exporter  /bin/security_exporter
COPY docker-entrypoint.sh /bin/docker-entrypoint.sh

ENV METRICS_ENDPOINT "/metrics"
ENV METRICS_ADDR ":9933"

ENTRYPOINT [ "docker-entrypoint.sh" ]
