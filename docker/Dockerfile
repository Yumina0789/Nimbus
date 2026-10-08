# Nimbus + vlmcsd —— 一个容器装齐 KMS 服务和 Web 管理面板
#
#   docker build -t nimbus:local .
#   docker run -d --name kms -p 1688:1688 -v nimbus-data:/var/lib/nimbus \
#          -v /etc/nimbus.token:/etc/nimbus.token:ro nimbus:local
#
# 镜像里跑两个进程（由 supervisord 管）：vlmcsd 和 nimbus.py。
# 之所以放在一起：面板要读写 vlmcsd 的 ini、给它发 SIGHUP、还要读它的日志，
# 拆成两个容器就得额外挂 docker.sock 或共享 PID namespace，反而更脏。
FROM python:3.12-alpine

LABEL org.opencontainers.image.title="Nimbus" \
      org.opencontainers.image.description="vlmcsd KMS server + Nimbus web panel in one container" \
      org.opencontainers.image.source="https://github.com/Yumina0789/Nimbus" \
      org.opencontainers.image.licenses="GPL-3.0-or-later"

# supervisor 管两个进程；curl 用来取 vlmcsd 的静态二进制
RUN apk add --no-cache supervisor curl tzdata

# alpine 的 supervisor 包不带主配置（那是 Debian 的习惯），自己写一份：
# 前台运行 + 把 conf.d 收进来。
RUN mkdir -p /etc/supervisor/conf.d /run \
 && printf '%s\n' \
      '[supervisord]' \
      'nodaemon=true' \
      'logfile=/dev/null' \
      'logfile_maxbytes=0' \
      'pidfile=/run/supervisord.pid' \
      '[unix_http_server]' \
      'file=/run/supervisor.sock' \
      '[supervisorctl]' \
      'serverurl=unix:///run/supervisor.sock' \
      '[rpcinterface:supervisor]' \
      'supervisor.rpcinterface_factory = supervisor.rpcinterface:make_main_rpcinterface' \
      '[include]' \
      'files = /etc/supervisor/conf.d/*.conf' \
      > /etc/supervisor/supervisord.conf

# vlmcsd / vlmcs 是 musl 静态二进制（由 vlmcsd 部署项目发布），alpine 上直接可用，
# 不需要任何 C 运行时依赖。
ARG RELEASE_TAG=binaries
ARG RELEASE_BASE=https://github.com/Yumina0789/V1mc4d/releases/download
ARG ARCH=x86_64
RUN set -eux; \
    for name in vlmcsd vlmcs; do \
      curl -fsSL --retry 3 --connect-timeout 15 -H 'Cache-Control: no-cache' \
        "${RELEASE_BASE}/${RELEASE_TAG}/${name}-linux-${ARCH}-static" \
        -o "/usr/local/bin/${name}"; \
      chmod 0755 "/usr/local/bin/${name}"; \
    done; \
    /usr/local/bin/vlmcsd -V | head -1

COPY nimbus.py /opt/nimbus/nimbus.py
COPY ui.html /opt/nimbus/ui.html
COPY docker/supervisord.conf /etc/supervisor/conf.d/nimbus.conf
COPY docker/entrypoint.sh /entrypoint.sh
RUN chmod 0755 /entrypoint.sh \
 && mkdir -p /var/lib/nimbus /var/log /etc/vlmcsd \
 && chmod 0700 /var/lib/nimbus

VOLUME ["/var/lib/nimbus"]
EXPOSE 1688 8099
ENTRYPOINT ["/entrypoint.sh"]
CMD ["/usr/bin/supervisord", "-n", "-c", "/etc/supervisor/supervisord.conf"]
