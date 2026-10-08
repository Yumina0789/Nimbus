#!/bin/sh
# 容器启动前的准备：vlmcsd 的 ini 必须存在，否则
#   * vlmcsd 会退回"命令行参数"而不是 ini（面板改参数就不生效），
#   * 面板写 ini 时会因为目录/文件不存在而报错。
# 空 ini 是完全合法的（每一项都用默认值），面板接手后会往里写。
set -eu

INI="${VLMCSD_INI:-/etc/vlmcsd/vlmcsd.ini}"
mkdir -p "$(dirname "$INI")" /var/log /var/lib/nimbus

if [ ! -f "$INI" ]; then
    printf '; created by the Nimbus container entrypoint\n' > "$INI"
    echo "[entrypoint] created empty $INI (all defaults)"
fi

# token 与统计库放在同一个持久卷里：容器重建、镜像升级都不会把你踢下线。
TOKEN="${NIMBUS_TOKEN_FILE:-/var/lib/nimbus/nimbus.token}"
if [ ! -s "$TOKEN" ]; then
    python3 -c 'import secrets; print(secrets.token_urlsafe(24))' > "$TOKEN"
    chmod 0600 "$TOKEN"
    echo "[entrypoint] generated a fresh token in $TOKEN:"
    cat "$TOKEN"
else
    echo "[entrypoint] reusing token from $TOKEN"
fi

exec "$@"
