# 这个目录放「别的服务」的 Caddy 站点文件

主 `Caddyfile` 末尾有一行：

```
import /etc/caddy/sites/*.caddy
```

这个目录以只读方式挂进 caddy 容器（compose 里 `./caddy-sites:/etc/caddy/sites:ro`）。

## 为什么单独放文件

Nimbus 的「域名与 HTTPS」页会读写主 `Caddyfile`，而它的实现里有一条刻意的限制：
**Caddyfile 里出现多个站点块时它拒绝替你猜要改哪一个**。把别的站点放进这个目录，
主文件里就永远只有 Nimbus 自己那一个站点块，两边互不打扰。

## 注意

`import` 的 glob **匹配不到任何文件时 Caddy 会启动失败**。所以这个目录至少要留一个
文件 —— 本文件的 `.gitkeep` 不行（它不是 `.caddy`）。要么放一个真实站点文件，要么放
一个空文件，例如：

```bash
touch caddy-sites/.keep.caddy
```

## 例子：把宿主机上的 Steward 面板挂出来

```caddyfile
# caddy-sites/steward.caddy
panel.example.com {
	encode zstd gzip
	reverse_proxy 172.18.0.1:8402      # 宿主在 compose 网桥上的地址

	header {
		Strict-Transport-Security "max-age=31536000; includeSubDomains"
		X-Content-Type-Options "nosniff"
		X-Frame-Options DENY
		-Server
	}
}
```

配套三件事（都在 Steward 那边）：面板要额外绑一份网桥地址
（`--bind 127.0.0.1,docker`）、加来源白名单（`--allow-ip 127.0.0.0/8,::1,172.16.0.0/12,...`），
以及放行网桥到面板端口的流量（`ufw allow from 172.18.0.0/16 to any port 8402 proto tcp`）。
Steward 的 README 里有完整步骤。
