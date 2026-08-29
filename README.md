# Standalone 3proxy setup 2.0.0

Пакет устанавливает 3proxy 1.0.0 из проверенного tag-архива, собирает основной
binary с обязательным OpenSSL client support, создаёт выбранные listeners и
запускает health-check. Рассчитан на Ubuntu/Debian с `apt-get`, `systemd` и
доступом в интернет.

Версия 2.0.0 добавляет полноценный HTTPS upstream (`connect+s`) с обязательной
проверкой CA и DNS-имени сертификата, отдельный bind для каждого listener и
безопасный local-only профиль для цепочки Telemt → SOCKS5 → HTTPS proxy.
Существующие direct, SOCKS5-parent, plaintext HTTP-parent, strong/iponly access,
UDP и `monitor_v1` остаются совместимыми.

## Что изменилось в 3proxy 1.0.0

Исходник жёстко закреплён за официальным тегом и SHA-256:

```text
version: 1.0.0
source:  https://github.com/3proxy/3proxy/archive/refs/tags/1.0.0.tar.gz
sha256:  35b07de1046f3aaeac4a7085101b7e5c453efa3527cbdc42a84690366c7ecfa8
```

Три из четырёх прежних UDP-over-SOCKS патчей больше не применяются: их логика
либо уже вошла в upstream, либо была заменена новой официальной реализацией.
Сохранён только перенесённый на 1.0.0 parser fix для SOCKS5 BND reply; он
предотвращает перезапись request buffer, исправляет offsets IPv4/IPv6 и безопасно
считывает domain-form ответ. Фактический UDP relay в поддерживаемой runtime-схеме
по-прежнему использует IPv4 BND. Подробности находятся в `patches/README.md`.

Сборка выполняется CMake с `3PROXY_USE_OPENSSL=ON` и
`3PROXY_USE_WOLFSSL=OFF`. Отсутствие OpenSSL останавливает установку. Перед
заменой установленного binary проверяются CMake flags, dynamic dependencies и
runtime-разбор TLS client directives.

## Быстрый запуск

После распаковки на VM:

```bash
cd 3proxy-setup
cp config.example.yaml config.yaml
nano config.yaml
sudo ./setup3proxy.sh all
```

ZIP хранит Unix mode metadata: setup, cleanup, step-скрипты и Python tools
получают `0755` при обычной распаковке на Linux.

Для применения только конфига и systemd unit без повторной сборки binary:

```bash
sudo ./setup3proxy.sh reconfigure
```

`reconfigure` не обновляет 3proxy. При переходе с 1.x setup-пакета на 2.0.0
обязательно запускайте `all`, чтобы собрать и установить 3proxy 1.0.0.
В существующем приватном YAML замените весь `install` block значениями из
`config.example.yaml`. Новые `tls`, `https_primary` и HTTPS listeners не нужны,
пока используется только прежняя direct/SOCKS5/HTTP topology.

В `config.yaml` замените:

- `server.public_ip` на публичный IPv4 VM
- `local_auth` на локальные credentials прокси при `access.mode: strong`
- адреса, порты и credentials используемых upstream
- `expected_egress_ip` на ожидаемый внешний IP каждого upstream

Если UFW должен настраиваться автоматически, установите `manage_ufw: true`.
Listener, привязанный к loopback, намеренно не добавляется в UFW. Облачный
firewall/security group всегда настраивается отдельно.

## HTTPS upstream для Telemt

Начните с отдельного безопасного профиля:

```bash
cp config.telemt-bridge.example.yaml config.yaml
nano config.yaml
sudo ./setup3proxy.sh all
```

Ключевые поля:

```yaml
tls:
  client_ca_file: "/etc/ssl/certs/ca-certificates.crt"

upstreams:
  https_primary:
    type: "https"
    host: "proxy.example.com"
    port: 8443
    username: "UPSTREAM_USER"
    password: "UPSTREAM_PASSWORD"
    tls_server_name: "proxy.example.com"
    expected_egress_ip: "198.51.100.20"
    capabilities: [tcp]

listeners:
  - id: "socks_via_https"
    protocol: "socks5"
    listen_ip: "127.0.0.1"
    port: 11080
    parent: "https_primary"
    capabilities: [tcp]
```

`tls_server_name` обязателен, должен быть DNS-именем из сертификата upstream и
не может быть IP-literal. Генератор всегда включает:

```text
ssl_client_mode 3
ssl_client_verify
ssl_client_ca_file ...
ssl_client_sni ...
ssl_client_min_proto_version TLSv1.2
ssl_cli
parent 1000 connect+s ...
```

Небезопасного флага для отключения certificate verification нет. Если upstream
работает только по whitelist и не требует Basic auth, удалите одновременно
`username` и `password`; указывать только одно из двух запрещено.

Telemt подключается к `127.0.0.1:11080` как к обычному SOCKS5 upstream. Для
этой двухступенчатой схемы у Telemt должно остаться `use_middle_proxy = false`:
Telegram middle-proxy handshake требует внешний BND tuple, которого HTTP(S)
CONNECT provider не сообщает локальному 3proxy. Это не отключает настроенный
SOCKS upstream — Telemt всё равно соединяется с Telegram DC через него.

TLS применяется только на участке 3proxy → HTTPS upstream. Для каждого secure
listener генератор включает `ssl_cli`, а сразу после service сбрасывает состояние
через `ssl_nocli`, поэтому direct, SOCKS5 и plaintext HTTP listeners в том же
процессе не меняются. UDP через HTTP(S) CONNECT не поддерживается и отклоняется
схемой; direct UDP и UDP через SOCKS5 parent сохраняются.

При необходимости можно вместо `socks_via_https` или вместе с ним объявить
`http_via_https` (`protocol: http`, `parent: https_primary`, capabilities `[tcp]`).

## Доступ и логирование

`config.iponly.example.yaml` — passwordless direct profile, ограниченный source
IPv4. В режиме `iponly` требуется непустой allowlist, `/0` запрещён, каждый ACL
заканчивается `deny *`. `local_auth` и `upstreams` полностью direct-профилю не
нужны.

`monitor_v1` использует машинно-читаемый logformat, ежедневную встроенную
ротацию, gzip и группу `proxy-observability` для непривилегированного read-only
мониторинга. Старый журнал при первом переключении сохраняется как
`3proxy.log.pre-monitor-*.gz`.

Боевые профили именуйте по SSH-алиасу, например `config.yc-vm-0426.yaml`, и
всегда передавайте через `--config`. `config.yaml` содержит секреты: храните его
с правами `600` и не добавляйте в репозитории или общедоступные архивы.

## Шаги и проверки

```bash
sudo ./setup3proxy.sh 0  # остановка, диагностика и backup
sudo ./setup3proxy.sh 1  # CMake/OpenSSL сборка и установка 3proxy
sudo ./setup3proxy.sh 2  # генерация config/systemd/UFW
sudo ./setup3proxy.sh 3  # запуск и VM-side health-check
```

Можно использовать YAML вне каталога:

```bash
sudo ./setup3proxy.sh all --config /secure/path/proxy.yaml
```

Полный e2e-тест запускается с клиентской машины, имеющей доступ к VM:

```bash
python3 -m venv venv
venv/bin/pip install PyYAML
venv/bin/python tools/healthcheck.py --scope e2e --config config.yaml
```

При `--scope vm` local-only listener проверяется через его loopback bind. При
`--scope e2e` он явно помечается `N/A`, потому что с внешней машины недоступен.
HTTPS upstream проверяется отдельными TLS HTTP GET и CONNECT probes с тем же SNI,
CA trust и минимумом TLS 1.2.

## Полная очистка

Без `--yes` cleaner работает как dry-run и только показывает план:

```bash
./clean3proxy.sh
sudo ./clean3proxy.sh --yes
```

Очистка останавливает service и процессы, удаляет binary, systemd unit, конфиги,
логи, runtime state, build manifest и rollback-backup. Распакованный каталог
сохраняется для повторной установки. Дополнительные режимы:

```bash
sudo ./clean3proxy.sh --yes --keep-backups
sudo ./clean3proxy.sh --yes --purge-setup
sudo ./clean3proxy.sh --yes --purge-ufw
```

`--purge-ufw` включается только явно. Он удаляет лишь правила для non-loopback
listeners и dynamic UDP relay, если такой внешний UDP listener был настроен.
Cleaner не меняет cloud security groups и не очищает глобальный systemd journal.
