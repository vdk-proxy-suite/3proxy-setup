# Standalone 3proxy setup 2.3.0

Upstream: [3proxy/3proxy](https://github.com/3proxy/3proxy).

Пакет устанавливает 3proxy 1.0.0 из проверенного tag-архива, собирает основной
binary с обязательным OpenSSL client support, создаёт выбранные listeners и
запускает health-check. Рассчитан на Ubuntu/Debian с `apt-get`, `systemd` и
доступом в интернет.

Версия 2.2.0 добавляет необязательный `listeners[].access`: без этого поля
listener наследует весь глобальный access block, а при наличии локальный block
полностью его заменяет и требует явный `mode`. Это позволяет сохранить
публичные listeners в `strong`, а отдельный loopback SOCKS listener перевести в `iponly` для
локального HAProxy. Healthcheck использует фактический режим каждого listener
и для `iponly` SOCKS дополнительно выполняет обязательный raw SOCKS4 CONNECT
без аутентификации. Версия установленного 3proxy остаётся закреплена на 1.0.0.

Версия 2.1.1 исправляет build-time проверки без изменения YAML или runtime
топологии. Patchset digest теперь зависит только от имён и содержимого патчей,
а не от абсолютного staging-пути. Обязательный combined OpenSSL smoke использует
одноразовый TLS CONNECT parent: он проверяет SNI от 3proxy, принимает только
ожидаемый CONNECT authority и возвращает `200` через тот же TLS-канал. Это
заменяет недостоверный поиск request line в выводе `openssl s_server -www`,
который эту строку не журналирует.

Версия 2.1.0 добавляет настоящий HTTPS forward-proxy listener: соединение
клиент → 3proxy начинается с проверяемого TLS, а внутри него работает обычный
HTTP proxy с GET и CONNECT. Установщик создаёт для каждой VM приватный CA и
серверный сертификат с обязательным IP SAN, хранит ключи только под
`/etc/3proxy-setup/instances/main/tls` и переиспользует действующий trust anchor при перевыпуске leaf.
HTTPS listener можно независимо сочетать с direct, SOCKS5, HTTP и HTTPS
маршрутами. Поэтому доступны полные 3 direct + 9 two-hop комбинаций.

Версия 2.0.1 разрешила произвольно именовать listeners и подключать несколько
SOCKS5/HTTP listeners к одному upstream. Версия 2.0.0 добавила HTTPS upstream
(`connect+s`) с обязательной проверкой CA и DNS-имени сертификата. Старые YAML
без HTTPS listener, direct, SOCKS5/HTTP/HTTPS parents, strong/iponly access, UDP
и `monitor_v1` остаются совместимыми.

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
реальный combined runtime-маршрут TLS client → HTTPS listener → 3proxy → HTTPS
parent. На входе проверяются CA и IP SAN, на выходе — CA и ожидаемый DNS SNI;
parent дополнительно валидирует сам CONNECT request.

## Изолированные экземпляры (2.3.0)

Каждая распакованная папка принадлежит одному `instance.id`. В YAML обязательно
задайте уникальный ID по шаблону `[a-z][a-z0-9-]{0,19}`; примеры содержат `main`.
Перед установкой второго экземпляра измените и ID, и занятые первым порты.
Имя папки не определяет ID. Параллельные setup не поддерживаются.

```yaml
instance:
  id: "main"
```

Установщик сохраняет root-owned manifest до создания ресурсов и проверяет
владельца, symlink/hardlink, UID/GID, хеш unit и конфликт портов перед изменениями.
Имена unit/user/group выводятся из ID; произвольные переопределения путей и имён
не поддерживаются. Неизвестный ID нельзя остановить или удалить. При повторном
развёртывании того же ID из другой папки требуется `--update-existing`; это
явное обновление уже установленного экземпляра. Скопированная папка с прежним
ID не создаёт второй экземпляр.

| Ресурс | Путь для `main` |
|---|---|
| Unit / user / group | `3proxy-main.service` / `3proxy-main` / `3proxy-main` |
| Конфиги и private CA | `/etc/3proxy-setup/instances/main/` |
| Binary | `/opt/3proxy/instances/main/bin/3proxy` |
| Данные | `/var/lib/3proxy-instances/main/` |
| Логи и healthchecks | `/var/log/3proxy-setup/instances/main/` |
| Runtime | `/run/3proxy-main/` |
| Manifest, сборка и backups | `/var/lib/3proxy-setup/instances/main/` |
| Установленные управляющие скрипты | `/usr/local/lib/3proxy-setup/instances/main/` |

Сервис работает от отдельного системного пользователя с правом bind низких
портов. Config и server key доступны его группе; private CA key остаётся
root-only. `proxy-observability` сохраняет доступ к файлам журналов. Выбранный
экземпляр имеет собственный binary: обновление A не заменяет executable B.
После переноса или удаления распакованной папки сервис и управление через
установленные скрипты продолжают работать:

```bash
sudo ./setup3proxy.sh all --config ./config.yaml
sudo ./setup3proxy.sh update --instance main
sudo ./setup3proxy.sh reconfigure --config ./config.yaml
sudo ./setup3proxy.sh stop --instance main
sudo ./setup3proxy.sh start --instance main
sudo ./setup3proxy.sh status --instance main
sudo ./setup3proxy.sh healthcheck --instance main
sudo ./setup3proxy.sh backup --instance main
sudo ./setup3proxy.sh rollback --instance main
sudo /usr/local/lib/3proxy-setup/instances/main/setup3proxy.sh status --instance main
```

`--instance ID` использует установленный `setup.yaml`, а до окончания установки
— защищённый snapshot в state. При одновременных `--config` и `--instance` ID
должны совпадать. Те же аргументы принимают отдельные `steps/00..03`;
`tools/healthcheck.py` принимает `--config` или `--instance`. Backup, как и шаг 0,
останавливает только выбранный unit; возобновить его можно через `start`.
Rollback восстанавливает конфиг, binary, PKI и прежнее enabled/active состояние.
Шаги и rollback не используют глобальный поиск/убийство процессов по имени.

Относительный `tls.client_ca_file` разрешается относительно YAML, независимо
от текущего каталога. Пользовательский public CA копируется в `client-ca.crt`
в каталоге instance; runtime и сохранённый YAML используют этот устойчивый путь.
Новый CA сначала сохраняется в state и применяется после backup; rollback
восстанавливает прежний CA. Исходная папка для работы TLS-parent не требуется.

Setup не обновляет уже установленные общие пакеты. Запрашиваются только отсутствующие
зависимости; если solver требует обновления или удаления уже установленных
пакетов, установка останавливается: зависимости нужно обновить отдельно.
Для чтения YAML заранее нужны `python3` и `python3-yaml`. Общие ОС, сеть,
пакеты и journal остаются общими; namespace ресурсов не является контейнером.

### Существующая установка без ID

Старый YAML не переводится в новый namespace автоматически. Для осознанного
обслуживания прежнего `3proxy.service` добавьте `--legacy` к `all`, `reconfigure`
или отдельному шагу. Первое принятие существующего unit допускает только точный
unit предыдущего релиза, без сторонних drop-ins; установщик сохраняет manifest.
Legacy cleanup после такого принятия удаляет только известные legacy-файлы,
не каталоги `instances/`, не чужие процессы и не общие журналы.

Для перехода с legacy на named instance: сохраните legacy backup и CA, создайте
профиль с новым ID и свободными портами, установите и проверьте новый экземпляр,
переключите клиентов, затем явно остановите/очистите legacy через `--legacy`.
При необходимости сохранить прежний trust anchor скопируйте CA/leaf из backup
в новый root-owned `.../instances/ID/tls` после шага 1 и до шага 2; ключи должны
остаться защищёнными. Автоматический перенос/удаление старого экземпляра и
неявное присвоение его identity не выполняются.

## Быстрый запуск

После распаковки на VM:

```bash
cd 3proxy-setup
cp config.example.yaml config.yaml
nano config.yaml  # задайте instance.id и свободные порты
sudo ./setup3proxy.sh all
```

ZIP хранит Unix mode metadata: setup, cleanup, step-скрипты и Python tools
получают `0755` при обычной распаковке на Linux.

Для применения только конфига и systemd unit без повторной сборки binary:

```bash
sudo ./setup3proxy.sh reconfigure
```

`reconfigure` не обновляет 3proxy. При переходе с 1.x setup-пакета на 2.x
обязательно запускайте `all`, чтобы собрать и установить 3proxy 1.0.0.
В существующем приватном YAML замените весь `install` block значениями из
`config.example.yaml`. Новые `tls`, `https_primary` и HTTPS listeners не нужны,
пока используется только прежняя direct/SOCKS5/HTTP topology.

При обновлении с 2.0.x на 2.1.x пересборка binary не требуется: server-side TLS
уже присутствует в закреплённой OpenSSL-сборке 3proxy 1.0.0. Если новый HTTPS
listener не добавляется, достаточно `reconfigure`, а старые YAML и ID вроде
`socks_via_https` остаются валидными. При первом добавлении HTTPS listener
`reconfigure` также достаточно, если на VM уже доступен `openssl`: шаг
конфигурации атомарно создаст managed PKI до перезапуска сервиса. Если команды
`openssl` нет, используйте `all`, который устанавливает зависимость и повторно
проверяет одновременно server-side и client-side TLS. Приватные `config*.yaml`,
сертификаты и ключи установщик и release-архив не включают.

Переход с 2.1.0 на 2.1.1 не требует изменений конфигурации. Для уже проверенного
OpenSSL binary допустим штатный `reconfigure`. Первый последующий запуск `all`
пересоберёт binary один раз, потому что прежний manifest содержал зависящий от
пути patchset digest; новый manifest остаётся одинаковым при переносе setup в
другой каталог.

Переход с 2.1.1 на 2.2.0 не требует пересборки binary и не меняет существующие
renders: listeners без собственного `access` продолжают наследовать глобальный
режим. Для добавления mixed-access listener достаточно штатного `reconfigure`.

В `config.yaml` замените:

- `instance.id` на уникальный ID установки

- `server.public_ip` на публичный IPv4 VM
- `local_auth` на локальные credentials прокси, если хотя бы один listener
  фактически использует `strong`
- адреса, порты и credentials используемых upstream
- `expected_egress_ip` на ожидаемый внешний IP каждого upstream

Если UFW должен настраиваться автоматически, установите `manage_ufw: true`.
Listener, привязанный к loopback, намеренно не добавляется в UFW. Облачный
firewall/security group всегда настраивается отдельно.

## HTTPS listener, upstream и полная матрица

`protocol: https` означает настоящий TLS-wrapped HTTP forward proxy: клиент
сначала устанавливает проверяемое TLS-соединение с 3proxy, затем передаёт внутри
него обычные HTTP proxy GET или CONNECT. Это отличается от `protocol: http`:
CONNECT позволяет открыть HTTPS-сайт, но сам участок клиент → proxy и Basic auth
при обычном HTTP listener остаются незашифрованными.

TLS на входе и TLS до parent независимы. Для HTTPS listener генератор ограниченно
включает `ssl_serv ... ssl_noserv`; для HTTPS parent —
`ssl_cli ... ssl_nocli`. В комбинации HTTPS listener → HTTPS parent оба режима
действуют одновременно, а проверка CA и SNI parent остаётся fail-closed. Минимум
на обоих TLS-участках — TLS 1.2.

`config.https.example.yaml` показывает combined HTTPS ingress → HTTPS parent,
рядом с HTTP/SOCKS listeners к тому же parent:

```bash
cp config.https.example.yaml config.yaml
nano config.yaml  # задайте instance.id и свободные порты
sudo ./setup3proxy.sh all
```

Ключевые поля:

```yaml
tls:
  client_ca_file: "/etc/ssl/certs/ca-certificates.crt"
  server:
    dns_names:
      - "proxy-vm.example.com"
    validity_days: 365
    ca_validity_days: 3650
    regenerate_on_setup: false

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
  - id: "public_https_tls"
    protocol: "https"
    listen_ip: "0.0.0.0"
    port: 8443
    parent: "https_primary"
    capabilities: [tcp]
  - id: "local_socks_tls"
    protocol: "socks5"
    listen_ip: "127.0.0.1"
    port: 11080
    parent: "https_primary"
    capabilities: [tcp]
    access:
      mode: "iponly"
      allowed_client_cidrs:
        - "127.0.0.1/32"
```

Полная схема находится в `config.matrix.example.yaml`:

| Вход в 3proxy | Direct | SOCKS5 parent | HTTP parent | HTTPS parent |
|---|---:|---:|---:|---:|
| SOCKS5 | `1080`, TCP+UDP | `1081`, TCP | `1082`, TCP | `1083`, TCP |
| HTTP | `8080`, TCP | `8081`, TCP | `8082`, TCP | `8083`, TCP |
| HTTPS | `8443`, TCP | `8444`, TCP | `8445`, TCP | `8446`, TCP |

Порты в примере не зарезервированы схемой. Получаются три direct listener и
девять two-hop комбинаций. UFW и cloud security group должны отдельно разрешать
только реально используемые публичные порты.

`tls.client_ca_file` относится только к HTTPS parent. `tls_server_name`
обязателен для такого parent, должен быть DNS-именем из его сертификата и не
может быть IP-literal. Генератор всегда включает:

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

У закреплённого upstream 3proxy 1.0.0 есть особенность обработки повторного
CONNECT: после отклонения credentials HTTPS-parent с `407` frontend иногда
возвращает клиенту вводящий в заблуждение `200 Connection established`, после
чего туннель закрывается без передачи данных. Это воспроизводится и до 2.3.0;
данный релиз не исправляет upstream parser и не меняет pin/patchset. Проверка
неверного пароля теперь детерминированно воспроизводит этот случай и требует
фактический parent `407`, отсутствие успешной авторизации, ноль переданных
байтов и ноль соединений с target (включая обходной direct). Сам по себе
frontend status не считается доказательством успешной авторизации или маршрута.
Проверки TLS-first, CA/SNI и остальных отказов сохраняются.

Поле `id` — непрозрачная метка listener, а не имя предопределённой topology.
Допустимы уникальные строки длиной до 64 символов по шаблону
`^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$`. Маршрут задаётся исключительно полями
`protocol`, `parent` и `capabilities`. Поэтому один `https_primary` можно
без дублирования credentials использовать у нескольких публичных и локальных
listeners. Порты listeners должны быть уникальны; loopback listener не создаёт
публичное UFW-правило. Установщик намеренно не зависит от приложения, которое
будет использовать конкретный listener.

## Managed TLS для HTTPS listeners

При наличии хотя бы одного HTTPS listener обязателен `tls.server`:

```yaml
tls:
  server:
    dns_names: []
    validity_days: 365
    ca_validity_days: 3650
    regenerate_on_setup: false
```

`server.public_ip` всегда включается в leaf как IP SAN. `dns_names` добавляет
необязательные DNS SAN. Срок leaf допустим от 2 до 825 дней, срок CA — от 2 до
3650 дней и должен быть больше срока leaf. `tls.server` допустим только при
HTTPS listener; независимый `tls.client_ca_file` — только при HTTPS upstream.

PKI хранится в защищённом каталоге `/etc/3proxy-setup/instances/main/tls`:

- `ca.crt` — публичный trust anchor, который передаётся клиентам
- `ca.key` — приватный ключ CA, который нельзя копировать с VM
- `server.crt` и `server.key` — leaf certificate и его приватный ключ

В named instance каталог имеет mode `750` и группу instance; `server.key` —
`640 root:instance`, а `ca.key` — `600 root:root`. В legacy режиме ключи доступны root. При
`regenerate_on_setup: false` валидный CA сохраняется. Leaf переиспользуется,
пока цепочка, ключ, IP SAN, точный набор DNS SAN и срок действия соответствуют
конфигурации. Смена публичного IP или DNS SAN перевыпускает только leaf под тем
же CA, поэтому trust anchor клиентов не меняется.

CA заменяется, если повреждён, просрочен или не сможет прожить весь новый leaf.
`regenerate_on_setup: true` принудительно меняет CA и leaf при каждом setup;
после этого всем клиентам надо заново передать `ca.crt`. Новый каталог сначала
формируется и проверяется, затем атомарно заменяет действующий. Backup сохраняет
старую PKI, а автоматический rollback восстанавливает её целиком.

## UDP и TCP-only SOCKS

HTTP и HTTPS listeners всегда TCP-only. SOCKS5 listener с
`capabilities: [tcp]` тоже строго TCP-only: renderer ставит
`deny * * * * UDPASSOC` перед разрешающим ACL и parent route, а healthcheck
требует получить отказ на UDP ASSOCIATE. Это не позволяет встроенному UDP relay
3proxy обойти TCP-only parent.

UDP сохраняется только у SOCKS5 listener с `[tcp, udp]`. Для two-hop SOCKS5 и
listener, и upstream должны содержать `udp`, а провайдер обязан реально
поддерживать UDP ASSOCIATE. В matrix-example UDP включён только на direct SOCKS5
`1080`.

## Доступ и логирование

`config.iponly.example.yaml` — passwordless direct profile, ограниченный source
IPv4. В режиме `iponly` требуется непустой allowlist, `/0` запрещён, каждый ACL
заканчивается `deny *`. `local_auth` и `upstreams` полностью direct-профилю не
нужны.

Глобальный `access` остаётся default для всех listeners. Если
`listeners[].access` отсутствует, listener наследует global block целиком. Если
поле присутствует, оно полностью заменяет global block для этого listener,
обязано явно содержать `mode` и самостоятельно задавать
`allowed_client_cidrs` для `iponly`. Типичный локальный адаптер к проверяемому
HTTPS parent выглядит так:

```yaml
access:
  mode: "strong"

local_auth:
  username: "PUBLIC_USER"
  password: "PUBLIC_PASSWORD"

listeners:
  - id: "whatsapp_media_bridge"
    protocol: "socks5"
    listen_ip: "127.0.0.1"
    port: 11081
    parent: "https_primary"
    capabilities: [tcp]
    access:
      mode: "iponly"
      allowed_client_cidrs:
        - "127.0.0.1/32"
```

Renderer оставляет остальные listeners в `strong`, а для этого блока создаёт
`auth iponly`, loopback allow и завершающий `deny *`. Loopback bind не
публикуется через UFW. `protocol: socks5` выбирает сервис `socks` 3proxy,
который принимает и SOCKS5, и SOCKS4; strong listeners проверяются по SOCKS5 с
credentials, а effective-`iponly` listeners — по SOCKS5 no-auth и отдельному
raw SOCKS4 no-auth probe.

SOCKS4 передаёт destination как IPv4, а не hostname. Поэтому HAProxy или
healthcheck сначала разрешает DNS локально, а HTTPS parent затем получает
`CONNECT <IPv4>:<port>`. Если требуется именно remote DNS или hostname в
CONNECT authority, этот SOCKS4 adapter такую семантику не предоставляет.

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

Для HTTPS listener скопируйте с VM только публичный CA через доверенный SSH
канал. Приватные `ca.key` и `server.key` должны остаться на VM:

```bash
ssh VM_ALIAS 'sudo cat /etc/3proxy-setup/instances/main/tls/ca.crt' > ./VM_ALIAS-3proxy-ca.crt
openssl x509 -in ./VM_ALIAS-3proxy-ca.crt -noout -fingerprint -sha256
```

Полный e2e-тест запускается с клиентской машины, имеющей доступ к VM:

```bash
python3 -m venv venv
venv/bin/pip install PyYAML
venv/bin/python tools/healthcheck.py \
  --scope e2e \
  --config config.yaml \
  --proxy-ca-file ./VM_ALIAS-3proxy-ca.crt \
  --skip-upstreams
```

`--proxy-ca-file` обязателен в E2E, если выбран хотя бы один HTTPS listener.
Проверка доверяет этому CA, сверяет IP SAN с `server.public_ip`, требует TLS 1.2+
и доказывает отказ принимать plaintext HTTP. `--skip-upstreams` отключает только
отдельные прямые probes клиент → upstream; listener probes всё равно проходят
полную цепочку клиент → VM → parent → target и проверяют ожидаемый egress. Это
нужно, когда upstream whitelist разрешает только IP виртуальной машины. Для
одного маршрута используйте, например, `--endpoint https_via_https`; неизвестный
ID считается ошибкой.

При `--scope vm` local-only listener проверяется через его loopback bind. При
`--scope e2e` он явно помечается `N/A`, потому что с внешней машины недоступен.
HTTPS upstream проверяется отдельными TLS HTTP GET и CONNECT probes с тем же SNI,
CA trust и минимумом TLS 1.2. Для effective-`iponly` SOCKS listener результат
raw SOCKS4 probe обязателен и отдельно отображается как `socks4_tcp`.

Перед общим healthcheck шаг 3 обязательно запускает для каждого HTTPS listener
TLS gate. Его можно повторить вручную:

```bash
sudo python3 tools/healthcheck.py \
  --scope vm \
  --config config.yaml \
  --endpoint https_direct \
  --tls-gate-only
```

Gate проверяет цепочку, IP SAN, TLS 1.2+ и отказ plaintext, но намеренно не
выполняет forwarding. Поэтому он работает и при `access.mode: iponly`, когда
сама VM не входит в allowlist. Для `iponly` доступ, ACL и GET/CONNECT следует
доказать E2E с разрешённого внешнего IP; gate не расширяет ACL.

## Очистка одного экземпляра

Без `--yes` cleaner показывает dry-run. Выбор обязателен через YAML или ID:

```bash
sudo ./clean3proxy.sh --instance main
sudo ./clean3proxy.sh --instance main --yes
sudo ./clean3proxy.sh --instance main --yes --purge-logs
sudo ./clean3proxy.sh --instance main --yes --keep-backups
sudo ./clean3proxy.sh --instance main --yes --purge-setup
sudo ./setup3proxy.sh cleanup --instance main --yes
```

Обычная очистка удаляет unit, отдельный user/group, binary, конфиги/PKI, данные,
runtime и backups только выбранного экземпляра. Логи сохраняются; их удаляет
лишь `--purge-logs`. `--keep-backups` сохраняет root-only backup с приватным CA.
`--purge-setup` удаляет только отмеченную ownership token распакованную папку.
Если в ней остались `.log`, `.gz` или healthcheck reports, без `--purge-logs`
папка сохраняется целиком. Оставшиеся после прерывания сборки файлы удаляются,
а её `.log` сохраняются в `LOG_DIR/setup-build/`, если не указан `--purge-logs`.
Сохранённые журналы получают владельца root перед удалением service user,
чтобы повторное использование UID не открыло их другому экземпляру.
Проверка несовпадающего UID/GID, unit hash, symlink или чужого потребителя
останавливает опасную операцию до удаления.

Manifest и root-owned управляющие скрипты остаются для повторного cleanup
после частичной установки, удаления YAML или исходной папки:

```bash
sudo /usr/local/lib/3proxy-setup/instances/main/clean3proxy.sh \
  --instance main --yes --purge-logs
```

При `manage_ufw: true` новые правила получают comment с ID и ownership token;
manifest сохраняет их до изменения firewall. Совпадающие ранее существовавшие
правила не присваиваются экземпляру и не получают новый comment. Loopback
listeners по-прежнему не создают публичных правил.

`--purge-ufw` или `--purge-shared-components` явно разрешают удаление только
созданных этим экземпляром UFW-правил с неизменённым ownership comment,
без зависимости зарегистрированных соседей и без другого активного TCP listener.
При неопределённом владельце или потребителе правило сохраняется с объяснением;
пересекающиеся dynamic UDP ranges соседей также сохраняются. Без этих флагов
firewall не очищается. Общие пакеты и `proxy-observability` сохраняются даже с
`--purge-shared-components`: исключительное владение ими не доказано.
Глобальный systemd journal и cloud security groups никогда не очищаются.
Собственные file logs и встроенная daily rotation находятся в каталоге instance;
общая logrotate-конфигурация не создаётся.

После удаления CA и чистой переустановки клиентам потребуется новый `ca.crt`.
Default cleanup не удаляет журналы, но удаляет секреты установленного YAML;
сохранённые по явному флагу backups и исходная папка требуют отдельного хранения.
