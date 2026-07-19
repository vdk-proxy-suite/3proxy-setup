# Standalone 3proxy setup 1.1.1

Пакет устанавливает 3proxy 0.9.7 из исходников, применяет патчи UDP-over-SOCKS,
создаёт шесть listeners и запускает локальный health-check. Рассчитан на
Ubuntu/Debian с `apt-get`, `systemd` и доступом в интернет.

Версия 1.1.0 добавляет машинно-читаемый `monitor_v1` logformat, ежедневную
встроенную ротацию, gzip и группу `proxy-observability` для непривилегированного
read-only мониторинга. Старый журнал при первом переключении сохраняется как
`3proxy.log.pre-monitor-*.gz`.

## Быстрый запуск

После распаковки на VM:

```bash
cd 3proxy-setup
cp config.example.yaml config.yaml
nano config.yaml
sudo ./setup3proxy.sh all
```

Начиная с 1.1.1 ZIP хранит Unix mode metadata: setup, cleanup, step-скрипты и
Python tools получают `0755` при обычной распаковке на Linux; ручной `chmod` не нужен.

Для применения только конфига и systemd unit без повторной сборки patched
binary используйте:

```bash
sudo ./setup3proxy.sh reconfigure
```

В `config.yaml` обязательно замените:

- `server.public_ip` на публичный IPv4 новой VM
- `local_auth` на локальные credentials прокси
- адреса, порты и credentials обоих upstream
- `expected_egress_ip` для проверок upstream

Если UFW должен настраиваться автоматически, установите `manage_ufw: true`.
Облачный firewall/security group всё равно настраивается отдельно.

## Шаги

```bash
sudo ./setup3proxy.sh 0  # остановка, диагностика и backup
sudo ./setup3proxy.sh 1  # сборка и установка patched 3proxy
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

`config.yaml` содержит секреты: храните его с правами `600` и не добавляйте в
публичные репозитории или общедоступные архивы.

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

`--purge-ufw` включается только явно, поскольку совпадающие правила могли
существовать до установки. Cleaner не меняет cloud security groups и не очищает
глобальный systemd journal: выборочное удаление записей одного unit там
невозможно без затрагивания остальных сервисов.
