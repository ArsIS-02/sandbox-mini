# Песочница-мини (sandbox-mini)

Обёртка над podman: кидаете файл (например, извлечённый TrafficLens из дампа) —
получаете короткий отчёт о поведении. Прогон в изолированном контейнере
**без сети** (`--network none`), read-only rootfs, без capabilities, лимиты
64 PID / 256 МБ. Отчёт уходит в Graylog по GELF и сохраняется JSON'ом.

## Что в отчёте

- **Статика**: тип файла, sha256, URL и IP из строк, «интересные» строки
  (shell, curl/wget, base64, системные пути), ELF-импорты;
- **Динамика** (для ELF x86-64 и shell-скриптов): 10 секунд под `strace` —
  попытки `connect()` (адреса), файловые операции вне /proc|/sys|/dev,
  дочерние `execve`.

## Вердикт

Уровень alert (письмо из Graylog), если есть: сетевые обращения, работа с
системными путями (/etc, cron, systemd), дочерние процессы или URL по
IP-литералу. Доменные URL из строк (типа ссылок на GPL в coreutils) — только
контекст, не повод для алерта.

## Установка (RED OS 8, rootless podman)

```bash
mkdir -p ~/sandbox/reports
cp Containerfile analyze.sh sandbox.py ~/sandbox/
cd ~/sandbox && podman build -t localhost/sandbox-mini:latest .
```

## Использование

```bash
python3 ~/sandbox/sandbox.py /path/to/sample
# отчёт: ~/sandbox/reports/<sha256>.json
```

Стыковка с TrafficLens: извлечённые из дампа файлы скачиваются ZIP'ом —
любой из них можно прогнать здесь вручную.

## Graylog

Поток **Sandbox** (`homelab_app=sandbox`). Правило «SANDBOX - Подозрительное
поведение файла» (высокий приоритет, письмо «Mail.ru Alert Homelab tools»).

## Грабли

- Том образца монтировать с `:ro,z` (SELinux), каталог отчёта — `:Z`.
- Исполняются только ELF x86-64 и shell-скрипты; PE и прочее — только статика.

## Тесты

```bash
python -m pytest tests/ -v
```
