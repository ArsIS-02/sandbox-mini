#!/bin/bash
# Анализ образца внутри изолированного контейнера (сети нет).
# $1 — путь к образцу внутри контейнера (/sample)
set -u
SAMPLE="${1:-/sample}"
OUT=/work/report_raw
mkdir -p "$OUT"

file -b "$SAMPLE" > "$OUT/filetype"
sha256sum "$SAMPLE" | cut -d' ' -f1 > "$OUT/sha256"

# YARA: статический прогон по вендоренным правилам
if [ -f /opt/all-rules.yar ]; then
  yara -f /opt/all-rules.yar "$SAMPLE" 2>/dev/null \
    | awk '{print $1}' | sort -u > "$OUT/yara" || true
fi
touch "$OUT/yara"

# Статика: интересные строки
strings -n 6 "$SAMPLE" > "$OUT/strings_all" || true
grep -aoE 'https?://[^ "]*' "$OUT/strings_all" | sort -u | head -20 > "$OUT/urls" || true
grep -aoE '\b([0-9]{1,3}\.){3}[0-9]{1,3}\b' "$OUT/strings_all" | sort -u \
  | grep -vE '^(0\.|127\.|255\.)' | head -20 > "$OUT/ips" || true
grep -aiE 'powershell|cmd\.exe|/bin/(ba)?sh|chmod|curl|wget|nc |ncat|base64|/etc/|/tmp/' \
  "$OUT/strings_all" | sort -u | head -30 > "$OUT/interesting" || true

# ELF-импорты (если применимо)
readelf -d "$SAMPLE" 2>/dev/null | grep -oE '\[.*\]' | tr -d '[]' | head -30 > "$OUT/imports" || true

# Динамика: запускаем только исполняемые ELF x86-64 и скрипты, 10 секунд под strace
FT=$(cat "$OUT/filetype")
RAN=0
chmod +x "$SAMPLE" 2>/dev/null || true
case "$FT" in
  *ELF*executable*x86-64*|*ELF*x86-64*executable*|*ELF*"pie executable"*)
    timeout -s KILL 10 strace -f -qq -o "$OUT/trace" "$SAMPLE" >/dev/null 2>&1 && RAN=1 || RAN=1
    ;;
  *"shell script"*|*"a /bin"*)
    timeout -s KILL 10 strace -f -qq -o "$OUT/trace" /bin/sh "$SAMPLE" >/dev/null 2>&1 || true
    RAN=1
    ;;
esac
echo "$RAN" > "$OUT/ran"

if [ -f "$OUT/trace" ]; then
  grep -oE 'connect\([^\n]*inet_addr\("[0-9.]+"\)[^\n]*' "$OUT/trace" \
    | grep -oE '[0-9]{1,3}(\.[0-9]{1,3}){3}' | sort -u > "$OUT/net_attempts" || true
  grep -oE '(openat|creat|mkdir|unlink|rename)\([^\n]*' "$OUT/trace" \
    | grep -oE '"[^"]+"' | tr -d '"' | grep -vE '^/(proc|sys|dev|usr/lib|lib)' \
    | sort -u | head -40 > "$OUT/fs_ops" || true
  grep -oE 'execve\("[^"]+"' "$OUT/trace" | cut -d'"' -f2 | sort -u > "$OUT/execve" || true
fi
touch "$OUT/net_attempts" "$OUT/fs_ops" "$OUT/execve" "$OUT/urls" "$OUT/ips" "$OUT/interesting" "$OUT/imports"
