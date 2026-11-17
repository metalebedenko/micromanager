#!/bin/sh
# micromanager installer (macOS / Linux).
#
#   curl -fsSL https://raw.githubusercontent.com/metalebedenko/micromanager/main/install.sh | sh
#
# Скачивает готовый статичный бинарь под твою ОС/архитектуру из последнего
# GitHub Release и кладёт в ~/.local/bin (без sudo). Зависимостей не требует.
set -eu

REPO="metalebedenko/micromanager"
BIN="micromanager"
INSTALL_DIR="${MM_INSTALL_DIR:-$HOME/.local/bin}"

say() { printf '%s\n' "$*"; }
err() { printf 'ошибка: %s\n' "$*" >&2; exit 1; }

# --- определить платформу ---
os="$(uname -s)"
arch="$(uname -m)"
case "$os" in
  Linux)  os="linux" ;;
  Darwin) os="macos" ;;
  *)      err "неподдерживаемая ОС: $os (собери из исходников: cargo install --git https://github.com/$REPO)" ;;
esac
case "$arch" in
  x86_64|amd64)  arch="x86_64" ;;
  arm64|aarch64) arch="aarch64" ;;
  *)             err "неподдерживаемая архитектура: $arch" ;;
esac

# Под Linux собираем только x86_64; arm64-Linux — из исходников.
if [ "$os" = "linux" ] && [ "$arch" != "x86_64" ]; then
  err "для Linux $arch нет готового бинаря — собери: cargo install --git https://github.com/$REPO"
fi

asset="${BIN}-${os}-${arch}.tar.gz"
url="https://github.com/${REPO}/releases/latest/download/${asset}"

# --- инструмент загрузки ---
if command -v curl >/dev/null 2>&1; then
  dl() { curl -fsSL "$1" -o "$2"; }
elif command -v wget >/dev/null 2>&1; then
  dl() { wget -qO "$2" "$1"; }
else
  err "нужен curl или wget"
fi

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

say "↓ скачиваю $asset ..."
dl "$url" "$tmp/$asset" || err "не удалось скачать $url (релиз ещё не собран? проверь github.com/$REPO/releases)"

# --- проверка контрольной суммы до распаковки ---
dl "${url}.sha256" "$tmp/$asset.sha256" || err "не удалось получить SHA-256 для $asset"
want="$(awk -v asset="$asset" '
  NR == 1 && NF == 2 && length($1) == 64 && $1 !~ /[^0-9a-fA-F]/ && ($2 == asset || $2 == "*" asset) { hash = tolower($1) }
  END { if (NR != 1 || hash == "") exit 1; print hash }
' "$tmp/$asset.sha256")" || err "некорректный файл SHA-256 для $asset"
if command -v shasum >/dev/null 2>&1; then
  result="$(shasum -a 256 "$tmp/$asset")" || err "не удалось вычислить SHA-256"
elif command -v sha256sum >/dev/null 2>&1; then
  result="$(sha256sum "$tmp/$asset")" || err "не удалось вычислить SHA-256"
else
  err "для проверки архива нужен shasum или sha256sum"
fi
[ "${result%% *}" = "$want" ] || err "контрольная сумма архива не совпадает"
say "✓ SHA-256 проверен"

# --- распаковка и установка ---
tar -xzf "$tmp/$asset" -C "$tmp"
[ -f "$tmp/$BIN" ] || err "в архиве нет бинаря $BIN"
mkdir -p "$INSTALL_DIR"
chmod +x "$tmp/$BIN"
mv "$tmp/$BIN" "$INSTALL_DIR/$BIN"

say "✓ установлено: $INSTALL_DIR/$BIN"

# --- проверка PATH ---
case ":$PATH:" in
  *":$INSTALL_DIR:"*) ;;
  *)
    say ""
    say "⚠ $INSTALL_DIR не в PATH. Добавь в ~/.profile / ~/.zshrc:"
    say "    export PATH=\"$INSTALL_DIR:\$PATH\""
    ;;
esac

say ""
say "Готово. Запусти:  $BIN tui   (или: $BIN listen  — поделиться своим ПК)"
