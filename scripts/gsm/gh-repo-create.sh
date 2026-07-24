#!/usr/bin/env bash
# gh-repo-create.sh — создать GitHub репозиторий и пушнуть одной командой
# Использование: bash gh-repo-create.sh <repo-name> [public|private]
# Пример:       bash gh-repo-create.sh my-new-tool public

set -euo pipefail

NAME="${1:?Укажи имя репозитория}"
VISIBILITY="${2:-public}"

echo "🚀 Создаю репозиторий $NAME ($VISIBILITY)..."

# Создать репозиторий через gh CLI
gh repo create "$NAME" \
  --"$VISIBILITY" \
  --source=. \
  --remote=origin \
  --push 2>&1 || {

  # Если remote уже есть — просто пушим
  echo "⚠️  Remote уже существует, делаю push..."
  git remote set-url origin "git@github.com:Banda198565/$NAME.git"
  git push -u origin main
}

echo ""
echo "✅ Готово: https://github.com/Banda198565/$NAME"
