#!/bin/zsh
set -euo pipefail

ROOT="${0:A:h:h}"
cd "$ROOT"

PATTERN='(/Users/[^/[:space:]]+|/var/folders/[^/[:space:]]+|/private/(tmp|var)/[^[:space:]]+|gh[opsu]_[A-Za-z0-9_]+|subscribe\?token=|Authorization:[[:space:]]*Bearer[[:space:]]+[A-Za-z0-9._-]{12,}|-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----|(^|[^0-9])(10\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}|192\.168\.[0-9]{1,3}\.[0-9]{1,3}|172\.(1[6-9]|2[0-9]|3[01])\.[0-9]{1,3}\.[0-9]{1,3})([^0-9]|$))'

TARGETS=(
  .gitignore
  Package.swift
  package_app.sh
  Info.plist
  README.md
  PRIVACY.md
  LICENSE
  Assets/Icon/AppIcon.png
  Sources
  scripts
)

if rg -q --hidden --glob '!privacy-audit.sh' --glob '!release-audit.sh' "$PATTERN" "${TARGETS[@]}"; then
  print -u2 "privacy audit failed for a built-in sensitive-data pattern"
  exit 1
fi

EXTRA_PATTERN_FILE="${PRIVACY_AUDIT_EXTRA_PATTERN_FILE:-}"
if [[ -n "$EXTRA_PATTERN_FILE" ]]; then
  if [[ ! -f "$EXTRA_PATTERN_FILE" ]]; then
    print -u2 "privacy audit pattern file not found: $EXTRA_PATTERN_FILE"
    exit 1
  fi

  while IFS= read -r private_pattern || [[ -n "$private_pattern" ]]; do
    [[ -z "$private_pattern" || "$private_pattern" == \#* ]] && continue
    if rg -q --hidden --fixed-strings -- "$private_pattern" "${TARGETS[@]}"; then
      print -u2 "privacy audit failed for an external private pattern"
      exit 1
    fi
  done < "$EXTRA_PATTERN_FILE"
fi

print "privacy audit passed"
