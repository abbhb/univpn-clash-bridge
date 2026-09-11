#!/bin/zsh
set -euo pipefail

ROOT="${0:A:h:h}"
VERSION="${VERSION:-1.0.7}"
ARCHIVE="${1:-$ROOT/dist/UniVPN-Clash-Bridge-$VERSION-macos-arm64.zip}"
CHECKSUM="$ARCHIVE.sha256"
EXTRA_PATTERN_FILE="${PRIVACY_AUDIT_EXTRA_PATTERN_FILE:-}"
PATTERN='(/Users/[^/[:space:]]+|/var/folders/[^/[:space:]]+|/private/(tmp|var)/[^[:space:]]+|gh[opsu]_[A-Za-z0-9_]+|subscribe\?token=|Authorization:[[:space:]]*Bearer[[:space:]]+[A-Za-z0-9._-]{12,}|-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----|(^|[^0-9])(10\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}|192\.168\.[0-9]{1,3}\.[0-9]{1,3}|172\.(1[6-9]|2[0-9]|3[01])\.[0-9]{1,3}\.[0-9]{1,3})([^0-9]|$))'

[[ -f "$ARCHIVE" ]] || { print -u2 "release archive not found"; exit 1; }

if [[ -f "$CHECKSUM" ]]; then
  if rg -q '^/' "$CHECKSUM"; then
    print -u2 "release audit failed: checksum contains an absolute path"
    exit 1
  fi
  (
    cd "${ARCHIVE:h}"
    shasum -a 256 -c "${CHECKSUM:t}"
  ) >/dev/null
fi

if zipinfo -1 "$ARCHIVE" | rg -q '(^|/)(__MACOSX|\.DS_Store)(/|$)'; then
  print -u2 "release audit failed: archive contains macOS metadata"
  exit 1
fi

TEMPORARY_DIRECTORY="$(mktemp -d "${TMPDIR:-/tmp}/univpn-clash-bridge-audit.XXXXXX")"
trap 'rm -rf "$TEMPORARY_DIRECTORY"' EXIT
ditto -x -k "$ARCHIVE" "$TEMPORARY_DIRECTORY"

APP="$TEMPORARY_DIRECTORY/UniVPN Clash Bridge.app"
[[ -d "$APP" ]] || { print -u2 "release audit failed: app bundle missing"; exit 1; }

if (cd "$TEMPORARY_DIRECTORY" && find . -print) | rg -q "$PATTERN"; then
  print -u2 "release audit failed: sensitive data in an archive path"
  exit 1
fi
if rg -a -q "$PATTERN" "$TEMPORARY_DIRECTORY"; then
  print -u2 "release audit failed: sensitive data in archive contents"
  exit 1
fi

if [[ -n "$EXTRA_PATTERN_FILE" ]]; then
  [[ -f "$EXTRA_PATTERN_FILE" ]] || {
    print -u2 "release audit pattern file not found"
    exit 1
  }
  while IFS= read -r private_pattern || [[ -n "$private_pattern" ]]; do
    [[ -z "$private_pattern" || "$private_pattern" == \#* ]] && continue
    if (cd "$TEMPORARY_DIRECTORY" && find . -print) | \
      rg -q --fixed-strings -- "$private_pattern"; then
      print -u2 "release audit failed for an external private path pattern"
      exit 1
    fi
    if rg -a -q --fixed-strings -- "$private_pattern" "$TEMPORARY_DIRECTORY"; then
      print -u2 "release audit failed for an external private content pattern"
      exit 1
    fi
  done < "$EXTRA_PATTERN_FILE"
fi

codesign --verify --deep --strict "$APP"
[[ "$(/usr/libexec/PlistBuddy -c 'Print :CFBundleIdentifier' "$APP/Contents/Info.plist")" == \
  "io.github.abbhb.univpn-clash-bridge" ]] || {
  print -u2 "release audit failed: unexpected bundle identifier"
  exit 1
}

ICONSET="$TEMPORARY_DIRECTORY/AppIcon.iconset"
iconutil -c iconset "$APP/Contents/Resources/AppIcon.icns" -o "$ICONSET"
[[ -f "$ICONSET/icon_16x16.png" && -f "$ICONSET/icon_512x512@2x.png" ]] || {
  print -u2 "release audit failed: icon sizes missing"
  exit 1
}

print "release audit passed"
