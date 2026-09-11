#!/bin/zsh
set -euo pipefail

ROOT="${0:A:h}"
VERSION="${VERSION:-1.0.7}"
BUILD_NUMBER="${BUILD_NUMBER:-8}"
APP="$ROOT/dist/UniVPN Clash Bridge.app"
ZIP="$ROOT/dist/UniVPN-Clash-Bridge-$VERSION-macos-arm64.zip"
MODULE_CACHE="$ROOT/.module-cache"
SWIFTPM_CACHE="$ROOT/.swiftpm-cache"
ICONSET="$ROOT/.build/AppIcon.iconset"
ICON_SOURCE="$ROOT/Assets/Icon/AppIcon.png"

rm -rf "$APP" "$ICONSET"
rm -f "$ZIP" "$ZIP.sha256"
mkdir -p "$MODULE_CACHE" "$SWIFTPM_CACHE"
CLANG_MODULE_CACHE_PATH="$MODULE_CACHE" \
SWIFTPM_MODULECACHE_OVERRIDE="$MODULE_CACHE" \
swift build \
  --disable-sandbox \
  --cache-path "$SWIFTPM_CACHE" \
  --package-path "$ROOT" \
  -Xswiftc -gnone \
  -Xswiftc -file-prefix-map \
  -Xswiftc "$ROOT=." \
  -c release

mkdir -p "$APP/Contents/MacOS" "$APP/Contents/Resources" "$ICONSET"
cp "$ROOT/.build/release/UniVPNClashBridge" "$APP/Contents/MacOS/UniVPNClashBridge"
cp "$ROOT/.build/release/UniVPNDNSGuard" "$APP/Contents/Resources/univpn-dns-guard"
cp "$ROOT/Info.plist" "$APP/Contents/Info.plist"
chmod 755 "$APP/Contents/MacOS/UniVPNClashBridge" "$APP/Contents/Resources/univpn-dns-guard"

sips -z 16 16 "$ICON_SOURCE" --out "$ICONSET/icon_16x16.png" >/dev/null
sips -z 32 32 "$ICON_SOURCE" --out "$ICONSET/icon_16x16@2x.png" >/dev/null
sips -z 32 32 "$ICON_SOURCE" --out "$ICONSET/icon_32x32.png" >/dev/null
sips -z 64 64 "$ICON_SOURCE" --out "$ICONSET/icon_32x32@2x.png" >/dev/null
sips -z 128 128 "$ICON_SOURCE" --out "$ICONSET/icon_128x128.png" >/dev/null
sips -z 256 256 "$ICON_SOURCE" --out "$ICONSET/icon_128x128@2x.png" >/dev/null
sips -z 256 256 "$ICON_SOURCE" --out "$ICONSET/icon_256x256.png" >/dev/null
sips -z 512 512 "$ICON_SOURCE" --out "$ICONSET/icon_256x256@2x.png" >/dev/null
sips -z 512 512 "$ICON_SOURCE" --out "$ICONSET/icon_512x512.png" >/dev/null
sips -z 1024 1024 "$ICON_SOURCE" --out "$ICONSET/icon_512x512@2x.png" >/dev/null
"$ROOT/.build/release/IconPackager" "$ICONSET" "$APP/Contents/Resources/AppIcon.icns"

/usr/libexec/PlistBuddy -c "Set :CFBundleShortVersionString $VERSION" "$APP/Contents/Info.plist"
/usr/libexec/PlistBuddy -c "Set :CFBundleVersion $BUILD_NUMBER" "$APP/Contents/Info.plist"
xattr -cr "$APP"
codesign --force --sign - "$APP/Contents/Resources/univpn-dns-guard"
codesign --force --deep --sign - "$APP"

ditto -c -k --keepParent --norsrc --noextattr --noqtn --noacl "$APP" "$ZIP"
(
  cd "$ROOT/dist"
  shasum -a 256 "${ZIP:t}" > "${ZIP:t}.sha256"
)

printf '%s\n%s\n' "$APP" "$ZIP"
