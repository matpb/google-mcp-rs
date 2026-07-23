#!/usr/bin/env bash
# Assemble and pack the Google Workspace MCP bundle (.mcpb) for Claude Desktop.
#
# The bundle runs `google-mcp stdio` (single-tenant, no HTTP/SSL). It carries a
# prebuilt binary per platform in server/; Claude Desktop picks the right one
# via manifest `platform_overrides`.
#
# Prereqs (build the binaries first):
#   Linux:   cargo build --release
#   Windows: cargo xwin build --release --target x86_64-pc-windows-msvc
#   macOS:   cargo build --release            (run on a Mac; see TODO below)
#
# Usage: mcpb/pack.sh [output.mcpb]
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BUILD="$ROOT/mcpb/build"
OUT="${1:-$ROOT/mcpb/google-workspace-mcp.mcpb}"

LINUX_BIN="$ROOT/target/release/google-mcp"
WIN_BIN="$ROOT/target/x86_64-pc-windows-msvc/release/google-mcp.exe"
# macOS: build + sign on a Mac (Developer ID + notarize before distributing),
# then drop the signed binary here for packing.
MAC_BIN="$ROOT/target/aarch64-apple-darwin/release/google-mcp"

rm -rf "$BUILD"
mkdir -p "$BUILD/server"
cp "$ROOT/mcpb/manifest.json" "$BUILD/manifest.json"

[ -f "$LINUX_BIN" ] || { echo "missing linux binary: $LINUX_BIN (cargo build --release)"; exit 1; }
cp "$LINUX_BIN" "$BUILD/server/google-mcp"
chmod +x "$BUILD/server/google-mcp"

if [ -f "$WIN_BIN" ]; then
  cp "$WIN_BIN" "$BUILD/server/google-mcp.exe"
else
  echo "WARNING: windows binary not found at $WIN_BIN — bundle will omit win32"
fi

if [ -f "$MAC_BIN" ]; then
  cp "$MAC_BIN" "$BUILD/server/google-mcp-darwin"
  chmod +x "$BUILD/server/google-mcp-darwin"
else
  echo "WARNING: macOS binary not found at $MAC_BIN — bundle will omit darwin"
fi

npx -y @anthropic-ai/mcpb validate "$BUILD/manifest.json"
npx -y @anthropic-ai/mcpb pack "$BUILD" "$OUT"
echo "packed: $OUT"
