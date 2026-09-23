#!/usr/bin/env bash
# Local release script: cross-builds Linux/Windows here, macOS over SSH.
# macOS config: env vars, optionally from scripts/release.local.env (see --help).
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

die() { echo "error: $*" >&2; exit 1; }

LOCAL_ENV="$ROOT/scripts/release.local.env"
if [[ -f "$LOCAL_ENV" ]]; then
  # shellcheck disable=SC1090
  source "$LOCAL_ENV"
fi

MAC_REPO_DIR="${MAC_REPO_DIR:-google-mcp-rs}"

CHECK_ONLY=0
DRY_RUN=0
SKIP_MAC=0

usage() {
  cat <<'EOF'
Usage: scripts/release.sh [--check] [--dry-run] [--skip-mac] [--help]

  --check     Run preflight checks only, then exit.
  --dry-run   Build, sign, notarize and checksum everything, but skip
              tagging, pushing and publishing the GitHub release.
  --skip-mac  Skip the macOS build (emergency use only); the release
              then ships three binaries instead of four.
  --help      Show this help and exit.

The macOS build/sign/notarize step needs a macOS host reachable over SSH.
Configure it with environment variables, or put them in
scripts/release.local.env (gitignored; copy from release.local.env.example):

  MAC_HOST             SSH host of the macOS build machine
  MAC_SIGN_IDENTITY     codesign identity string
  MAC_NOTARY_PROFILE    xcrun notarytool --keychain-profile name
  SECRETS_ENV           env file that exports KEYCHAIN_PASSWORD
  MAC_REPO_DIR          remote checkout path, relative to the remote home
                       (default: google-mcp-rs)

All are required unless --skip-mac is passed.
EOF
}

for arg in "$@"; do
  case "$arg" in
    --help) usage; exit 0 ;;
    --check) CHECK_ONLY=1 ;;
    --dry-run) DRY_RUN=1 ;;
    --skip-mac) SKIP_MAC=1 ;;
    *) die "unknown argument: $arg (see --help)" ;;
  esac
done

export PATH="$HOME/.local/bin:$HOME/.cargo/bin:$PATH"

# ---------------------------------------------------------------------------
# A. Preflight
# ---------------------------------------------------------------------------
echo "==> Preflight"

VERSION="$(grep -m1 '^version = ' Cargo.toml | cut -d'"' -f2)"
TAG="v$VERSION"

grep -q "^## \[$VERSION\]" CHANGELOG.md \
  || die "CHANGELOG.md has no '## [$VERSION]' section"

if git rev-parse -q --verify "refs/tags/$TAG" >/dev/null; then
  die "local tag $TAG already exists"
fi
if [[ -n "$(git ls-remote --tags origin "refs/tags/$TAG" 2>/dev/null)" ]]; then
  die "remote tag $TAG already exists"
fi

if [[ "$CHECK_ONLY" -eq 1 ]]; then
  [[ -z "$(git status --porcelain)" ]] || echo "warning: working tree is not clean"
  branch="$(git rev-parse --abbrev-ref HEAD)"
  [[ "$branch" == "main" ]] || echo "warning: current branch is '$branch', not main"
else
  [[ -z "$(git status --porcelain)" ]] || die "working tree is not clean"
  branch="$(git rev-parse --abbrev-ref HEAD)"
  [[ "$branch" == "main" ]] || die "current branch is '$branch', not main"
fi

for tool in cargo rustup cargo-zigbuild zig cargo-xwin qemu-aarch64-static rsync gh sha256sum; do
  command -v "$tool" >/dev/null 2>&1 || die "required tool not on PATH: $tool"
done
HAVE_WINE=1
command -v wine64 >/dev/null 2>&1 || { HAVE_WINE=0; echo "warning: wine64 not found, Windows smoke test will be skipped"; }

installed_targets="$(rustup target list --installed)"
for t in x86_64-unknown-linux-musl aarch64-unknown-linux-musl x86_64-pc-windows-msvc; do
  grep -qx "$t" <<<"$installed_targets" || die "rust target not installed: $t"
done

gh auth status >/dev/null 2>&1 || die "gh is not authenticated"

if [[ "$SKIP_MAC" -eq 0 ]]; then
  missing=()
  [[ -n "${MAC_HOST:-}" ]] || missing+=(MAC_HOST)
  [[ -n "${MAC_SIGN_IDENTITY:-}" ]] || missing+=(MAC_SIGN_IDENTITY)
  [[ -n "${MAC_NOTARY_PROFILE:-}" ]] || missing+=(MAC_NOTARY_PROFILE)
  [[ -n "${SECRETS_ENV:-}" ]] || missing+=(SECRETS_ENV)
  [[ ${#missing[@]} -eq 0 ]] || die "missing required variable(s) for the macOS step: ${missing[*]} (set them or use --skip-mac; see --help)"

  ssh -o BatchMode=yes -o ConnectTimeout=10 "$MAC_HOST" true \
    || die "cannot SSH to $MAC_HOST"
  # shellcheck disable=SC1090
  source "$SECRETS_ENV"
  [[ -n "${KEYCHAIN_PASSWORD:-}" ]] || die "KEYCHAIN_PASSWORD is empty after sourcing $SECRETS_ENV"
fi

assets="linux-x86_64 linux-aarch64 windows-x86_64"
[[ "$SKIP_MAC" -eq 1 ]] || assets="$assets macos-universal"
echo "==> version=$VERSION tag=$TAG assets=[$assets]"

if [[ "$CHECK_ONLY" -eq 1 ]]; then
  exit 0
fi

# ---------------------------------------------------------------------------
# B. Quality gate
# ---------------------------------------------------------------------------
echo "==> Quality gate"
cargo fmt --all -- --check
cargo clippy --all-targets -- -D warnings
cargo test

# ---------------------------------------------------------------------------
# C. Linux + Windows builds
# ---------------------------------------------------------------------------
echo "==> Linux + Windows builds"
rm -rf dist
mkdir -p dist

cargo zigbuild --release --bin google-mcp --target x86_64-unknown-linux-musl
cargo zigbuild --release --bin google-mcp --target aarch64-unknown-linux-musl
cargo xwin build --release --bin google-mcp --target x86_64-pc-windows-msvc

cp target/x86_64-unknown-linux-musl/release/google-mcp dist/google-mcp-linux-x86_64
cp target/aarch64-unknown-linux-musl/release/google-mcp dist/google-mcp-linux-aarch64
cp target/x86_64-pc-windows-msvc/release/google-mcp.exe dist/google-mcp-windows-x86_64.exe
chmod +x dist/google-mcp-linux-x86_64 dist/google-mcp-linux-aarch64

expected="google-mcp $VERSION"

out="$(dist/google-mcp-linux-x86_64 --version)"
[[ "$out" == "$expected" ]] || die "linux-x86_64 --version gave '$out', expected '$expected'"

out="$(qemu-aarch64-static dist/google-mcp-linux-aarch64 --version)"
[[ "$out" == "$expected" ]] || die "linux-aarch64 --version gave '$out', expected '$expected'"

if [[ "$HAVE_WINE" -eq 1 ]]; then
  if out="$(WINEDEBUG=-all wine64 dist/google-mcp-windows-x86_64.exe --version 2>/dev/null | tr -d '\r')"; then
    [[ "$out" == "$expected" ]] || die "windows --version gave '$out', expected '$expected'"
  else
    echo "warning: wine64 failed to run, skipping Windows smoke test"
  fi
fi

# ---------------------------------------------------------------------------
# D. macOS build, sign, notarize
# ---------------------------------------------------------------------------
if [[ "$SKIP_MAC" -eq 0 ]]; then
  echo "==> macOS build ($MAC_HOST)"
  ssh "$MAC_HOST" 'nohup caffeinate -dimsu -t 3600 >/dev/null 2>&1 & disown' || true
  trap 'ssh "$MAC_HOST" "pkill -f \"caffeinate -dimsu -t 3600\"" >/dev/null 2>&1 || true' EXIT

  rsync -az --delete --exclude target/ --exclude dist/ --exclude .git/ \
    --exclude .env --exclude '*.db*' "$ROOT/" "$MAC_HOST:$MAC_REPO_DIR/"

  notarize_out="$(mktemp)"
  { printf 'export KEYCHAIN_PASSWORD=%q\n' "$KEYCHAIN_PASSWORD"
    printf 'export MAC_SIGN_IDENTITY=%q\n' "$MAC_SIGN_IDENTITY"
    printf 'export MAC_NOTARY_PROFILE=%q\n' "$MAC_NOTARY_PROFILE"
    printf 'export MAC_REPO_DIR=%q\n' "$MAC_REPO_DIR"
    cat <<'REMOTE'
set -euo pipefail
export PATH="/usr/bin:/usr/sbin:/opt/homebrew/bin:$HOME/.cargo/bin:$PATH"
cd "$MAC_REPO_DIR"
security unlock-keychain -p "$KEYCHAIN_PASSWORD" ~/Library/Keychains/login.keychain-db
cargo build --release --bin google-mcp --target aarch64-apple-darwin
cargo build --release --bin google-mcp --target x86_64-apple-darwin
mkdir -p dist
lipo -create -output dist/google-mcp-macos-universal target/aarch64-apple-darwin/release/google-mcp target/x86_64-apple-darwin/release/google-mcp
lipo -info dist/google-mcp-macos-universal
codesign --force --options runtime --timestamp --sign "$MAC_SIGN_IDENTITY" dist/google-mcp-macos-universal
codesign --verify --verbose=2 dist/google-mcp-macos-universal
rm -f dist/notarize.zip
ditto -c -k --keepParent dist/google-mcp-macos-universal dist/notarize.zip
# Bare Mach-O binaries cannot be stapled; Gatekeeper checks the ticket online.
xcrun notarytool submit dist/notarize.zip --keychain-profile "$MAC_NOTARY_PROFILE" --wait
spctl -a -vvv -t install dist/google-mcp-macos-universal 2>&1 | grep -q 'source=Notarized Developer ID' || { echo "not notarized"; exit 1; }
REMOTE
  } | ssh "$MAC_HOST" bash -s | tee "$notarize_out"

  grep -q 'status: Accepted' "$notarize_out" || die "notarytool did not report status: Accepted"
  rm -f "$notarize_out"

  rsync "$MAC_HOST:$MAC_REPO_DIR/dist/google-mcp-macos-universal" dist/
  chmod +x dist/google-mcp-macos-universal

  # shellcheck disable=SC2029
  out="$(ssh "$MAC_HOST" "$MAC_REPO_DIR/dist/google-mcp-macos-universal --version")"
  [[ "$out" == "$expected" ]] || die "macos --version gave '$out', expected '$expected'"
else
  echo "==> Skipping macOS build (--skip-mac)"
fi

# ---------------------------------------------------------------------------
# E. Checksums and notes
# ---------------------------------------------------------------------------
echo "==> Checksums"
(cd dist && sha256sum google-mcp-* > SHA256SUMS.txt && cat SHA256SUMS.txt)

awk -v v="$VERSION" '$0 ~ "^## \\[" v "\\]" {f=1; next} f && /^## \[/ {exit} f {print}' CHANGELOG.md > dist/notes.md
[[ -s dist/notes.md ]] || die "dist/notes.md is empty; check CHANGELOG.md formatting"

# ---------------------------------------------------------------------------
# F. Publish
# ---------------------------------------------------------------------------
if [[ "$DRY_RUN" -eq 1 ]]; then
  echo "==> Dry run: would tag $TAG, push origin main $TAG, and publish a GitHub release with:"
  ls dist/google-mcp-* dist/SHA256SUMS.txt
  exit 0
fi

echo "==> Publish"
git tag -a "$TAG" -m "$TAG"
git push origin main "$TAG"
gh release create "$TAG" --title "$TAG" --notes-file dist/notes.md --verify-tag dist/google-mcp-* dist/SHA256SUMS.txt
gh release view "$TAG" --json assets --jq '.assets[].name'

echo "released $TAG"
