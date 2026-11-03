#!/bin/sh
# intraweb installer -- your neighborhood web
#
# Fetches the release binary for this machine. If there is no release for it
# yet, falls back to building from source, after checking that the machine can
# actually build -- a missing C linker is the usual reason it cannot, and
# "linker `cc` not found" three screens into a cargo build is a poor way to
# discover that.
#
# Needs the internet exactly once. intraweb itself never does.
set -eu

REPO="bnvac/intraweb"
BIN="intraweb"
PREFIX="${PREFIX:-$HOME/.local/bin}"

say() { printf '%s\n' "$*"; }
die() { printf 'error: %s\n' "$*" >&2; exit 1; }
have() { command -v "$1" >/dev/null 2>&1; }

# ---------------------------------------------------------------- platform ---

os=$(uname -s)
arch=$(uname -m)

case "$os" in
  Linux)  os_tag="unknown-linux-musl" ;;
  Darwin) os_tag="apple-darwin" ;;
  *) die "unsupported operating system: $os" ;;
esac

case "$arch" in
  x86_64|amd64) arch_tag="x86_64" ;;
  aarch64|arm64) arch_tag="aarch64" ;;
  armv6l|armv7l) die "32-bit ARM is not a supported target; see the README" ;;
  *) die "unsupported architecture: $arch" ;;
esac

target="${arch_tag}-${os_tag}"

# ------------------------------------------------------------ build deps ----

# The command that installs a C toolchain here. Rust shells out to `cc` to link
# every binary, and the bundled SQLite needs a C compiler of its own.
toolchain_hint() {
  if have apt-get;   then say "sudo apt-get update && sudo apt-get install -y build-essential"
  elif have dnf;     then say "sudo dnf install -y gcc"
  elif have yum;     then say "sudo yum install -y gcc"
  elif have pacman;  then say "sudo pacman -S --needed base-devel"
  elif have apk;     then say "sudo apk add build-base"
  elif have zypper;  then say "sudo zypper install -y gcc"
  elif [ "$os" = "Darwin" ]; then say "xcode-select --install"
  else say "install a C compiler (gcc or clang) using your package manager"
  fi
}

check_build_tools() {
  missing=""
  have cargo || missing="rust"
  have cc || have gcc || have clang || missing="${missing:+$missing }cc"

  [ -z "$missing" ] && return 0

  say ""
  say "This machine cannot build intraweb yet."
  case "$missing" in
    *rust*)
      say ""
      say "  Rust is not installed. Get it with:"
      say "    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh"
      ;;
  esac
  case "$missing" in
    *cc*)
      say ""
      say "  No C compiler found. Rust uses one to link every binary, and the"
      say "  bundled database needs one too. Install it with:"
      say "    $(toolchain_hint)"
      ;;
  esac
  say ""
  die "install the above, then run this script again"
}

build_from_source() {
  check_build_tools

  say "Building from source (about a minute)..."
  cargo build --release --bin "$BIN" || die "the build failed; the output above says why"

  mkdir -p "$PREFIX"
  cp "target/release/$BIN" "$PREFIX/$BIN"
  chmod +x "$PREFIX/$BIN"
}

# ------------------------------------------------------------- install ------

install_release() {
  url="https://github.com/${REPO}/releases/latest/download/${BIN}-${target}"
  # No curl is a reason to fall back to building, not a reason to give up.
  have curl || return 1

  say "Looking for a ${target} release..."
  tmp=$(mktemp)
  # shellcheck disable=SC2064
  trap "rm -f '$tmp'" EXIT

  if ! curl -fsSL "$url" -o "$tmp" 2>/dev/null; then
    rm -f "$tmp"
    trap - EXIT
    return 1
  fi

  mkdir -p "$PREFIX"
  chmod +x "$tmp"
  mv "$tmp" "$PREFIX/$BIN"
  trap - EXIT
  return 0
}

if install_release; then
  say "Installed a prebuilt binary."
elif [ -f "Cargo.toml" ] && [ -d "crates/$BIN-cli" ]; then
  say "No published build for ${target} yet, and you are in the source tree."
  build_from_source
else
  say ""
  say "There is no published build for ${target} yet."
  say ""
  say "Build it from source instead:"
  say "  git clone https://github.com/${REPO}.git"
  say "  cd $(basename "$REPO")"
  say "  sh install.sh"
  say ""
  say "That needs Rust and a C compiler; the script will tell you if either is"
  say "missing before it starts building."
  exit 1
fi

say "Installed to $PREFIX/$BIN"

case ":$PATH:" in
  *":$PREFIX:"*) ;;
  *)
    say ""
    say "$PREFIX is not on your PATH. Add it with:"
    say "  export PATH=\"$PREFIX:\$PATH\""
    ;;
esac

say ""
say "Get started:  $BIN up"
say "Host a hub:   $BIN up --hub"
say "Look around:  $BIN surf"
