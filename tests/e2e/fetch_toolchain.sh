#!/bin/sh
# Fetch the pinned E2E toolchain (Squid, haproxy, nftables, iproute2, htpasswd) WITHOUT root:
# a private apt state directory is used for the index, packages are downloaded with
# `apt-get download`, verified against toolchain.lock (SHA-256) and unpacked with dpkg-deb.
#
#   tests/e2e/fetch_toolchain.sh              # populate $EGRESS_E2E_CACHE (default .e2e-cache)
#   tests/e2e/fetch_toolchain.sh --update-lock  # deliberately re-pin to the archive's current versions
set -eu

HERE=$(cd "$(dirname "$0")" && pwd)
REPO=$(cd "$HERE/../.." && pwd)
LOCK="$HERE/toolchain.lock"
CACHE=${EGRESS_E2E_CACHE:-$REPO/.e2e-cache}
UPDATE=0
[ "${1:-}" = "--update-lock" ] && UPDATE=1

mkdir -p "$CACHE/apt/lists/partial" "$CACHE/apt/cache/archives/partial" "$CACHE/debs"
APT="-o Dir::State::Lists=$CACHE/apt/lists -o Dir::Cache=$CACHE/apt/cache -o Debug::NoLocking=1"

if [ -f "$CACHE/root/.complete" ] && [ "$UPDATE" = 0 ] && cmp -s "$LOCK" "$CACHE/root/.lock"; then
  echo "toolchain: up to date ($CACHE/root)"; exit 0
fi

echo "toolchain: refreshing package index (rootless)"
# shellcheck disable=SC2086
apt-get $APT update >/dev/null 2>&1 || apt-get $APT update

cd "$CACHE/debs"
if [ "$UPDATE" = 1 ]; then
  pkgs=$(grep -v '^#' "$LOCK" | awk '{print $1}')
  rm -f ./*.deb
  # shellcheck disable=SC2086
  apt-get $APT download $pkgs
  {
    echo "# Pinned E2E toolchain (Ubuntu 24.04 noble, amd64). Format: package version sha256"
    echo "# Regenerate deliberately; fetch_toolchain.sh refuses any file whose SHA-256 differs."
    for p in $pkgs; do
      f=$(ls "${p}"_*.deb | head -1)
      printf '%s %s %s\n' "$p" "$(dpkg-deb -f "$f" Version)" "$(sha256sum "$f" | cut -d' ' -f1)"
    done
  } > "$LOCK"
  echo "toolchain: lock updated; review and commit tests/e2e/toolchain.lock"
fi

grep -v '^#' "$LOCK" | while read -r pkg ver sum; do
  f=$(ls "${pkg}"_*.deb 2>/dev/null | head -1 || true)
  if [ -z "$f" ] || [ "$(sha256sum "$f" | cut -d' ' -f1)" != "$sum" ]; then
    rm -f "${pkg}"_*.deb
    # shellcheck disable=SC2086
    if ! apt-get $APT download "$pkg=$ver" >/dev/null 2>&1; then
      echo "toolchain: $pkg=$ver is no longer in the archive index; run $0 --update-lock" >&2
      exit 1
    fi
    f=$(ls "${pkg}"_*.deb | head -1)
  fi
  got=$(sha256sum "$f" | cut -d' ' -f1)
  if [ "$got" != "$sum" ]; then
    echo "toolchain: SHA-256 mismatch for $f (expected $sum, got $got)" >&2
    exit 1
  fi
done

rm -rf "$CACHE/root" && mkdir -p "$CACHE/root"
for f in ./*.deb; do dpkg-deb -x "$f" "$CACHE/root"; done
# iproute2 ships /bin/ip and /sbin/*; expose them under /usr for the overlay mount.
mkdir -p "$CACHE/root/usr/bin" "$CACHE/root/usr/sbin"
[ -d "$CACHE/root/bin" ] && cp -a "$CACHE/root/bin/." "$CACHE/root/usr/bin/"
[ -d "$CACHE/root/sbin" ] && cp -a "$CACHE/root/sbin/." "$CACHE/root/usr/sbin/"
cp "$LOCK" "$CACHE/root/.lock"
touch "$CACHE/root/.complete"
echo "toolchain: ready ($CACHE/root)"
