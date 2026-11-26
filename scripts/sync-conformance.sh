#!/usr/bin/env bash
# sync-conformance.sh — Go reference-ийн (gerege-systems/eid-mongolia-sdk-go) RP SDK conformance corpus-ийг
# (testdata/conformance, rp-conformance/N) src/test/resources/conformance руу байт-ижил vendor хийнэ.
#
#   scripts/sync-conformance.sh <ref>       # Go репогийн tag/commit-оос татаж бичнэ (жишээ: rp-conformance-v1)
#   scripts/sync-conformance.sh --check     # vendored хуулбар conformance/SOURCE-ийн ref-тэй таарч буйг шалгана (CI)
#
# Генераторын хувийн түлхүүрийг (pki/keys/) ХУУЛАХГҮЙ — corpus README «consumers do not vendor them». Файл бүрийн
# SHA-256-ийг ConformanceManifestTest manifest.json-оор тулгана.
set -euo pipefail

GO_REPO=gerege-systems/eid-mongolia-sdk-go
root=$(cd "$(dirname "$0")/.." && pwd)
dest=$root/src/test/resources/conformance

fetch() { # $1 = ref → $2 = dir (corpus copy, keys removed)
  local ref=$1 out=$2 tmp
  tmp=$(mktemp -d)
  curl -fsSL "https://codeload.github.com/$GO_REPO/tar.gz/$ref" | tar -xz -C "$tmp" --strip-components=1
  cp -R "$tmp/testdata/conformance" "$out"
  rm -rf "$tmp" "$out/pki/keys"
}

if [ "${1:-}" = --check ]; then
  [ -f "$dest/SOURCE" ] || { echo "conformance/SOURCE алга" >&2; exit 1; }
  ref=$(head -n1 "$dest/SOURCE")
  tmp=$(mktemp -d)
  fetch "$ref" "$tmp/conformance"
  cp "$dest/SOURCE" "$tmp/conformance/SOURCE"
  if diff -r "$tmp/conformance" "$dest" >/dev/null; then echo "conformance = $GO_REPO@$ref ✓"; rm -rf "$tmp"; exit 0; fi
  diff -rq "$tmp/conformance" "$dest" || true
  rm -rf "$tmp"
  echo "vendored conformance нь $ref-ээс зөрж байна — scripts/sync-conformance.sh $ref" >&2
  exit 1
fi

ref=${1:?ref (Go репогийн tag/commit)}
rm -rf "$dest"
mkdir -p "$(dirname "$dest")"
fetch "$ref" "$dest"
echo "$ref" > "$dest/SOURCE"
echo "✓ $dest ← $ref"
