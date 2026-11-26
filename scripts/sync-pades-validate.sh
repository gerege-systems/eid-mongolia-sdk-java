#!/usr/bin/env bash
# sync-pades-validate.sh — vendors the Go reference's ValidatePDF conformance corpus (gerege-systems/eid-mongolia-sdk-go
# pades/testdata/validate, "pades-validate/1") byte-identically into src/test/resources/pades-validate, laid out like
# Go's pades/testdata so the manifest's relative paths resolve:
#   validate/{manifest.json,README.md,input/,http/,pki/*.pem}   (private keys *.key.pem excluded)
#   golden/output/<only the PDFs the manifest references>
#   golden/pki/*.pem                                            (private keys excluded)
#
#   scripts/sync-pades-validate.sh <commit>   # fetch from that Go commit and write
#   scripts/sync-pades-validate.sh --check    # the vendored copy equals pades-validate/SOURCE's commit (CI)
#
# PadesValidateGoldenTest additionally checks every file the manifest names exists.
set -euo pipefail

GO_REPO=gerege-systems/eid-mongolia-sdk-go
root=$(cd "$(dirname "$0")/.." && pwd)
dest=$root/src/test/resources/pades-validate

fetch() { # $1 = ref → $2 = dir
  local ref=$1 out=$2 tmp f
  tmp=$(mktemp -d)
  curl -fsSL "https://codeload.github.com/$GO_REPO/tar.gz/$ref" | tar -xz -C "$tmp" --strip-components=1
  local td=$tmp/pades/testdata
  mkdir -p "$out/validate/input" "$out/validate/http" "$out/validate/pki" "$out/golden/output" "$out/golden/pki"
  cp "$td/validate/manifest.json" "$td/validate/README.md" "$out/validate/"
  cp "$td"/validate/input/* "$out/validate/input/"
  cp "$td"/validate/http/* "$out/validate/http/"
  for f in "$td"/validate/pki/*.pem "$td"/golden/pki/*.pem; do
    case "$f" in *.key.pem) continue ;; esac
    case "$f" in */validate/pki/*) cp "$f" "$out/validate/pki/" ;; *) cp "$f" "$out/golden/pki/" ;; esac
  done
  for f in $(grep -o '"golden/output/[^"]*"' "$td/validate/manifest.json" | tr -d '"' | sort -u); do
    cp "$td/$f" "$out/$f"
  done
  rm -rf "$tmp"
  (cd "$out" && find . -type f ! -name SHA256SUMS ! -name SOURCE | LC_ALL=C sort | sed "s|^\./||" | while read -r p; do printf "%s  %s\n" "$(shasum -a 256 "$p" | cut -d" " -f1)" "$p"; done > SHA256SUMS)
}

if [ "${1:-}" = --check ]; then
  [ -f "$dest/SOURCE" ] || { echo "pades-validate/SOURCE missing" >&2; exit 1; }
  ref=$(head -n1 "$dest/SOURCE")
  tmp=$(mktemp -d)
  fetch "$ref" "$tmp/c"
  cp "$dest/SOURCE" "$tmp/c/SOURCE"
  if diff -r "$tmp/c" "$dest" >/dev/null; then echo "pades-validate = $GO_REPO@$ref ✓"; rm -rf "$tmp"; exit 0; fi
  diff -rq "$tmp/c" "$dest" || true
  rm -rf "$tmp"
  echo "vendored pades-validate differs from $ref — run scripts/sync-pades-validate.sh $ref" >&2
  exit 1
fi

ref=${1:?ref (Go repo commit)}
rm -rf "$dest"
fetch "$ref" "$dest"
echo "$ref" > "$dest/SOURCE"
echo "✓ $dest ← $ref"
