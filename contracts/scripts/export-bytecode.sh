#!/usr/bin/env bash
# Compile src/ and export copy-paste-ready bytecode for every deployable contract.
#
# Output (default: dist/), per contract <Name>:
#   <Name>.bin          creation bytecode (initcode), 0x-prefixed hex, no trailing newline
#   <Name>.bin-runtime  runtime bytecode (deployed code), 0x-prefixed hex, no trailing newline
#   <Name>.abi.json     ABI
# plus:
#   bytecode.json       all of the above + compiler settings in one file
#   SHA256SUMS          checksums of every file above
set -euo pipefail

cd "$(dirname "$0")/.."
dist="${1:-dist}"

# Build into a fresh output and cache directory, so artifacts of deleted or moved sources in a
# reused out/ can never be exported (issue #4).
build=$(mktemp -d)
trap 'rm -rf "$build"' EXIT
forge build --skip test --skip script --force --out "$build/out" --cache-path "$build/cache" >&2

rm -rf "$dist"
mkdir -p "$dist"

combined='{}'
settings=''
count=0

while IFS= read -r -d '' artifact; do
  # Only contracts whose compilation target lives in src/ (skips forge-std etc.).
  source=$(jq -r '.metadata.settings.compilationTarget | keys[0]' "$artifact")
  [[ "$source" == src/* ]] || continue

  name=$(jq -r '.metadata.settings.compilationTarget[]' "$artifact")
  bytecode=$(jq -r '.bytecode.object' "$artifact")
  runtime=$(jq -r '.deployedBytecode.object' "$artifact")

  # Interfaces and abstract contracts have no bytecode. Libraries with only internal functions
  # are inlined into their callers and have an empty ABI; nothing would deploy or call them.
  [[ "$bytecode" != "0x" ]] || continue
  [[ $(jq '.abi | length' "$artifact") -ne 0 ]] || continue

  if [[ "$bytecode" == *__\$* || "$runtime" == *__\$* ]]; then
    echo "error: $name has unlinked library references; cannot export" >&2
    exit 1
  fi

  # Immutables are zero-filled in the compiler's runtime bytecode and only set by the
  # constructor, so the published .bin-runtime would be silently wrong.
  if [[ $(jq '.deployedBytecode.immutableReferences // {} | length' "$artifact") -ne 0 ]]; then
    echo "error: $name uses immutables; its runtime bytecode is incomplete" >&2
    exit 1
  fi

  # Two contracts with the same name in different files would overwrite each other's output.
  if [[ -e "$dist/$name.bin" ]]; then
    echo "error: two contracts named $name in src/; cannot export both" >&2
    exit 1
  fi

  printf '%s' "$bytecode" >"$dist/$name.bin"
  printf '%s' "$runtime" >"$dist/$name.bin-runtime"
  jq '.abi' "$artifact" >"$dist/$name.abi.json"

  combined=$(jq -n \
    --argjson acc "$combined" \
    --arg name "$name" \
    --arg source "$source" \
    --slurpfile artifact "$artifact" \
    '$acc + {($name): {
        source: $source,
        bytecode: $artifact[0].bytecode.object,
        deployedBytecode: $artifact[0].deployedBytecode.object,
        abi: $artifact[0].abi
      }}')

  if [[ -z "$settings" ]]; then
    settings=$(jq '{
        solc: .metadata.compiler.version,
        evmVersion: .metadata.settings.evmVersion,
        optimizer: .metadata.settings.optimizer,
        viaIR: (.metadata.settings.viaIR // false)
      }' "$artifact")
  fi

  count=$((count + 1))
  echo "exported $name ($source)" >&2
done < <(find "$build/out" -name '*.json' -not -path "$build/out/build-info/*" -print0 | sort -z)

if [[ "$count" -eq 0 ]]; then
  echo "error: no deployable contracts found in src/" >&2
  exit 1
fi

jq -n --argjson compiler "$settings" --argjson contracts "$combined" \
  '{compiler: $compiler, contracts: $contracts}' >"$dist/bytecode.json"

(cd "$dist" && sha256sum -- * >SHA256SUMS)

echo "wrote $count contract(s) to $dist/" >&2
