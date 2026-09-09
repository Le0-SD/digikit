#!/usr/bin/env bash
# Build the one-line SR-read fix from official Unicorn 2.1.4; no source is vendored.
set -euo pipefail

root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
patch=$root/patches/unicorn-2.1.4-m68k-sr-read.patch
commit=8028ec436f2d9376525352dd38ed9ed6b9f6be10
patch_sha=01cdaea7357162b44cc00046b811b03594788d969cc48972d463c86c3af84095
python=${PYTHON:-$root/.venv/bin/python}
dry_run=false
if [[ ${1:-} == --dry-run ]]; then
  dry_run=true
  shift
fi
[[ $# == 0 ]] || {
  echo "usage: $0 [--dry-run]" >&2
  exit 2
}
[[ -x $python ]] || {
  echo "error: project Python not found: $python (set PYTHON=...)" >&2
  exit 2
}
[[ $("$python" -c 'import unicorn; print(unicorn.__version__)') == 2.1.4 ]] || {
  echo "error: interpreter must have unicorn==2.1.4; run uv sync first" >&2
  exit 2
}
[[ $(shasum -a 256 "$patch" | awk '{print $1}') == "$patch_sha" ]] || {
  echo "error: unexpected patch SHA-256: $patch" >&2
  exit 2
}
command -v git >/dev/null || {
  echo "error: git is required" >&2
  exit 2
}
command -v cmake >/dev/null || {
  echo "error: cmake is required" >&2
  exit 2
}

# These are the exact dynamic-library names selected by Unicorn's bindings.
# Do not glob: official wheels also contain libunicorn.a.
target=$(
  "$python" - <<'PY'
import os
import sys
import unicorn

name = {"darwin": "libunicorn.2.dylib", "linux": "libunicorn.so.2"}.get(sys.platform)
if name is None:
    raise SystemExit("unsupported Unicorn platform: " + sys.platform)
path = os.path.join(os.path.dirname(unicorn.__file__), "lib", name)
if not os.path.isfile(path):
    raise SystemExit("unsupported Unicorn native-library layout: expected " + path)
print(path)
PY
)
case $(uname -s) in
Darwin) built_name=libunicorn.2.dylib ;;
Linux) built_name=libunicorn.so.2 ;;
*)
  echo "error: unsupported platform $(uname -s)" >&2
  exit 2
  ;;
esac
if $dry_run; then
  printf 'dry-run: target=%s\n' "$target"
  printf 'dry-run: expected-build-payload=build/%s\n' "$built_name"
  exit 0
fi

work=$(mktemp -d "${TMPDIR:-/tmp}/digitakt2-unicorn.XXXXXX")
trap 'rm -rf "$work"' EXIT

git clone --quiet --branch 2.1.4 --depth 1 https://github.com/unicorn-engine/unicorn.git "$work/src"
[[ $(git -C "$work/src" rev-parse HEAD) == "$commit" ]] || {
  echo "error: tag 2.1.4 did not resolve to expected commit" >&2
  exit 2
}
git -C "$work/src" apply --check "$patch"
git -C "$work/src" apply "$patch"
cmake -S "$work/src" -B "$work/build" -DCMAKE_BUILD_TYPE=Release -DUNICORN_ARCH=m68k -DUNICORN_BUILD_TESTS=OFF
cmake --build "$work/build" --config Release --target unicorn
built=$work/build/$built_name
[[ -f $built && ! -L $built ]] || {
  echo "error: expected real m68k dynamic-library payload not produced: $built" >&2
  exit 2
}
# Replacement is atomic in the library directory, so an interrupted install never leaves a partial dylib.
tmp_target=$(mktemp "$(dirname "$target")/.${built_name}.XXXXXX")
cp "$built" "$tmp_target"
mv -f "$tmp_target" "$target"
printf 'unicorn commit=%s\npatch_sha256=%s\nlibrary=%s\nlibrary_sha256=%s\n' "$commit" "$patch_sha" "$target" "$(shasum -a 256 "$target" | awk '{print $1}')"
"$python" -m emu.unicorn_compat
