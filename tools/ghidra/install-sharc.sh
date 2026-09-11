#!/bin/sh
# Compile the SHARC SLEIGH spec and install it into the Ghidra tree.
#
# Ghidra can only disassemble architectures it has a processor module for, and
# stock Ghidra 12.1.3 ships none for SHARC, Blackfin or ADSP -- verified by
# listing Ghidra/Processors. This adds one. Re-run after editing the .slaspec;
# a Homebrew upgrade of Ghidra wipes the install, so re-run after that too.
set -e
GHIDRA="${GHIDRA_INSTALL_DIR:-/opt/homebrew/Cellar/ghidra/12.1.3/libexec}"
HERE=$(cd "$(dirname "$0")" && pwd)
"$GHIDRA/support/sleigh" -a "$HERE/SHARC/data/languages"
rm -rf "$GHIDRA/Ghidra/Processors/SHARC"
cp -R "$HERE/SHARC" "$GHIDRA/Ghidra/Processors/SHARC"
echo "installed SHARC processor module into $GHIDRA/Ghidra/Processors/SHARC"
