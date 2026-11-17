#!/usr/bin/env bash
#
# Adds (or removes) the loopback entries the .test host set needs.
#
# It shows you the exact change and asks before touching /etc/hosts. Nothing is written
# without your confirmation, and `--undo` removes only the block this script added,
# leaving the file byte-identical to how it started.

set -euo pipefail

HOSTS_FILE="/etc/hosts"
BACKUP_FILE="/etc/hosts.csrf-lab.bak"
MARKER_BEGIN="# >>> csrf-lab >>>"
MARKER_END="# <<< csrf-lab <<<"
ENTRIES="127.0.0.1 bank.test evil.test uploads.bank.test app.test"

undo=false
if [[ "${1:-}" == "--undo" ]]; then
  undo=true
fi

echo "This script manages these lines in ${HOSTS_FILE}:"
echo
echo "  ${MARKER_BEGIN}"
echo "  ${ENTRIES}"
echo "  ${MARKER_END}"
echo

confirm() {
  local reply=""
  read -r -p "$1 [y/N] " reply || reply=""
  [[ "$reply" =~ ^[Yy]$ ]] || { echo "Aborted. No changes made."; exit 1; }
}

# Replace the hosts file with $1, keeping a copy of what was there first.
install_hosts() {
  sudo cp "$HOSTS_FILE" "$BACKUP_FILE"
  sudo cp "$1" "$HOSTS_FILE"
}

# awk and printf both end the last line with a newline, so a file that did not end with one
# would come back with an extra byte. $2 says whether the original lacked it.
restore_eof() {
  local file="$1" had_no_newline="$2"
  $had_no_newline || return 0
  head -c "$(( $(wc -c < "$file") - 1 ))" "$file" > "${file}.trimmed"
  mv "${file}.trimmed" "$file"
}

ends_without_newline=false
if [[ -s "$HOSTS_FILE" && -n "$(tail -c 1 "$HOSTS_FILE" || true)" ]]; then
  ends_without_newline=true
fi

if $undo; then
  if ! grep -qF "$MARKER_BEGIN" "$HOSTS_FILE" 2>/dev/null; then
    echo "No csrf-lab block found in ${HOSTS_FILE}. Nothing to remove."
    exit 0
  fi
  # Only ever delete a complete block. If the end marker is missing, walking to EOF would
  # take the rest of the file with it, and this file is not one to guess about.
  if ! grep -qF "$MARKER_END" "$HOSTS_FILE"; then
    echo "Found the start of a csrf-lab block but not its end marker, so this is not a"
    echo "complete block. Refusing to edit ${HOSTS_FILE}; remove those lines by hand."
    exit 1
  fi
  echo "About to REMOVE the csrf-lab block above. This needs sudo."
  confirm "Proceed?"
  # Delete the marked block. awk writes a filtered copy rather than sed editing in place,
  # because sed's in-place flag differs between BSD (macOS) and GNU (Linux) and this
  # script is meant to run on both. The one blank line the add step inserts before the
  # block goes with it; blank lines the file already had are kept.
  tmp="$(mktemp)"
  awk -v begin="$MARKER_BEGIN" -v end="$MARKER_END" '
    $0 == begin { skip = 1; if (blank > 0) blank--; next }
    $0 == end   { skip = 0; next }
    skip        { next }
    /^[[:space:]]*$/ { blank++; next }
    {
      while (blank > 0) { print ""; blank-- }
      print
    }
    END { while (blank > 0) { print ""; blank-- } }
  ' "$HOSTS_FILE" > "$tmp"
  restore_eof "$tmp" "$ends_without_newline"
  install_hosts "$tmp"
  rm -f "$tmp"
  echo "Removed. Previous file saved as ${BACKUP_FILE}."
  exit 0
fi

if grep -qF "$MARKER_BEGIN" "$HOSTS_FILE" 2>/dev/null; then
  echo "The csrf-lab block is already present in ${HOSTS_FILE}. Nothing to do."
  echo "Use '$0 --undo' to remove it."
  exit 0
fi

echo "About to APPEND the block above to ${HOSTS_FILE}. This needs sudo."
echo "It only adds loopback names; it changes nothing else and is reversible with --undo."
confirm "Proceed?"

tmp="$(mktemp)"
cat "$HOSTS_FILE" > "$tmp"
printf '\n%s\n%s\n%s\n' "$MARKER_BEGIN" "$ENTRIES" "$MARKER_END" >> "$tmp"
restore_eof "$tmp" "$ends_without_newline"
install_hosts "$tmp"
rm -f "$tmp"

echo "Done. Previous file saved as ${BACKUP_FILE}."
if command -v getent > /dev/null 2>&1; then
  if getent hosts bank.test > /dev/null 2>&1; then
    echo "Verified: bank.test resolves on loopback."
  else
    echo "Warning: bank.test does not resolve yet. Check ${HOSTS_FILE} and any local"
    echo "DNS settings before starting the lab."
  fi
else
  echo "Verify with:  ping -c1 bank.test"
fi
