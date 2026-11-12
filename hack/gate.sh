#!/bin/sh
# Compares a test run with its expected-failure list.
# Usage: hack/gate.sh <results> <groups> <expected>
#   results:  "group::test<TAB>ok|not ok|skipped" lines.
#   groups:   the groups that ran, one per line.
#   expected: "group::test" lines ("group::*" = the group crashed or timed out).
# Fails when a test outside <expected> failed, or when a listed test of a
# group that ran did not fail (passed, skipped or produced no result).
set -eu

results=$1 groups=$2 expected=$3
work=$(mktemp -d "${TMPDIR:-/tmp}/igvano-gate.XXXXXX")
trap 'rm -rf "$work"' 0
# Each test must report exactly once; a repeated name would hide a pass behind a fail.
cut -f 1 "$results" | LC_ALL=C sort | uniq -d > "$work/duplicates"
if [ -s "$work/duplicates" ]; then
    printf 'Duplicate test names in the results:\n' >&2
    sed 's/^/  /' "$work/duplicates" >&2
    exit 1
fi
awk -F '\t' '$2 == "not ok" { print $1 }' "$results" | LC_ALL=C sort -u > "$work/failed"
grep -v '^#' "$expected" | sed '/^$/d' |
    awk 'NR == FNR { ran[$0]; next } { group = $0; sub(/::.*/, "", group) } group in ran' "$groups" - |
    LC_ALL=C sort -u > "$work/expected"
LC_ALL=C comm -23 "$work/failed" "$work/expected" > "$work/unexpected"
LC_ALL=C comm -13 "$work/failed" "$work/expected" > "$work/fixed"
awk -F '\t' '{ n[$2]++ } END { printf "ok %d, not ok %d, skipped %d\n", n["ok"], n["not ok"], n["skipped"] }' "$results"
printf '\nUnexpected failures (not in %s):\n' "$expected"
sed 's/^/  /' "$work/unexpected"
printf '\nListed but no longer failing (passed, skipped or missing; update %s):\n' "$expected"
sed 's/^/  /' "$work/fixed"
[ ! -s "$work/unexpected" ] && [ ! -s "$work/fixed" ]
