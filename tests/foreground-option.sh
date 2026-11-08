#!/bin/sh
# The foreground switch must be a real getopt option, must not consume the
# device argument like -f does, and must be documented. This does not mount
# anything: a missing device fails before any FUSE call.
set -eu

BIN=${1:?usage: foreground-option.sh <apfs-fuse>}

out=$("$BIN" -F /nonexistent-apfs-reader-device /nonexistent-apfs-mount 2>&1) && rc=0 || rc=$?
if [ "$rc" -eq 0 ]; then
	echo "FAIL: -F with a missing device unexpectedly succeeded" >&2
	exit 1
fi
case $out in
	*"invalid option"*)
		echo "FAIL: -F was not accepted by getopt" >&2
		exit 1
		;;
	*"Error opening device"*)
		;;
	*)
		echo "FAIL: -F did not reach device open; output was: $out" >&2
		exit 1
		;;
esac

usage=$("$BIN" -F 2>&1) && rc=0 || rc=$?
if [ "$rc" -eq 0 ]; then
	echo "FAIL: -F without positional arguments unexpectedly succeeded" >&2
	exit 1
fi
case $usage in
	*-F*foreground*) ;;
	*)
		echo "FAIL: usage does not document -F foreground" >&2
		exit 1
		;;
esac

echo "foreground option test passed"
