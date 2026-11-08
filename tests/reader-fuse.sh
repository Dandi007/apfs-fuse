#!/bin/sh
# T2: exercise the FUSE layer over the same synthetic APFS fixtures as T1.
# Mounting is optional: without /dev/fuse, fusermount or mkapfs the test is
# skipped (77) so the regular build still works in restricted containers.
set -eu

BIN=$1
GEN=$2

if [ ! -e /dev/fuse ]; then
	if [ -n "${APFS_FIXTURE_REQUIRED:-}" ]; then
		echo "FAIL: /dev/fuse is required but missing"
		exit 1
	fi
	echo "SKIP: /dev/fuse is not available"
	exit 77
fi

if ! command -v fusermount3 >/dev/null 2>&1 && ! command -v fusermount >/dev/null 2>&1; then
	if [ -n "${APFS_FIXTURE_REQUIRED:-}" ]; then
		echo "FAIL: fusermount is required but missing"
		exit 1
	fi
	echo "SKIP: fusermount is not available"
	exit 77
fi

if [ -z "${MKAPFS:-}" ]; then
	for candidate in /usr/sbin/mkapfs /sbin/mkapfs /usr/bin/mkapfs /usr/local/sbin/mkapfs /usr/local/bin/mkapfs; do
		if [ -x "$candidate" ]; then
			MKAPFS=$candidate
			export MKAPFS
			break
		fi
	done
fi

if [ -z "${MKAPFS:-}" ]; then
	if [ -n "${APFS_FIXTURE_REQUIRED:-}" ]; then
		echo "FAIL: mkapfs is required but missing"
		exit 1
	fi
	echo "SKIP: mkapfs is not available"
	exit 77
fi

WORK=$(mktemp -d "${TMPDIR:-/tmp}/apfs-fuse-t2-XXXXXX") || exit 1
MNT=$(mktemp -d "${APFS_FUSE_MOUNT_ROOT:-$WORK}/apfs-mnt-XXXXXX") || exit 1

cleanup() {
	if command -v fusermount3 >/dev/null 2>&1; then
		fusermount3 -u "$MNT" 2>/dev/null || true
	else
		fusermount -u "$MNT" 2>/dev/null || true
	fi
	if [ "${APFS_FUSE_USE_SUDO:-auto}" = "0" ]; then
		umount -l "$MNT" 2>/dev/null || true
	else
		umount -l "$MNT" 2>/dev/null || sudo -n umount -l "$MNT" 2>/dev/null || true
	fi
	if mountpoint -q "$MNT"; then
		echo "FAIL: fixture mount remains; preserving $WORK" >&2
		return 1
	fi
	rmdir "$MNT"
	rm -rf "$WORK"
}
trap cleanup EXIT INT TERM

"$GEN" good "$WORK/good.img"
"$GEN" bad "$WORK/bad.img"

FUSERMOUNT=$(command -v fusermount3 || command -v fusermount)

# In restricted containers an unprivileged FUSE mount can be denied even
# though /dev/fuse exists. Fall back to passwordless sudo when available.
# Set APFS_FUSE_USE_SUDO=0 to force a direct, sudo-free run (for an owner
# validating as a regular user on a host where fusermount3 is permitted).
if [ "${APFS_FUSE_USE_SUDO:-auto}" = "0" ]; then
	APFS_FUSE_USE_SUDO=0 python3 -I \
		"$(dirname "$0")/reader_fuse_test.py" "$BIN" "$WORK" "$FUSERMOUNT" "$MNT"
elif [ "$(id -u)" -ne 0 ] && sudo -n true >/dev/null 2>&1; then
	sudo -n env APFS_FUSE_USE_SUDO=1 python3 -I \
		"$(dirname "$0")/reader_fuse_test.py" "$BIN" "$WORK" "$FUSERMOUNT" "$MNT"
else
	APFS_FUSE_USE_SUDO=0 python3 -I \
		"$(dirname "$0")/reader_fuse_test.py" "$BIN" "$WORK" "$FUSERMOUNT" "$MNT"
fi
