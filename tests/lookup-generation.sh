#!/bin/sh
# Regression: repeated lookups of one name must report the same (zero) generation.
# A changed generation makes the kernel replace the inode, so bind mounts holding
# the old inode get EIO forever. Usage: lookup-generation.sh <apfs-fuse binary>
set -eu
FUSE=$1
MKAPFS=${MKAPFS:-$(command -v mkapfs || true)}
if [ -z "$MKAPFS" ] || ! command -v strace >/dev/null || ! sudo -n true 2>/dev/null; then
	echo "skip: needs mkapfs, strace and passwordless sudo"
	[ -n "${LOOKUP_TEST_REQUIRED:-}" ] && exit 1
	exit 77
fi
dir=$(mktemp -d)
trap 'sudo -n umount "$dir/m" 2>/dev/null || true; sudo -n rm -rf "$dir"' EXIT
truncate -s 1G "$dir/img"
"$MKAPFS" "$dir/img" >/dev/null
mkdir "$dir/m"
sudo -n strace -f -xx -s 256 -e trace=writev -o "$dir/log" "$FUSE" -o ro "$dir/img" "$dir/m" &
for i in $(seq 50); do sudo -n mountpoint -q "$dir/m" && break; sleep 0.2; done
# Drop the dentry cache between stats so each one sends a fresh LOOKUP("root").
for i in 1 2 3 4; do
	sudo -n stat "$dir/m/root" >/dev/null
	sudo -n sh -c 'echo 2 > /proc/sys/vm/drop_caches'
done
sudo -n umount "$dir/m"
wait
sudo -n cat "$dir/log" | python3 -c '
import re, struct, sys
gens = []
for line in sys.stdin:
    iov = re.findall(r"iov_base=\"((?:\\x[0-9a-f]{2})+)\"", line)
    if len(iov) < 2:
        continue
    hdr, body = (bytes.fromhex(s.replace("\\x", "")) for s in iov[:2])
    # fuse_out_header (16 bytes) + fuse_entry_out (128 bytes): nodeid, generation, ...
    if len(hdr) == 16 and struct.unpack("<I", hdr[:4])[0] == 144:
        gens.append(struct.unpack("<QQ", body[:16]))
print("lookup replies (nodeid, generation):", gens)
sys.exit(0 if len(gens) >= 3 and all(g == 0 for _, g in gens) else 1)
'
