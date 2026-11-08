#!/usr/bin/env python3
"""FUSE-level assertions over the synthetic APFS fixtures (T2)."""

import ctypes
import errno
import hashlib
import os
import subprocess
import sys
import time

BIN = sys.argv[1]
WORK = sys.argv[2]
FUSERMOUNT = sys.argv[3]
MNT = sys.argv[4] if len(sys.argv) > 4 else os.path.join(WORK, "mnt")

USE_SUDO = os.environ.get("APFS_FUSE_USE_SUDO") == "1"
PREFIX = ["sudo", "-n"] if USE_SUDO else []

DECMPFS = "com.apple.decmpfs"
RF = "com.apple.ResourceFork"

# Valid resource-fork compression fixtures: uncompressed size and golden
# SHA-256 of the bytes the reader must return. These match tests/RfContent.cpp.
RF_GOLDEN = {
    "rf-zlib-1blk": (65536,
        "2b47f9d9b733211adfd5b9df4a6b8c6588484460044f256cf1afd4ca4291f7ba"),
    "rf-zlib-multi": (143417,
        "5d694d5ee57aaac2e0654e852c6a48f54f8c43cc24209ecf2dcedad3828007ba"),
    "rf-lzvn-1blk": (65536,
        "9d818af1daa0ddaa4bcfc3644c3afddb9d1b96b485d3361f84b0be875295e852"),
    "rf-lzvn-multi": (143417,
        "39df88537b4c33765f79d63e1d6ce4f09b65cae0758667658da2169b94fde121"),
}

# Valid inline zlib (algo 3) content. Unlike RF_GOLDEN these files have no
# ResourceFork carrier: the whole zlib stream lives in the decmpfs xattr.
INLINE_ZLIB_GOLDEN = {
    "inline-zlib": (16384,
        "8bb2b1c190c37e098a55be7bb5076a78e5b27712bea936fe5163fa5b70493918"),
}

# Damaged inline zlib fixtures. Both keep a valid zlib header, so the reader
# must enter DecompressZLib() and fail closed instead of hanging or returning
# partial data. In the default (strict, non `-l`) mode open() is EIO.
DAMAGED_ZLIB = ("inline-zlib-truncated", "inline-zlib-corrupt")

# Inode 60 (rf-zlib-1blk) also carries a second directory entry. Opening each
# hardlink path separately, as a manifest does, must produce one complete
# OBJECT record per open even when the second handle is never read.
HARDLINK_ALIAS = "rf-zlib-1blk-hardlink"
HARDLINK_GOLDEN = RF_GOLDEN["rf-zlib-1blk"]
OBJECT_FIELDS = (b"seq", b"ino", b"algo", b"logical_size", b"blocks", b"zlib",
                 b"raw", b"native", b"missing_adler", b"validation",
                 b"checksum_verified", b"result")
HARDLINK_OBJECT = {
    b"ino": b"60",
    b"algo": b"4",
    b"logical_size": b"65536",
    b"blocks": b"1",
    b"zlib": b"1",
    b"raw": b"0",
    b"native": b"0",
    b"missing_adler": b"0",
    b"validation": b"checksum",
    b"checksum_verified": b"1",
    b"result": b"ok",
}

libc = ctypes.CDLL("libc.so.6", use_errno=True)


def fail(message):
    print("FAIL:", message)
    sys.exit(1)


FOREGROUND = None
FOREGROUND_LOG = None
FOREGROUND_STDOUT = None
FOREGROUND_LOG_PATH = None
FOREGROUND_STDOUT_PATH = None


def mount(image, extra=(), foreground=False):
    global FOREGROUND, FOREGROUND_LOG, FOREGROUND_STDOUT
    global FOREGROUND_LOG_PATH, FOREGROUND_STDOUT_PATH
    args = [BIN]
    options = []
    if extra:
        options.append(extra)
    if options:
        args.extend(["-o", ",".join(options)])
    args.extend([image, MNT])
    if foreground:
        # -F keeps the reader in the foreground so stdout and stderr can be
        # captured separately. No -d (debug) and no -l (lax) may be in effect:
        # the diagnostics under test are the production defaults.
        FOREGROUND_LOG_PATH = os.path.join(WORK, "foreground.log")
        FOREGROUND_STDOUT_PATH = os.path.join(WORK, "foreground.stdout")
        FOREGROUND_LOG = open(FOREGROUND_LOG_PATH, "wb")
        FOREGROUND_STDOUT = open(FOREGROUND_STDOUT_PATH, "wb")
        FOREGROUND = subprocess.Popen(PREFIX + [BIN, "-F"] + args[1:],
                                      stdout=FOREGROUND_STDOUT,
                                      stderr=FOREGROUND_LOG)
    else:
        subprocess.run(PREFIX + args, check=True)
    deadline = time.time() + 15
    while time.time() < deadline:
        try:
            if os.path.ismount(MNT):
                os.listdir(MNT)
                if foreground and FOREGROUND.poll() is not None:
                    fail("foreground reader exited before the mount was ready")
                return
            time.sleep(0.05)
        except OSError:
            time.sleep(0.05)
    fail("mount did not become ready: " + image)


def unmount():
    global FOREGROUND, FOREGROUND_LOG, FOREGROUND_STDOUT
    subprocess.run(PREFIX + [FUSERMOUNT, "-u", MNT], check=False,
                   stderr=subprocess.DEVNULL)
    time.sleep(0.1)
    if os.path.ismount(MNT):
        # Restricted containers sometimes refuse a regular FUSE unmount even
        # for root; a lazy unmount is enough for a throwaway mount point.
        subprocess.run(PREFIX + ["umount", "-l", MNT], check=False,
                   stderr=subprocess.DEVNULL)
    deadline = time.time() + 10
    while time.time() < deadline:
        if not os.path.ismount(MNT):
            if FOREGROUND is not None:
                FOREGROUND.wait(timeout=10)
                FOREGROUND_LOG.close()
                FOREGROUND_STDOUT.close()
                FOREGROUND = FOREGROUND_LOG = FOREGROUND_STDOUT = None
            return
        time.sleep(0.05)
    fail("unmount did not complete")


def xattrs(path):
    return set(os.listxattr(path))


def lgetxattr(path, name, size):
    buf = ctypes.create_string_buffer(size) if size else None
    res = libc.lgetxattr(path.encode(), name.encode(), buf, size)
    if res < 0:
        err = ctypes.get_errno()
        return -1, err, None
    return res, 0, buf.raw[:res]


def expect_errno(call, expected, message):
    try:
        call()
    except OSError as exc:
        if exc.errno != expected:
            fail("%s: got errno %d, expected %d" % (message, exc.errno, expected))
        return
    fail("%s: call unexpectedly succeeded" % message)


def read_log_window(path, start):
    with open(path, "rb") as log:
        log.seek(start)
        return log.read()


def parse_fields(line):
    fields = {}
    for token in line.split():
        if b"=" in token:
            key, value = token.split(b"=", 1)
            fields[key] = value
    return fields


def object_records(window):
    return [parse_fields(line) for line in window.splitlines()
            if line.startswith(b"APFS_DECMPFS_OBJECT ")]


def check_object_window(window, label):
    """One complete OBJECT summary plus its one zlib block VALIDATION line."""
    objects = object_records(window)
    if len(objects) != 1:
        fail("%s: expected one OBJECT line, got %d" % (label, len(objects)))
    obj = objects[0]
    missing = [field for field in OBJECT_FIELDS if field not in obj]
    if missing:
        fail("%s: OBJECT line missing fields %s" % (label, missing))
    for key, value in HARDLINK_OBJECT.items():
        if obj[key] != value:
            fail("%s: OBJECT %s=%r, expected %r" %
                 (label, key.decode(), obj[key], value))
    lines = [line for line in window.splitlines()
             if line.startswith(b"APFS_DECMPFS_VALIDATION ")]
    if len(lines) != 1:
        fail("%s: expected one VALIDATION line, got %d" % (label, len(lines)))
    val = parse_fields(lines[0])
    expected = {
        b"seq": obj[b"seq"],
        b"ino": b"60",
        b"algo": b"4",
        b"block": b"0",
        b"expected": b"65536",
        b"decoded": b"65536",
        b"validation": b"length_with_checksum",
        b"missing_adler": b"0",
    }
    for key, value in expected.items():
        if val.get(key) != value:
            fail("%s: VALIDATION %s=%r, expected %r" %
                 (label, key.decode(), val.get(key), value))
    return obj


def check_rf_content(root, backup):
    for name in sorted(RF_GOLDEN):
        size, digest = RF_GOLDEN[name]
        path = os.path.join(root, name)
        attrs = xattrs(path)
        if backup:
            if DECMPFS in attrs or RF in attrs:
                fail("backup view must hide the decmpfs/RF pair on " + name)
        else:
            if DECMPFS not in attrs or RF not in attrs:
                fail("default view must expose decmpfs and the carrier on " + name)
        st = os.stat(path)
        if st.st_size != size:
            fail("%s size is %d, expected %d" % (name, st.st_size, size))
        with open(path, "rb") as f:
            data = f.read()
        if hashlib.sha256(data).hexdigest() != digest:
            fail("%s content SHA-256 mismatch" % name)


def check_inline_zlib(root, backup):
    for name in sorted(INLINE_ZLIB_GOLDEN):
        size, digest = INLINE_ZLIB_GOLDEN[name]
        path = os.path.join(root, name)
        attrs = xattrs(path)
        if backup:
            if DECMPFS in attrs:
                fail("backup view must hide decmpfs on " + name)
        else:
            if DECMPFS not in attrs:
                fail("default view must expose decmpfs on " + name)
            if RF in attrs:
                fail("inline zlib must not expose a ResourceFork carrier: " + name)
        st = os.stat(path)
        if st.st_size != size:
            fail("%s size is %d, expected %d" % (name, st.st_size, size))
        with open(path, "rb") as f:
            data = f.read()
        if hashlib.sha256(data).hexdigest() != digest:
            fail("%s content SHA-256 mismatch" % name)


def expect_damaged_zlib_eio(root):
    for name in DAMAGED_ZLIB:
        expect_errno(
            lambda name=name: os.open(os.path.join(root, name), os.O_RDONLY),
            errno.EIO, name + " open")


def test_good_default():
    mount(os.path.join(WORK, "good.img"))
    root = os.path.join(MNT, "root")

    names = sorted(os.listdir(root))
    for expected in ("inline", "rf", "user-rf", "xattrs", "hole.bin", "gap.bin"):
        if expected not in names:
            fail("default view is missing " + expected)

    # Default (non-backup) view keeps the on-disk compression metadata visible.
    if DECMPFS not in xattrs(os.path.join(root, "inline")):
        fail("default view must expose decmpfs on inline files")

    # Damaged compression metadata must not make the object unreachable: the
    # backup manifest still needs type/mode/size.
    st = os.stat(os.path.join(root, "inline-empty"))
    if st.st_size != 100:
        fail("inline-empty default size changed: %d" % st.st_size)
    st = os.stat(os.path.join(root, "rf-missing"))
    if st.st_size != 200:
        fail("rf-missing default size changed: %d" % st.st_size)
    st = os.stat(os.path.join(root, "size-mismatch"))
    if st.st_size != 99:
        fail("size-mismatch default size changed: %d" % st.st_size)

    # A missing name is ENOENT, not EIO.
    expect_errno(lambda: os.stat(os.path.join(root, "no-such-name")), errno.ENOENT,
                 "missing name")

    # A missing extent record must be EIO, not silent zero-fill.
    fd = os.open(os.path.join(root, "gap.bin"), os.O_RDONLY)
    try:
        expect_errno(lambda: os.read(fd, 80), errno.EIO, "missing extent record")
    finally:
        os.close(fd)

    # Explicit hole: zeros in the middle, real data on both sides.
    with open(os.path.join(root, "hole.bin"), "rb") as f:
        data = f.read()
    if len(data) != 80:
        fail("hole.bin size is %d" % len(data))
    if data[:24] != bytes(k & 0xFF for k in range(24)):
        fail("hole.bin prefix data")
    if data[24:64] != bytes(40):
        fail("hole.bin explicit hole is not zero")
    if data[64:80] != bytes(k & 0xFF for k in range(64, 80)):
        fail("hole.bin suffix data")

    # xattr semantics at the FUSE boundary.
    path = os.path.join(root, "xattrs")
    if os.getxattr(path, "com.apple.test.small") != b"hello":
        fail("small xattr value")
    big = os.getxattr(path, "com.apple.test.big64k")
    if len(big) != 65536:
        fail("64 KiB xattr length")
    expect_errno(lambda: os.getxattr(path, "com.apple.test.big64k1"), errno.EIO,
                 "65537-byte xattr must be EIO")
    res, err, _ = lgetxattr(path, "com.apple.test.small", 4)
    if res != -1 or err != errno.ERANGE:
        fail("short xattr buffer must be ERANGE (res=%d err=%d)" % (res, err))

    # Valid resource-fork compressed content must decompress in the default view.
    check_rf_content(root, backup=False)

    # Inline zlib (algo 3) content and its damaged variants. Both damaged
    # fixtures must be EIO under the default strict mode, never partial data.
    check_inline_zlib(root, backup=False)
    expect_damaged_zlib_eio(root)

    # The original placeholder keeps its invalid carrier: opening it is EIO.
    expect_errno(lambda: open(os.path.join(root, "rf"), "rb"), errno.EIO,
                 "invalid RF carrier open")

    unmount()


def test_good_backup():
    mount(os.path.join(WORK, "good.img"), "backup_view=1")
    root = os.path.join(MNT, "root")

    inline = xattrs(os.path.join(root, "inline"))
    if DECMPFS in inline:
        fail("backup view must hide decmpfs for inline compression")

    rf = xattrs(os.path.join(root, "rf"))
    if DECMPFS in rf or RF in rf:
        fail("backup view must hide the decmpfs/RF carrier pair")

    if RF not in xattrs(os.path.join(root, "user-rf")):
        fail("backup view must keep a real user resource fork")

    inline_rf = xattrs(os.path.join(root, "inline-user-rf"))
    if DECMPFS in inline_rf:
        fail("backup view hides decmpfs on inline files")
    if RF not in inline_rf:
        fail("backup view must keep the user RF on inline files")

    expect_errno(
        lambda: os.getxattr(os.path.join(root, "inline-empty"), DECMPFS),
        errno.EIO, "broken compression metadata in backup view")
    expect_errno(
        lambda: os.getxattr(os.path.join(root, "rf-missing"), RF),
        errno.EIO, "missing RF carrier in backup view")

    # The default view is the oracle for stat semantics: backup_view must not
    # change sizes for reachable objects.
    st = os.stat(os.path.join(root, "inline"))
    if st.st_size != 100:
        fail("inline size in backup view: %d" % st.st_size)

    # backup_view=1 hides the metadata pair but still returns the real content.
    check_rf_content(root, backup=True)
    check_inline_zlib(root, backup=True)

    unmount()


def test_bad():
    mount(os.path.join(WORK, "bad.img"))
    root = os.path.join(MNT, "root")

    expect_errno(lambda: os.stat(os.path.join(root, "badfile")), errno.EIO,
                 "damaged leaf lookup")
    expect_errno(lambda: os.stat(os.path.join(root, "no-such-name")), errno.ENOENT,
                 "missing name next to damaged pages")

    unmount()


def test_foreground_log():
    mount(os.path.join(WORK, "good.img"), foreground=True)
    log_path = FOREGROUND_LOG_PATH
    root = os.path.join(MNT, "root")
    first = os.path.join(root, "rf-zlib-1blk")
    alias = os.path.join(root, HARDLINK_ALIAS)
    try:
        # The two names are hardlinks: one inode, two paths. A manifest that
        # opens every directory entry must see the same inode twice.
        first_stat = os.stat(first)
        alias_stat = os.stat(alias)
        if first_stat.st_ino != 60 or alias_stat.st_ino != first_stat.st_ino:
            fail("hardlink paths do not share FUSE inode 60: %d/%d" %
                 (first_stat.st_ino, alias_stat.st_ino))

        # First path: open and read the whole object, then compare the golden
        # SHA. The open itself decompresses, so one OBJECT record is due.
        size, digest = HARDLINK_GOLDEN
        start = os.path.getsize(log_path)
        with open(first, "rb") as f:
            data = f.read()
        first_object = check_object_window(
            read_log_window(log_path, start), "first hardlink open/read")
        if len(data) != size:
            fail("rf-zlib-1blk size is %d, expected %d" % (len(data), size))
        if hashlib.sha256(data).hexdigest() != digest:
            fail("rf-zlib-1blk content SHA-256 mismatch")

        # Second path: open and close without any read. The cached handle from
        # the first path must not suppress decompression for the new open.
        start = os.path.getsize(log_path)
        fd = os.open(alias, os.O_RDONLY)
        os.close(fd)
        second_object = check_object_window(
            read_log_window(log_path, start), "second hardlink open without read")
        if int(second_object[b"seq"]) <= int(first_object[b"seq"]):
            fail("second hardlink open must get a newer seq: %s -> %s" %
                 (first_object[b"seq"].decode(), second_object[b"seq"].decode()))

        # rf-missing is MissingCarrier: classification rejects it at open, so
        # it must be EIO with no decompression error and no OBJECT record.
        # The separate bad-carrier fixture is named "rf", not this one.
        start = os.path.getsize(log_path)
        expect_errno(lambda: os.open(os.path.join(root, "rf-missing"), os.O_RDONLY),
                     errno.EIO, "rf-missing open")
        window = read_log_window(log_path, start)
        if b"APFS_DECMPFS_ERROR" in window:
            fail("rf-missing must not emit APFS_DECMPFS_ERROR")
        if object_records(window):
            fail("rf-missing must not emit an OBJECT line")

        os.stat(os.path.join(MNT, "root", "unicode-\U0001f9e8"))
        # These opens must reach DecompressZLib() and fail closed; the FUSE
        # process writes the diagnostic to the captured stderr log.
        expect_damaged_zlib_eio(root)
    finally:
        unmount()

    stdout_path = FOREGROUND_STDOUT_PATH
    if os.path.getsize(stdout_path) != 0:
        fail("foreground stdout must be empty without -d")
    with open(log_path, "rb") as log:
        data = log.read()
    if b"APFS_UNICODE_FALLBACK" not in data or b"name_hex=756e69636f64652df09fa7a8" not in data:
        fail("foreground fallback log missing")

    zlib_lines = [line for line in data.splitlines() if b"APFS_ZLIB_ERROR" in line]
    if len(zlib_lines) < len(DAMAGED_ZLIB):
        fail("foreground log is missing damaged-zlib diagnostics")
    for line in zlib_lines:
        for field in (b"ret=", b"total_in=", b"total_out=", b"src_size=", b"dst_size="):
            if field not in line:
                fail("zlib diagnostic is missing %s: %r" % (field.decode(), line))
        # The diagnostic describes the stream only. A real path or the image
        # name would leak where the backup source lives.
        if WORK.encode() in line or b"good.img" in line:
            fail("zlib diagnostic leaks the image path: %r" % line)


def main():
    test_good_default()
    test_good_backup()
    test_bad()
    test_foreground_log()
    print("FUSE reader tests passed")


if __name__ == "__main__":
    main()
