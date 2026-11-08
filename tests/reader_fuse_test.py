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
MNT = os.path.join(WORK, "mnt")

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

libc = ctypes.CDLL("libc.so.6", use_errno=True)


def fail(message):
    print("FAIL:", message)
    sys.exit(1)


FOREGROUND = None
FOREGROUND_LOG = None


def mount(image, extra=(), foreground=False):
    global FOREGROUND, FOREGROUND_LOG
    args = [BIN]
    options = []
    if extra:
        options.append(extra)
    if options:
        args.extend(["-o", ",".join(options)])
    args.extend([image, MNT])
    if foreground:
        FOREGROUND_LOG = open(os.path.join(WORK, "foreground.log"), "wb")
        FOREGROUND = subprocess.Popen(PREFIX + [BIN, "-d", "1"] + args[1:],
                                      stdout=FOREGROUND_LOG, stderr=FOREGROUND_LOG)
    else:
        subprocess.run(PREFIX + args, check=True)
    deadline = time.time() + 15
    while time.time() < deadline:
        try:
            if os.path.ismount(MNT):
                os.listdir(MNT)
                return
            time.sleep(0.05)
        except OSError:
            time.sleep(0.05)
    fail("mount did not become ready: " + image)


def unmount():
    global FOREGROUND, FOREGROUND_LOG
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
                FOREGROUND = FOREGROUND_LOG = None
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
    try:
        os.stat(os.path.join(MNT, "root", "unicode-\U0001f9e8"))
    finally:
        unmount()
    with open(os.path.join(WORK, "foreground.log"), "rb") as log:
        data = log.read()
    if b"APFS_UNICODE_FALLBACK" not in data or b"name_hex=756e69636f64652df09fa7a8" not in data:
        fail("foreground fallback log missing")


def main():
    test_good_default()
    test_good_backup()
    test_bad()
    test_foreground_log()
    print("FUSE reader tests passed")


if __name__ == "__main__":
    main()
