import hashlib
import os
import sys


def stream(path, out, after_block=lambda: None):
    digest, size = hashlib.sha256(), 0
    with open(path, "rb") as source:
        before = os.fstat(source.fileno())
        for block in iter(lambda: source.read(1 << 20), b""):
            digest.update(block)
            out.write(block)
            size += len(block)
            after_block()
        after = os.fstat(source.fileno())
    out.flush()
    unchanged = (before.st_ino, before.st_size, before.st_mtime_ns) == (after.st_ino, size, after.st_mtime_ns)
    # Renaming a new file over the path unlinks this inode, which updates its
    # ctime but not its bytes; any other ctime change means a write.
    unwritten = before.st_ctime_ns == after.st_ctime_ns or after.st_nlink < before.st_nlink
    return digest.hexdigest(), size, unchanged and after.st_size == size and unwritten


if __name__ == "__main__":
    sha256, size, stable = stream(sys.argv[1], sys.stdout.buffer)
    sys.stderr.write("READ sha256=%s size=%d stable=%d\n" % (sha256, size, stable))
