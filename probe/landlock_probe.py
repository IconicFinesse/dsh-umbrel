#!/usr/bin/env python3
"""Landlock availability probe for a container.

Reports the Landlock ABI version the kernel offers this process:
  >0  Landlock is compiled in, enabled, and reachable (not seccomp-blocked)
  -1  with errno ENOSYS (38)    -> kernel built without Landlock
      with errno EOPNOTSUPP(95) -> Landlock disabled at boot
      with errno EPERM/EACCES   -> likely blocked by the container seccomp profile
Also prints the process seccomp mode from /proc/self/status.
"""
import ctypes
import errno
import os
import sys

libc = ctypes.CDLL(None, use_errno=True)
SYS_landlock_create_ruleset = 444
LANDLOCK_CREATE_RULESET_VERSION = 1 << 0


class RulesetAttr(ctypes.Structure):
    _fields_ = [("handled_access_fs", ctypes.c_uint64)]


def main() -> int:
    for line in open("/proc/self/status"):
        if line.startswith(("Seccomp:", "NoNewPrivs:")):
            print(line.strip())
    attr = RulesetAttr(0)
    ret = libc.syscall(
        SYS_landlock_create_ruleset,
        ctypes.byref(attr),
        ctypes.sizeof(attr),
        LANDLOCK_CREATE_RULESET_VERSION,
    )
    if ret >= 0:
        print(f"LANDLOCK OK: ABI version {ret}")
        return 0
    err = ctypes.get_errno()
    print(f"LANDLOCK UNAVAILABLE: errno {err} ({errno.errorcode.get(err, os.strerror(err))})")
    return 1


if __name__ == "__main__":
    sys.exit(main())
