"""Scan stand-ins for the benchmark isolation tests. They run inside a spawned item process (imported by name), so
they live in a plain module the child can import. Nothing here touches any package or the network."""
import os
import time


def ok(item, osv):
    return {"status": "scored", "findings_by_tier": {"high_risk": 0}, "label": "No findings"}


def sleep_forever(item, osv):
    while True:
        time.sleep(1)


def allocate_forever(item, osv):
    hold = []
    for _ in range(96):               # 64 MB at a time, up to 6 GB, until the memory cap stops it
        hold.append(bytearray(64 * 1024 * 1024))
    sleep_forever(item, osv)          # no cap on this platform: end as a timeout, never exhaust the machine


def hard_exit(item, osv):
    os._exit(3)                       # the process dies without sending a result


def sleep_if_pkg1(item, osv):
    if item.get("package") == "pkg1":
        sleep_forever(item, osv)
    return ok(item, osv)
