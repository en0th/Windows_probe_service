"""Windows ICMP APIs: no raw sockets, shell commands or localized output parsing."""
from __future__ import annotations

import ctypes
import ipaddress
import os
import sys
import time


class IpOptions(ctypes.Structure):
    _fields_ = [("ttl", ctypes.c_uint8), ("tos", ctypes.c_uint8),
                ("flags", ctypes.c_uint8), ("size", ctypes.c_uint8),
                ("data", ctypes.c_void_p)]


class ReplyOptions32(ctypes.Structure):
    _fields_ = [("ttl", ctypes.c_uint8), ("tos", ctypes.c_uint8),
                ("flags", ctypes.c_uint8), ("size", ctypes.c_uint8),
                ("data", ctypes.c_uint32)]


class EchoReply(ctypes.Structure):
    # IcmpSendEcho returns ICMP_ECHO_REPLY32 on Win64 too. Only its status/RTT
    # are read, but retain the documented fixed-width layout for the full ABI.
    _fields_ = [("address", ctypes.c_uint32), ("status", ctypes.c_uint32),
                ("rtt", ctypes.c_uint32), ("size", ctypes.c_uint16),
                ("reserved", ctypes.c_uint16), ("data", ctypes.c_uint32),
                ("options", ReplyOptions32)]


def classify_status(status: int) -> str:
    if status == 0:
        return "reachable"
    if status == 11010:  # IP_REQ_TIMED_OUT
        return "timeout"
    if status in {11002, 11003, 11004, 11005, 11013, 11014, 11015, 11016,
                  11018, 11040, 11042, 11043, 11044, 11045}:
        return "unreachable"
    return "error"


def ping(address: str, timeout_ms: int) -> dict:
    """One echo request. Called in a bounded asyncio worker thread."""
    started = time.monotonic()
    result = {"address": address, "status": "error", "elapsedMs": 0}
    try:
        target = ipaddress.ip_address(address)
    except ValueError:
        return {**result, "error": "invalid_address"}
    if target.version != 4:
        return {**result, "status": "skipped_ipv6", "reason": "ipv4_only"}
    if os.name != "nt":
        return {**result, "error": "windows_required"}
    handle = None
    api = None
    try:
        api = ctypes.WinDLL("iphlpapi.dll", use_last_error=True)
        api.IcmpCloseHandle.argtypes = [ctypes.c_void_p]
        api.IcmpCloseHandle.restype = ctypes.c_int
        request = ctypes.create_string_buffer(b"SOARProbe")
        options = IpOptions(64, 0, 0, 0, None)
        api.IcmpCreateFile.restype = ctypes.c_void_p
        handle = api.IcmpCreateFile()
        api.IcmpSendEcho.argtypes = [ctypes.c_void_p, ctypes.c_uint32,
            ctypes.c_void_p, ctypes.c_uint16, ctypes.POINTER(IpOptions),
            ctypes.c_void_p, ctypes.c_uint32, ctypes.c_uint32]
        api.IcmpSendEcho.restype = ctypes.c_uint32
        reply = ctypes.create_string_buffer(ctypes.sizeof(EchoReply) + 64)
        destination = int.from_bytes(target.packed, byteorder=sys.byteorder)
        if handle in (None, ctypes.c_void_p(-1).value):
            raise OSError(ctypes.get_last_error(), "IcmpCreateFile failed")
        count = api.IcmpSendEcho(handle, destination, request, 9,
            ctypes.byref(options), reply, len(reply), timeout_ms)
        parsed = ctypes.cast(reply, ctypes.POINTER(EchoReply)).contents if count else None
        status = int(parsed.status) if parsed is not None else ctypes.get_last_error()
        result["status"] = classify_status(status)
        if result["status"] == "reachable":
            result["roundTripMs"] = int(parsed.rtt)
        else:
            result["error"] = f"icmp_status_{status}"
    except (OSError, ValueError, AttributeError) as exc:
        result["error"] = f"icmp_api_error_{getattr(exc, 'winerror', None) or getattr(exc, 'errno', None) or type(exc).__name__}"
    finally:
        if api is not None and handle not in (None, ctypes.c_void_p(-1).value):
            api.IcmpCloseHandle(handle)
        result["elapsedMs"] = round((time.monotonic() - started) * 1000)
    return result
