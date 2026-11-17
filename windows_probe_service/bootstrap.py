"""Load the service only after a standard-library startup error handler exists."""
from __future__ import annotations

import os
import sys
import traceback


def _pause_for_double_click():
    # Automated commands and redirected input must never wait for a key. The
    # optional CMD launcher owns its own pause, including bootloader failures.
    if (not getattr(sys, "frozen", False) or len(sys.argv) != 1
            or os.environ.get("SOAR_PROBE_CMD_LAUNCH") == "1"
            or not getattr(sys.stdin, "isatty", lambda: False)()
            or not getattr(sys.stdout, "isatty", lambda: False)()
            or not getattr(sys.stderr, "isatty", lambda: False)()):
        return
    try:
        input("Press Enter to close this window...")
    except (EOFError, OSError):
        pass


def launch():
    try:
        # Keep this import inside the handler: native extension imports can
        # fail before service.launch() has had an opportunity to run.
        import service
    except Exception as error:
        traceback.print_exc(file=sys.stderr)
        message = str(error).casefold()
        policy_block = (getattr(error, "winerror", None) in {577, 1260, 4551}
                        or "应用程序控制策略" in message
                        or "application control policy" in message
                        or "smart app control" in message)
        print("SOARProbe could not load a bundled dependency.", file=sys.stderr)
        if policy_block:
            print("Windows application control blocked a DLL or PYD file. "
                  "The portable ZIP avoids temporary dependency extraction, but "
                  "does not change Smart App Control or guarantee policy approval. "
                  "Keep this error for support and review the package's policy guidance.",
                  file=sys.stderr)
        else:
            print("Keep this error for support. Extract the complete portable ZIP; "
                  "do not copy only its EXE or delete its _internal directory.",
                  file=sys.stderr)
        # Do not open configuration files, inspect credentials or write logs
        # while imports are failing. Only the console receives this diagnostic.
        _pause_for_double_click()
        return 1
    return service.launch()


if __name__ == "__main__":
    raise SystemExit(launch())
