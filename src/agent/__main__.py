import faulthandler
import os
import sys
import tempfile
import threading
import traceback
from datetime import datetime

from agent.config import KEY_FILE
from agent.entry_controllers.run_controller import RunController
from agent.entry_controllers.registration_controller import RegistrationController

CRASH_LOG_SIZE_LIMIT = 512 * 1024


def _crash_log_path() -> str:
    candidates = [
        os.path.join(os.path.dirname(KEY_FILE) or ".", "agent_crash.log"),
        os.path.join(os.getcwd(), "agent_crash.log"),
        os.path.join(tempfile.gettempdir(), "agent_crash.log"),
    ]
    for path in candidates:
        try:
            with open(path, "a", encoding="utf-8"):
                pass
            return path
        except OSError:
            continue
    return os.devnull


def _write_crash_log(log_path: str, text: str) -> None:
    try:
        if os.path.getsize(log_path) > CRASH_LOG_SIZE_LIMIT:
            with open(log_path, "w", encoding="utf-8"):
                pass
        with open(log_path, "a", encoding="utf-8") as f:
            f.write(text)
    except Exception:
        pass


def _install_crash_reporting() -> None:
    log_path = _crash_log_path()

    def _format(exc, tb) -> str:
        try:
            return "".join(traceback.format_exception(type(exc), exc, tb))
        except Exception:
            return repr(exc)

    def thread_hook(args) -> None:
        exc = args.exc_value
        if exc is None:
            return
        tb = getattr(args, "traceback", None) or getattr(args, "exc_traceback", None)
        thread_name = getattr(args.thread, "name", "?")
        _write_crash_log(
            log_path,
            f"\n=== {datetime.now().isoformat()} uncaught exception (thread={thread_name}) ===\n{_format(exc, tb)}",
        )

    def main_hook(etype, value, tb) -> None:
        if value is None:
            return
        _write_crash_log(
            log_path,
            f"\n=== {datetime.now().isoformat()} uncaught exception (thread=main) ===\n{_format(value, tb)}",
        )

    threading.excepthook = thread_hook
    sys.excepthook = main_hook
    try:
        faulthandler.enable(file=open(log_path, "a", encoding="utf-8"))
    except Exception:
        faulthandler.enable()


def main():
    _install_crash_reporting()
    args = sys.argv[1:]
    if len(args) > 0 and args[0] == "--register":
        RegistrationController().run(args)
    else:
        RunController().run(args)

if __name__ == "__main__":
    main()
