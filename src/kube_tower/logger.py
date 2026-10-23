import json
import logging
import sys
import threading
from datetime import datetime


class bcolors:
    OKGREEN = "\033[92m"
    ENDC = "\033[0m"
    OKBLUE = "\033[94m"
    YELLOW = "\033[93m"
    RED = "\033[91m"
    GREEN = "\033[92m"


class CustomFormatter(logging.Formatter):
    def format(self, record):
        current_datetime = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        thread_name = threading.current_thread().name
        thread_id = threading.get_ident()
        loglvl = record.levelname.upper()
        msg = record.getMessage()
        msg = msg.replace(" UP ", f"{bcolors.OKGREEN} UP {bcolors.ENDC}")
        msg = msg.replace(" DOWN ", f"{bcolors.RED} DOWN {bcolors.ENDC}")

        if loglvl == "DEBUG":
            logcolor = bcolors.GREEN
            return f"{logcolor}{current_datetime} - [{loglvl}] - [{thread_name}-{thread_id}] - {msg}{bcolors.ENDC}"
        elif loglvl == "INFO":
            logcolor = bcolors.OKBLUE
        elif loglvl == "WARNING":
            logcolor = bcolors.YELLOW
        elif loglvl == "ERROR":
            logcolor = bcolors.RED
        elif loglvl == "CRITICAL":
            logcolor = bcolors.RED
            return f"{logcolor}{current_datetime} - [{loglvl}] - [{thread_name}-{thread_id}] - {msg}{bcolors.ENDC}"
        else:
            logcolor = bcolors.ENDC

        return f"{current_datetime} - [{logcolor}{loglvl}{bcolors.ENDC}] - [{thread_name}-{thread_id}] - {msg}{bcolors.ENDC}"


class JsonFormatter(logging.Formatter):
    def format(self, record):
        log_record = {
            "time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "level": record.levelname,
            "thread": threading.current_thread().name,
            "message": record.getMessage(),
        }
        return json.dumps(log_record)


class LogfmtFormatter(logging.Formatter):
    def format(self, record):
        current_datetime = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        thread_name = threading.current_thread().name
        loglvl = record.levelname.upper()
        msg = record.getMessage()
        return f'time={current_datetime} level={loglvl} thread={thread_name} msg="{msg}"'


class CriticalExitHandler(logging.StreamHandler):
    def emit(self, record):
        super().emit(record)
        # if record.levelno == logging.CRITICAL:
        #     print(f"{bcolors.RED}Exiting...{bcolors.ENDC}")
        #     sys.exit(1)


def get_logger(name, level=logging.INFO, format_type="custom"):
    logger = logging.getLogger(name)
    logger.setLevel(level)

    # Clear existing handlers
    if logger.hasHandlers():
        logger.handlers.clear()

    if format_type == "json":
        formatter = JsonFormatter()
    elif format_type == "logfmt":
        formatter = LogfmtFormatter()
    else:
        formatter = CustomFormatter()

    stdout_handler = logging.StreamHandler(sys.stdout)
    stdout_handler.setLevel(logging.DEBUG)
    stdout_handler.addFilter(lambda record: record.levelno < logging.ERROR)
    stdout_handler.setFormatter(formatter)

    stderr_handler = CriticalExitHandler()
    stderr_handler.setLevel(logging.ERROR)
    stderr_handler.setFormatter(formatter)

    logger.addHandler(stdout_handler)
    logger.addHandler(stderr_handler)

    logger.debug(
        f"Logger initialized with the following parameters : log_level={logging.getLevelName(level)}, log_format={format_type}"
    )

    return logger
