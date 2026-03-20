import logging
import sys
from colorama import init, Fore, Style

# Initialize colorama
init(autoreset=True)

class CustomFormatter(logging.Formatter):
    """Custom color formatter for different log levels."""
    
    grey = "\x1b[38;20m"
    yellow = "\x1b[33;20m"
    red = "\x1b[31;20m"
    bold_red = "\x1b[31;1m"
    reset = "\x1b[0m"
    format_prefix = "[%(levelname)s] "
    format_msg = "%(message)s"

    FORMATS = {
        logging.DEBUG: grey + format_prefix + reset + format_msg,
        logging.INFO: Fore.CYAN + format_prefix + Style.RESET_ALL + format_msg,
        logging.WARNING: yellow + format_prefix + reset + format_msg,
        logging.ERROR: red + format_prefix + reset + format_msg,
        logging.CRITICAL: bold_red + format_prefix + reset + format_msg
    }

    def format(self, record):
        log_fmt = self.FORMATS.get(record.levelno)
        formatter = logging.Formatter(log_fmt)
        return formatter.format(record)

def setup_logger(name="v-xent", debug=False):
    """Configura y devuelve un logger profesional."""
    logger = logging.getLogger(name)
    
    if logger.hasHandlers():
        return logger

    level = logging.DEBUG if debug else logging.INFO
    logger.setLevel(level)

    # Console Handler
    stdout_handler = logging.StreamHandler(sys.stdout)
    stdout_handler.setLevel(level)
    stdout_handler.setFormatter(CustomFormatter())
    
    logger.addHandler(stdout_handler)
    
    return logger

# Singleton logger instance
logger = setup_logger()
