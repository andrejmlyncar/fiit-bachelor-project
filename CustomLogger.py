import logging
import config


def setup_logger(logfile):
    logger = logging.getLogger("SecurityMetricIDS")
    format_output = logging.Formatter(fmt='%(asctime)s - %(levelname)s - %(module)s: %(message)s')
    
    logger.setLevel(logging.DEBUG)
    file_logging = logging.FileHandler(logfile)
    file_logging.setLevel(logging.DEBUG)
    file_logging.setFormatter(format_output)
    logger.addHandler(file_logging)

    if config.console_log:
        console_logging = logging.StreamHandler()
        console_logging.setLevel(logging.DEBUG)
        console_logging.setFormatter(format_output)
        logger.addHandler(console_logging)

    return logger


