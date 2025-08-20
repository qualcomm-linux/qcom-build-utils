# Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
#
# SPDX-License-Identifier: BSD-3-Clause-Clear

"""
color_logger.py

This module provides a color logger class, allowing users to log messages with colored text.
The class includes methods for logging messages at different levels, the same as the standard
python 'logging' mdule : debug, info, warning, error, and critical.

Usage:
    from color_logger import logger

    logger.debug('This is a debug message')
    logger.info('This is an info message')
    logger.warning('This is a warning message')
    logger.error('This is an error message')
    logger.critical('This is a critical message')
"""

import logging
import datetime

class ColorLogger:
    LEVEL_STRING = {
        logging.DEBUG:    'DEBG',
        logging.INFO:     'INFO',
        logging.WARNING:  'WARN',
        logging.ERROR:    'ERR ',
        logging.CRITICAL: 'CRIT'
    }

    LEVEL_COLORS = {
        logging.DEBUG:    '\033[94m', #CYAN
        logging.INFO:     '\033[92m', #GREEN
        logging.WARNING:  '\033[93m', #YELLOW
        logging.ERROR:    '\033[91m', #RED
        logging.CRITICAL: '\033[95m' #MAGENTA
    }

    def __init__(self, name: str, level=logging.DEBUG):
        self.logger = logging.getLogger(name)
        self.logger.setLevel(level)
        self.color_enabled = True

        handler = logging.StreamHandler()
        handler.setFormatter(logging.Formatter('%(message)s'))
        self.logger.addHandler(handler)

    def log(self, level, message):
        reset = "\033[0m"
        color = self.LEVEL_COLORS.get(level, "")
        level_str = self.LEVEL_STRING.get(level, '    ')
        colored_message = f"{color}{message}{reset}"
        timestamp = datetime.datetime.now().strftime("%H:%M:%S")

        self.logger.log(level, f"[{timestamp}] {level_str} : {colored_message if self.color_enabled else message}")

    def debug(self, msg): self.log(logging.DEBUG, msg)
    def info(self, msg): self.log(logging.INFO, msg)
    def warning(self, msg): self.log(logging.WARNING, msg)
    def error(self, msg): self.log(logging.ERROR, msg)
    def critical(self, msg): self.log(logging.CRITICAL, msg)

    def disable_color(self):
        self.color_enabled = False

    def enable_color(self):
        self.color_enabled = True

logger = ColorLogger("BUILD")
