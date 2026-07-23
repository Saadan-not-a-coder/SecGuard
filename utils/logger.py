#!/usr/bin/env python3
"""
Logging Utility Module
"""

import logging
import sys
from datetime import datetime

def setup_logger():
    """Configure and return a logger instance"""
    logger = logging.getLogger('SecGuard')
    logger.setLevel(logging.INFO)
    
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(logging.INFO)
    
    formatter = logging.Formatter(
        '%(asctime)s - %(levelname)s - %(message)s',
        datefmt='%H:%M:%S'
    )
    console_handler.setFormatter(formatter)
    
    logger.addHandler(console_handler)
    return logger