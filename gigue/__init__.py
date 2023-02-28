import logging
import os
from logging.config import fileConfig

if not os.path.exists("log/"):
    os.mkdir("log/")

logging.getLogger(__name__)
fileConfig("logging.ini")
