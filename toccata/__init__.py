import os
from logging.config import fileConfig

if not os.path.exists("log/"):
    os.mkdir("log/")

fileConfig("logging.ini", disable_existing_loggers=False)
