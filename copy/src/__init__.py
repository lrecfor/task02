from . import scanner
from . import database
from . import mainwindow
from . import utils
from . import config
from . import main

DB_PATH = "/src/scans.db"

__doc__ = "Проект сканирования портов с использованием GTK и базы данных."


class MainWindow(mainwindow.MainWindow):
    """Class for the main window of the application."""


class Scanner(scanner.Scanner):
    """Class for scanner functions."""


class HostNotSpecifiedException(Exception):
    """Class for exceptions when host is not specified."""


class ScanErrorException(Exception):
    """Class for exceptions when scan fails."""


class CustomPortsNotSpecifiedException(Exception):
    """Class for exceptions when custom ports are not specified."""


class HostInputErrorException(Exception):
    """Class for exceptions when host string is not specified properly."""
