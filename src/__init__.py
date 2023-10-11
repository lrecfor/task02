from . import scanner
from . import database
from . import mainwindow
from . import utils
from . import config
from . import main

DB_PATH = "/src/scan_results.db"

__doc__ = "Проект сканирования портов с использованием GTK и базы данных."


class MainWindow(mainwindow.MainWindow):
    pass


class Scanner(scanner.Scanner):
    pass


class HostNotSpecifiedException(utils.HostNotSpecifiedException):
    pass


class ScanErrorException(utils.ScanErrorException):
    pass


class CustomPortsNotSpecifiedException(utils.CustomPortsNotSpecifiedException):
    pass
