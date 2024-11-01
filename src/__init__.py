from . import scanner
from . import mainwindow
from . import utils


__doc__ = "Проект сканирования портов с использованием GTK."


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
