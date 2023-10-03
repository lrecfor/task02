from PyQt6.QtWidgets import QApplication
from mainwindow import MainWindow
import sys


if __name__ == '__main__':
    app = QApplication(sys.argv)
    main_window = MainWindow()
    main_window.show()
    main_window.setWindowTitle("Scanner")
    main_window.showMaximized()
    sys.exit(app.exec())
