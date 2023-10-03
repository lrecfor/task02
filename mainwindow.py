from PyQt6.QtWidgets import *
from PyQt6 import QtCore, QtGui
from PyQt6.QtWidgets import QMainWindow, QWidget, QVBoxLayout, \
    QHBoxLayout, QComboBox, QPushButton, QScrollArea, QLineEdit, QTextEdit
from PyQt6.QtCore import Qt, QEvent, QPoint, QPointF, QCoreApplication
from PyQt6.QtGui import QMouseEvent, QPointingDevice, QShortcut, QKeySequence
from utils import HostNotSpecifiedException, ScanTypeNotSpecifiedException


class MainWindow(QMainWindow):
    def __init__(self):
        QMainWindow.__init__(self, parent=None)

        super().__init__()

        self.host_edit = QLineEdit(self)
        self.scan_type_edit = QComboBox(self)
        self.submit_button = QPushButton("Submit", self)
        self.output_edit = QTextEdit(self)

        self.submit_button.clicked.connect(self.start_scan)
        self.host_edit.returnPressed.connect(self.submit_button.click)
        shortcut = QShortcut(QKeySequence(Qt.Key.Key_Return), self)
        shortcut.activated.connect(self.submit_button.click)

        self.host_edit.setPlaceholderText("Enter host")
        self.scan_type_edit.addItems(["TCP", "UDP"])
        self.output_edit.setReadOnly(True)
        self.output_edit.setPlaceholderText("Output")
        self.output_edit.setVerticalScrollBarPolicy(QtCore.Qt.ScrollBarPolicy.ScrollBarAlwaysOn)
        self.output_edit.setHorizontalScrollBarPolicy(QtCore.Qt.ScrollBarPolicy.ScrollBarAlwaysOn)
        self.output_edit.setLineWrapMode(QTextEdit.LineWrapMode.NoWrap)

        self.window = QWidget()
        self.layout = QHBoxLayout(self.window)
        self.layout.setAlignment(QtCore.Qt.AlignmentFlag.AlignCenter | QtCore.Qt.AlignmentFlag.AlignCenter)

        self.left = QVBoxLayout()
        self.left.setAlignment(QtCore.Qt.AlignmentFlag.AlignLeft | QtCore.Qt.AlignmentFlag.AlignCenter)

        self.setCentralWidget(self.window)

        self.left.addWidget(self.host_edit)
        self.left.addWidget(self.scan_type_edit)
        self.left.addWidget(self.submit_button)

        self.layout.addLayout(self.left)
        self.layout.addWidget(self.output_edit)

    def start_scan(self):
        try:
            host = self.host_edit.text()
            if host == "":
                raise HostNotSpecifiedException()
            scan_type = self.scan_type_edit.currentText()
        except HostNotSpecifiedException:
            self.output_result("Host is not specified")
            return
        self.output_result(str(host + '\n' + scan_type))

    def output_result(self, text):
        self.output_edit.setText(text)
