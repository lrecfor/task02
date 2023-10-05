from PyQt6 import QtCore, QtGui
from PyQt6.QtWidgets import QMainWindow, QWidget, QVBoxLayout, \
    QHBoxLayout, QComboBox, QPushButton, QLineEdit, QTextEdit
from PyQt6.QtCore import Qt
from PyQt6.QtGui import QShortcut, QKeySequence
from utils import HostNotSpecifiedException, ScanErrorException
import scanner
import database as db
from database import Scan


class MainWindow(QMainWindow):
    def __init__(self):
        QMainWindow.__init__(self, parent=None)

        super().__init__()

        self.host_edit = QLineEdit(self)
        self.scan_type_cb = QComboBox(self)
        self.submit_button = QPushButton("Submit", self)
        self.output_edit = QTextEdit(self)

        self.submit_button.clicked.connect(self.start_scan)
        self.host_edit.returnPressed.connect(self.submit_button.click)
        shortcut = QShortcut(QKeySequence(Qt.Key.Key_Return), self)
        shortcut.activated.connect(self.submit_button.click)

        self.host_edit.setPlaceholderText("Enter host")
        self.scan_type_cb.addItems(["TCP", "UDP", "FIN", "SYN"])
        self.output_edit.setReadOnly(True)
        self.output_edit.setPlaceholderText("Output")
        self.output_edit.setVerticalScrollBarPolicy(QtCore.Qt.ScrollBarPolicy.ScrollBarAlwaysOn)
        self.output_edit.setHorizontalScrollBarPolicy(QtCore.Qt.ScrollBarPolicy.ScrollBarAlwaysOn)
        self.output_edit.setLineWrapMode(QTextEdit.LineWrapMode.NoWrap)

        font = QtGui.QFont()
        font.setPointSize(14)
        self.output_edit.setFont(font)
        self.host_edit.setFont(font)
        self.submit_button.setFont(font)
        self.scan_type_cb.setFont(font)

        self.window = QWidget()
        self.layout = QHBoxLayout(self.window)
        self.layout.setAlignment(QtCore.Qt.AlignmentFlag.AlignCenter | QtCore.Qt.AlignmentFlag.AlignCenter)

        self.left = QVBoxLayout()
        self.left.setAlignment(QtCore.Qt.AlignmentFlag.AlignLeft | QtCore.Qt.AlignmentFlag.AlignCenter)

        self.setCentralWidget(self.window)

        self.left.addWidget(self.host_edit)
        self.left.addWidget(self.scan_type_cb)
        self.left.addWidget(self.submit_button)

        self.layout.addLayout(self.left)
        self.layout.addWidget(self.output_edit)

    def start_scan(self):
        try:
            host = self.host_edit.text()
            if host == "":
                raise HostNotSpecifiedException()
            scan_type = self.scan_type_cb.currentText()
        except HostNotSpecifiedException:
            self.output_result("Host is not specified")
            return

        ports = None
        try:
            if scan_type == "TCP":
                ports = scanner.tcp_scan(host)
            elif scan_type == "UDP":
                ports = scanner.udp_scan(host)
            elif scan_type == "FIN":
                ports = scanner.fin_scan(host)
            elif scan_type == "SYN":
                ports = scanner.syn_scan(host)

            self.output_result("PORT\t\tSTATUS\n" + ports)
            # db.add(Scan(host=host, ports=ports))
        except ScanErrorException as e:
            self.output_result("Error occurred")
            # db.add(Scan(host=host, ports=ports))

    def output_result(self, text):
        self.output_edit.setText(text)
