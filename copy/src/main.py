"""Module providing main function."""

import gi

gi.require_version('Gtk', '3.0')
from gi.repository import Gtk
from mainwindow import MainWindow

if __name__ == "__main__":
    Gtk.init()
    MainWindow()
    Gtk.main()
