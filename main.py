import gi
from mainwindow import MainWindow

gi.require_version('Gtk', '3.0')
from gi.repository import Gtk

if __name__ == "__main__":
    Gtk.init()
    MainWindow()
    Gtk.main()
