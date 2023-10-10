import gi
gi.require_version('Gtk', '3.0')
from gi.repository import Gtk, GObject
from utils import *
import scanner


def parse_number_string(input_string):
    parts = input_string.split(',')
    numbers = []

    for part in parts:
        if '-' in part:
            start, end = map(int, part.split('-'))
            numbers.extend(range(start, end + 1))
        else:
            numbers.append(int(part.strip()))

    return numbers


class MainWindow:
    def __init__(self):
        self.window = Gtk.Window(title="Scanner")
        self.window.connect("delete-event", Gtk.main_quit)
        self.window.set_default_size(800, 400)

        self.host_edit = Gtk.Entry()
        self.scan_type_combo = Gtk.ComboBoxText()

        items = ["FIN", "SYN", "ACK"]   # ["TCP", "UDP", "FIN", "SYN", "ACK"]
        for item in items:
            self.scan_type_combo.append_text(item)

        self.scan_type_combo.set_active(0)

        self.default_radio = Gtk.RadioButton.new_with_label_from_widget(None, "Default")
        self.custom_radio = Gtk.RadioButton.new_from_widget(self.default_radio)
        self.custom_radio.set_label("Custom")

        self.custom_radio.connect("toggled", self.on_custom_toggled)

        self.submit_button = Gtk.Button(label="Submit")
        self.output_edit = Gtk.TextView()
        self.output_edit.set_editable(False)
        self.output_edit.set_wrap_mode(Gtk.WrapMode.WORD)
        self.output_edit.set_cursor_visible(False)

        self.submit_button.connect("clicked", self.start_scan)

        style_provider = Gtk.CssProvider()
        style_provider.load_from_data(b"""
            .my-font {
                font-size: 14pt;
            }
        """)

        context = self.output_edit.get_style_context()
        context.add_provider(style_provider, Gtk.STYLE_PROVIDER_PRIORITY_APPLICATION)

        self.output_scroll = Gtk.ScrolledWindow()
        self.output_scroll.set_policy(Gtk.PolicyType.AUTOMATIC, Gtk.PolicyType.AUTOMATIC)
        self.output_scroll.add(self.output_edit)

        self.main_box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        self.main_box.set_margin_start(8)
        self.window.add(self.main_box)

        self.left_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=8)
        self.left_box.set_size_request(300, -1)
        self.left_box.set_margin_top(8)
        self.main_box.pack_start(self.left_box, False, True, 0)

        self.left_box.pack_start(Gtk.Label('Host:', xalign=0.0), False, True, 0)
        self.left_box.pack_start(self.host_edit, False, True, 0)
        self.left_box.pack_start(Gtk.Label('Scan type:', xalign=0.0), False, True, 0)
        self.left_box.pack_start(self.scan_type_combo, False, True, 0)

        self.left_box.pack_start(Gtk.Label('Ports:', xalign=0.0), False, True, 0)
        self.left_box.pack_start(self.default_radio, False, True, 0)
        self.left_box.pack_start(self.custom_radio, False, True, 0)

        self.ports_edit = Gtk.Entry()
        self.ports_edit.set_text(", ".join([str(i) for i in default_ports]))
        self.left_box.pack_start(self.ports_edit, False, True, 0)
        self.ports_edit.set_sensitive(False)

        self.left_box.pack_start(self.submit_button, False, True, 0)

        self.main_box.pack_start(self.output_scroll, True, True, 0)
        self.output_edit.set_margin_top(8)
        self.output_edit.set_margin_end(8)
        self.output_edit.set_margin_bottom(8)

        self.accel_group = Gtk.AccelGroup()
        self.window.add_accel_group(self.accel_group)
        key, modifier = Gtk.accelerator_parse("Return")
        self.accel_group.connect(key, modifier, Gtk.AccelFlags.VISIBLE, self.on_enter_key_pressed)

        self.window.show_all()

    def on_custom_toggled(self, button):
        self.ports_edit.set_sensitive(button.get_active())

        if not button.get_active():
            self.ports_edit.set_text(", ".join([str(i) for i in default_ports]))
        else:
            self.ports_edit.set_text("")

    def start_scan(self, widget):
        try:
            host = self.host_edit.get_text()
            if not host:
                raise HostNotSpecifiedException("Host is not specified")
        except HostNotSpecifiedException as e:
            self.output_result(str(e))
            return

        host = host.split(', ')
        scan_type = self.scan_type_combo.get_active_text()
        ports_ = parse_number_string(self.ports_edit.get_text()) if self.custom_radio.get_active() else default_ports

        try:
            ports_status = ""
            # if scan_type == "TCP":
            #     ports_ = scanner.tcp_scan(host, ports_)
            # elif scan_type == "UDP":
            #     ports_ = scanner.udp_scan(host, ports_)
            if scan_type == "FIN":
                ports_status = scanner.fin_scan(host, ports_)
            elif scan_type == "SYN":
                ports_status = scanner.syn_scan(host, ports_)
            elif scan_type == "ACK":
                ports_status = scanner.ack_scan(host, ports_)

            if ports_status == "":
                self.output_result("All ports are filtered/closed")
            else:
                self.output_result("PORT\t\tSTATUS\n" + ports_status)
            # db.add(Scan(host=host, ports=ports))
        except ScanErrorException as e:
            self.output_result("Error occurred")

    def output_result(self, text):
        buffer = self.output_edit.get_buffer()
        buffer.set_text(text)

    def on_enter_key_pressed(self, *args):
        self.submit_button.clicked()
