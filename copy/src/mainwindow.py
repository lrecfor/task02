"""Module providing the main window of the application"""

import functools
import ipaddress
from concurrent.futures import ThreadPoolExecutor
from utils import HostNotSpecifiedException, ScanErrorException, HostInputErrorException, \
    CustomPortsNotSpecifiedException, default_ports, IP_PATTERN, DOMAIN_PATTERN, ITEMS
from scanner import Scanner, ACKScanner, FINScanner, NULLScanner, SYNScanner
import database as db
import gi
import re

gi.require_version('Gtk', '3.0')
from gi.repository import Gtk, Gdk


def parse_number_string(input_string):
    """
    Parse a string of numbers separated by commas and/or hyphens.
    For example, "1,2,3,4-5,6" will return [1, 2, 3, 4, 5, 6].

    :param input_string: The string to parse.
    :return: list of numbers of string.
    """
    parts = input_string.split(',')
    numbers = []

    for part in parts:
        if '-' in part:
            start, end = map(int, part.split('-'))
            numbers.extend(range(start, end + 1))
        else:
            numbers.append(int(part.strip()))

    return numbers


def parse_host_string(input_string):
    """
    Parse a string of hosts separated by commas and/or hyphens .
    For example, "127.0.0.1, 192.168.0.2-192.168.0.4, localhost" will return [127.0.0.1,
    192.168.0.2, 192.168.0.3, 192.168.0.4].

    :param input_string: The string to parse.
    :return: list of hosts of string.
    """
    if re.match(r'^[a-zA-Zа-яА-ЯёЁ0-9.\-]+$', input_string) is None:
        raise HostInputErrorException(f"Host entered incorrectly.")

    host_list = []
    input_string = input_string.strip()
    input_string = input_string.replace(" ", "")

    input_parts = input_string.split(",")

    for part in input_parts:
        if '-' in part:
            # Range processing
            start, end = part.split('-')
            try:
                if (re.match(IP_PATTERN, start) is None or
                        re.match(IP_PATTERN, end) is None):
                    raise Exception

                start_ip = ipaddress.ip_address(start)
                end_ip = ipaddress.ip_address(end)

                if start_ip > end_ip:
                    raise Exception

                while start_ip <= end_ip:
                    host_list.append(str(start_ip))
                    start_ip += 1
            except Exception as error_text:
                raise HostInputErrorException(f"Incorrect IP range: {part}") from error_text
        elif '/' in part:
            # CIDR notation processing (subnet mask)
            try:
                network = ipaddress.ip_network(part, strict=False)
                host_list.extend(str(ip) for ip in network.hosts())
            except Exception as error_text:
                raise HostInputErrorException(f"Incorrect CIDR notation: {part}") from error_text
        else:
            # Single IP address or domain name processing
            if re.match(IP_PATTERN, part) is not None:
                host_list.append(part)
            elif part == 'localhost' or re.match(DOMAIN_PATTERN, part) is not None:
                host_list.append(part)
            else:
                raise HostInputErrorException(f"Incorrect IP address: {part}")

    return host_list


class MainWindow:
    """Class for the main window of the application."""

    def __init__(self):
        self.result = []
        self.hosts_count = 0
        self.window = Gtk.Window(title="Scanner")
        self.window.connect("delete-event", Gtk.main_quit)
        self.window.set_default_size(800, 400)

        self.host_edit = Gtk.Entry()
        self.scan_type_combo = Gtk.ComboBoxText()
        self.spinner = Gtk.Spinner()
        self.spinner.set_size_request(24, 24)

        for item in ITEMS:
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

        self.overlay = Gtk.Overlay()
        self.overlay.add(self.output_edit)
        self.overlay.add_overlay(self.spinner)

        self.output_scroll = Gtk.ScrolledWindow()
        self.output_scroll.set_policy(Gtk.PolicyType.AUTOMATIC, Gtk.PolicyType.AUTOMATIC)
        self.output_scroll.add(self.overlay)

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

        self.thread_pool = ThreadPoolExecutor(max_workers=1)

    def on_custom_toggled(self, button):
        """
        Handle custom ports toggling.

        :param button:
        :return:
        """
        self.ports_edit.set_sensitive(button.get_active())

        if not button.get_active():
            self.ports_edit.set_text(", ".join([str(i) for i in default_ports]))
        else:
            self.ports_edit.set_text("")

    def start_scan(self, widget):
        """
        Get parameters from user and start scan

        :param widget:
        :return:
        """
        try:
            hosts_string = self.host_edit.get_text()
            if not hosts_string:
                raise HostNotSpecifiedException("Host is not specified")
        except HostNotSpecifiedException as error_text:
            self.output_text(str(error_text))
            return

        self.output_text("")
        hosts = []

        try:
            hosts = parse_host_string(hosts_string)
        except HostInputErrorException as error_text:
            self.output_text(str(error_text))

        self.hosts_count = len(hosts)
        self.result = []
        for host in hosts:
            scan_type = self.scan_type_combo.get_active_text()
            try:
                if self.ports_edit.get_text() == "":
                    raise CustomPortsNotSpecifiedException("Custom ports are not specified")
            except CustomPortsNotSpecifiedException as error_text:
                self.output_text(str(error_text))
                return
            ports_ = parse_number_string(
                self.ports_edit.get_text()) if self.custom_radio.get_active() \
                else default_ports

            self.upload_toggle('start')

            future = None
            # []
            if scan_type == "ACK":
                ack_scanner = ACKScanner(host, ports_)
                future = self.thread_pool.submit(ack_scanner.ack_scan)
            elif scan_type == "FIN":
                fin_scanner = FINScanner(host, ports_)
                future = self.thread_pool.submit(fin_scanner.fin_scan)
            elif scan_type == "NULL":
                null_scanner = NULLScanner(host, ports_)
                future = self.thread_pool.submit(null_scanner.null_scan)
            elif scan_type == "SYN":
                syn_scanner = SYNScanner(host, ports_)
                future = self.thread_pool.submit(syn_scanner.syn_scan)

            future.add_done_callback(functools.partial(self.scan_processing, host=host))

    def output_text(self, text):
        """
        Output text in the output window.

        :param text: text to be outputted.
        :return:
        """
        buffer = self.output_edit.get_buffer()
        buffer.set_text(text)

    def append_text(self, text):
        """
        Append text in the output window.

        :param text: text to be added.
        :return:
        """
        buffer = self.output_edit.get_buffer()
        iter_ = buffer.get_end_iter()
        buffer.insert(iter_, text)

    def on_enter_key_pressed(self, *args):
        """
        Causes submit_button to be pressed when enter key is pressed.

        :param args:
        :return:
        """
        self.submit_button.clicked()

    def upload_toggle(self, state):
        """
        Controls the spinner widget and the sensitivity of the submit_button.

        :param state: 'start' or 'stop' depending on the state of the spinner widget.
        :return:
        """
        if state == 'start':
            self.spinner.start()
            self.submit_button.set_sensitive(False)
        elif state == 'stop':
            Gdk.threads_enter()
            self.spinner.stop()
            self.submit_button.set_sensitive(True)
            Gdk.threads_leave()

    def update_window_state(self):
        """
        Output results of scanning and update window state.
        Called when scanning is complete.

        :return:
        """
        self.upload_toggle('stop')
        self.output_text("".join(self.result))
        self.result = []

    def scan_processing(self, future, host):
        """
        Processes the scan results.

        :param future: future object returned by scanner.scan() method.
        :param host: ip address or domain name that was scanned.
        :return:
        """

        try:
            self.hosts_count -= 1
            ports_status = future.result()
            if ports_status == "":
                self.result.append("All 1000 scanned ports are in ignored states.")
                db.insert_ports(host=host, ports=[])
            else:
                self.result.append(
                    "Host: " +
                    host +
                    "\n" +
                    "PORT\t\tSTATUS\n" +
                    ports_status +
                    '\n')
                db.insert_ports(host=host, ports=ports_status)
        except ScanErrorException:
            self.result.append(
                "Host: " +
                host +
                "\n" +
                "Error: something went wrong with host " + host + "\n\n")
        if self.hosts_count == 0:
            self.update_window_state()
