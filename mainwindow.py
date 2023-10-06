import gi
gi.require_version('Gtk', '3.0')
from gi.repository import Gtk, GObject

class MainWindow:
    def __init__(self):
        self.window = Gtk.Window(title="Scanner")
        self.window.connect("delete-event", Gtk.main_quit)
        self.window.set_default_size(800, 400)

        self.host_edit = Gtk.Entry()
        self.scan_type_combo = Gtk.ComboBoxText()

        items = ["TCP", "UDP", "FIN", "SYN"]
        for item in items:
            self.scan_type_combo.append_text(item)

        self.scan_type_combo.set_active(0)

        # Создаем RadioButton для выбора между "Default" и "Custom"
        self.default_radio = Gtk.RadioButton.new_with_label_from_widget(None, "Default")
        self.custom_radio = Gtk.RadioButton.new_with_label_from_widget(self.default_radio, "Custom")

        self.custom_radio.connect("toggled", self.on_custom_toggled)

        self.submit_button = Gtk.Button(label="Submit")
        self.output_edit = Gtk.TextView()
        self.output_edit.set_editable(False)
        self.output_edit.set_wrap_mode(Gtk.WrapMode.NONE)
        self.output_edit.set_cursor_visible(True)

        self.submit_button.connect("clicked", self.start_scan)

        style_provider = Gtk.CssProvider()
        style_provider.load_from_data(b"""
            .my-font {
                font-size: 14pt;
            }
        """)

        context = self.output_edit.get_style_context()
        context.add_provider(style_provider, Gtk.STYLE_PROVIDER_PRIORITY_APPLICATION)

        self.main_box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        self.main_box.set_margin_start(8)
        self.window.add(self.main_box)

        self.left_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=8)
        self.left_box.set_size_request(300, -1)
        self.left_box.set_margin_top(8)
        self.main_box.pack_start(self.left_box, False, True, 0)

        self.left_box.pack_start(self.host_edit, False, True, 0)
        self.left_box.pack_start(self.scan_type_combo, False, True, 0)

        # Добавляем RadioButton "Default" и "Custom"
        self.left_box.pack_start(self.default_radio, False, True, 0)
        self.left_box.pack_start(self.custom_radio, False, True, 0)

        # Создаем поле ввода только для "Custom"
        self.username_entry = Gtk.Entry()
        self.left_box.pack_start(self.username_entry, False, True, 0)
        self.username_entry.set_sensitive(False)  # Изначально отключено

        self.left_box.pack_start(self.submit_button, False, True, 0)

        self.main_box.pack_start(self.output_edit, True, True, 0)
        self.output_edit.set_margin_top(8)
        self.output_edit.set_margin_end(8)
        self.output_edit.set_margin_bottom(8)

        # Создаем обработчик клавиш для приложения
        self.accel_group = Gtk.AccelGroup()
        self.window.add_accel_group(self.accel_group)
        key, modifier = Gtk.accelerator_parse("Return")  # Клавиша Enter
        self.accel_group.connect(key, modifier, Gtk.AccelFlags.VISIBLE, self.on_enter_key_pressed)

        self.window.show_all()

    def on_custom_toggled(self, button):
        # Отключаем/включаем поле ввода при переключении состояния RadioButton "Custom"
        self.username_entry.set_sensitive(button.get_active())

    def start_scan(self, widget):
        host = self.host_edit.get_text()
        scan_type = self.scan_type_combo.get_active_text()
        username = self.username_entry.get_text() if self.username_entry.get_sensitive() else ""  # Получаем текст из поля ввода только при включенном состоянии

        if not host:
            self.output_result("Host is not specified")
            return

        scan_info = f"Host: {host}\nScan Type: {scan_type}\nUsername: {username}"
        self.output_result(scan_info)

    def output_result(self, text):
        buffer = self.output_edit.get_buffer()
        buffer.set_text(text)

    def on_enter_key_pressed(self, *args):
        # Вызываем нажатие кнопки "Submit" при нажатии клавиши Enter
        self.submit_button.clicked()

if __name__ == "__main__":
    app = MainWindow()
    Gtk.main()
