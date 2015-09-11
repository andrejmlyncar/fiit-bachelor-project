from gi.repository import Gtk, Gdk, GObject
import sys
from Application import CoreApplication, UserInterface
import fileinput
import DatabaseConnection
import time
import threading
import config
import matplotlib.pyplot as plt
from matplotlib.backends.backend_gtk3agg import FigureCanvasGTK3Agg as FigureCanvas


class GuiMain(Gtk.Window, UserInterface):

    def __init__(self):
        UserInterface.__init__(self)
        self.core = None
        self.settings_window = Gtk.Window()
        self.stats_window = None
        self.__define_settings_window()
        super(GuiMain, self).__init__()
        self.connect("destroy", self.__on_stop_click)
        self.set_size_request(850, 750)
        self.set_title("Bachelor thesis log analyser")
        self.set_resizable(False)
        self.btn1 = Gtk.Button("Start core")
        self.btn1.set_tooltip_text("Core of application will start. "
                                   "Application will perform log analysis "
                                   "and detection of possible intrusions.")
        self.btn1.connect("clicked", self.__on_start_click)
        self.btn1.set_size_request(150, 40)

        self.btn2 = Gtk.Button("Exit Program")
        self.btn2.set_size_request(150, 40)
        self.btn2.set_tooltip_text("Safely terminates program.")
        self.btn2.connect("clicked", self.__on_stop_click)

        self.btn3 = Gtk.Button("Setup config")
        self.btn3.set_size_request(150, 40)
        self.btn3.set_tooltip_text("Opens setup window where you can setup config settings of application.")
        self.btn3.connect("clicked", self.__show_settings_window)

        self.btn4 = Gtk.Button("Stop core")
        self.btn4.set_size_request(150, 40)
        self.btn4.set_tooltip_text("Stops core of application.")
        self.btn4.connect("clicked", self.__on_core_stop_click)
        self.btn4.set_sensitive(False)

        self.btn5 = Gtk.Button("Display statistics")
        self.btn5.set_size_request(150, 40)
        self.btn5.set_tooltip_text("Displays additional statistics of the application.")
        self.btn5.connect("clicked", self.__on_stats_click)

        vertical_first_lvl_container = Gtk.VBox(False, 8)
        scroll_first_lvl_window = Gtk.ScrolledWindow()
        vertical_first_lvl_container.pack_start(scroll_first_lvl_window, True, True, 0)
        store = self.create_anomaly_model(1)
        self.first_lvl_view = Gtk.TreeView(store)
        self.first_lvl_view.set_rules_hint(True)
        scroll_first_lvl_window.add(self.first_lvl_view)
        self.create_anomaly_columns(self.first_lvl_view)
        vertical_first_lvl_container.set_size_request(800, 180)

        vertical_second_lvl_container = Gtk.VBox(False, 8)
        scroll_second_lvl_window = Gtk.ScrolledWindow()
        vertical_second_lvl_container.pack_start(scroll_second_lvl_window, True, True, 0)
        store = self.create_anomaly_model(2)
        self.second_lvl_view = Gtk.TreeView(store)
        self.second_lvl_view.set_rules_hint(True)
        scroll_second_lvl_window.add(self.second_lvl_view)
        self.create_anomaly_columns(self.second_lvl_view)
        vertical_second_lvl_container.set_size_request(800, 180)

        vertical_third_lvl_container = Gtk.VBox(False, 8)
        scroll_third_lvl_window = Gtk.ScrolledWindow()
        vertical_third_lvl_container.pack_start(scroll_third_lvl_window, True, True, 0)
        store = self.create_anomaly_model(3)
        self.third_lvl_view = Gtk.TreeView(store)
        self.third_lvl_view.set_rules_hint(True)
        scroll_third_lvl_window.add(self.third_lvl_view)
        self.create_anomaly_columns(self.third_lvl_view)
        vertical_third_lvl_container.set_size_request(800, 180)

        self.main_label1 = Gtk.Label("Critical level anomalies:")
        self.main_label2 = Gtk.Label("Medium level anomalies:")
        self.main_label3 = Gtk.Label("Low level anomalies:")
        location = Gtk.Fixed()
        location.put(self.btn1, 10, 10)
        location.put(self.btn2, 650, 10)
        location.put(self.btn3, 330, 10)
        location.put(self.btn4, 170, 10)
        location.put(self.btn5, 490, 10)
        location.put(vertical_first_lvl_container, 25, 540)
        location.put(vertical_second_lvl_container, 25, 310)
        location.put(vertical_third_lvl_container, 25, 80)
        location.put(self.main_label1, 25, 60)
        location.put(self.main_label2, 25, 290)
        location.put(self.main_label3, 25, 520)

        self.add(location)
        self.show_all()
        refresh_thread = threading.Thread(target=self.__reload_tables, args=())
        refresh_thread.daemon = True
        refresh_thread.start()

    def create_anomaly_model(self, level):
        store = Gtk.ListStore(str, str, str, str, str, str)
        connection = DatabaseConnection.init_db_connection()
        cursor = connection.cursor()
        cursor.execute("select username, fail_count, success_count, "
                       "value, dateOccurred_from, dateOccurred_to "
                       "from anomaly join userData on userData.id = anomaly.data_id "
                       "join user on user.id = userData.user_id "
                       "where type=1 and level_id = {}".format(level))
        output = cursor.fetchall()

        cursor.execute("select ip_address, fail_count, success_count, "
                       "value, dateOccurred_from, dateOccurred_to "
                       "from anomaly join addressData on addressData.id = anomaly.data_id "
                       "join address on address.id = addressData.ip_address_id "
                       "where type=2 and level_id = {}".format(level))
        output += cursor.fetchall()
        for item in output:
            store.append([str(item[0]), str(item[1]), str(item[2]), str(item[3]), str(item[4]), str(item[5])])
        return store

    @staticmethod
    def __create_column(view, column_id, text):
        renderer_text = Gtk.CellRendererText()
        column = Gtk.TreeViewColumn(text, renderer_text, text=column_id)
        column.set_sort_column_id(column_id)
        view.append_column(column)

    def create_anomaly_columns(self, view):
        self. __create_column(view, 0, "username/ip address")
        self.__create_column(view, 1, "fail count")
        self.__create_column(view, 2, "success count")
        self.__create_column(view, 3, "value")
        self.__create_column(view, 4, "date from")
        self.__create_column(view, 5, "date to")

    def __define_settings_window(self):
        self.settings_window.set_size_request(800, 630)
        self.settings_window.connect("destroy", Gtk.main_quit)
        self.settings_window.set_resizable(False)
        self.settings_window.set_title("Settings configuration")

        location = Gtk.Fixed()

        self.apply_btn = Gtk.Button("Apply settings")
        self.apply_btn.set_size_request(150, 40)
        self.apply_btn.set_tooltip_text("Apply changes.")
        self.apply_btn.connect("clicked", self.__apply_settings_action)

        self.cancel_btn = Gtk.Button("Cancel")
        self.cancel_btn.set_size_request(150, 40)
        self.cancel_btn.set_tooltip_text("Cancel changes.")
        self.cancel_btn.connect("clicked", self.__cancel_settings_action)

        self.logname_entry = Gtk.Entry()
        self.logname_label = Gtk.Label("Logname path:")
        self.logname_entry.set_size_request(250, 30)
        self.time_entry = Gtk.Entry()
        self.time_label = Gtk.Label("Interval of log analysis (in minutes):")
        self.time_entry.set_size_request(250, 30)
        self.first_lvl_entry = Gtk.Entry()
        self.first_lvl_label = Gtk.Label("Max value of first security level:")
        self.first_lvl_entry.set_size_request(250, 30)
        self.second_lvl_entry = Gtk.Entry()
        self.second_lvl_label = Gtk.Label("Max value of second security level:")
        self.second_lvl_entry.set_size_request(250, 30)
        self.third_lvl_entry = Gtk.Entry()
        self.third_lvl_label = Gtk.Label("Max value of third security level:")
        self.third_lvl_entry.set_size_request(250, 30)
        self.emails_entry = Gtk.Entry()
        self.emails_label = Gtk.Label("Email notification will be sent to:")
        self.emails_entry.set_size_request(250, 30)
        self.outlog_entry = Gtk.Entry()
        self.outlog_label = Gtk.Label("Path of output log file:")
        self.outlog_entry.set_size_request(250, 30)
        self.outmail_entry = Gtk.Entry()
        self.outmail_label = Gtk.Label("Email address of outgoing mail:")
        self.outmail_entry.set_size_request(250, 30)
        self.mailserver_entry = Gtk.Entry()
        self.mailserver_label = Gtk.Label("Mail server address:")
        self.mailserver_entry.set_size_request(250, 30)
        self.mailserver_port_entry = Gtk.Entry()
        self.mailserver_port_label = Gtk.Label("Mail server port:")
        self.mailserver_port_entry.set_size_request(250, 30)
        self.mailserver_password_entry = Gtk.Entry()
        self.mailserver_password_entry.set_visibility(False)
        self.mailserver_password_label = Gtk.Label("Mail server password:")
        self.mailserver_password_entry.set_size_request(250, 30)
        self.alert_group_entry = Gtk.Entry()
        self.alert_group_label = Gtk.Label("Alert will be sent to group:")
        self.alert_group_entry.set_size_request(250, 30)
        self.database_connection_entry = Gtk.Entry()
        self.database_connection_label = Gtk.Label("Database server address:")
        self.database_connection_entry.set_size_request(250, 30)
        self.database_name_entry = Gtk.Entry()
        self.database_name_label = Gtk.Label("Database name:")
        self.database_name_entry.set_size_request(250, 30)
        self.database_user_entry = Gtk.Entry()
        self.database_user_label = Gtk.Label("Database username:")
        self.database_user_entry.set_size_request(250, 30)
        self.database_password_entry = Gtk.Entry()
        self.database_password_label = Gtk.Label("Database password:")
        self.database_password_entry.set_visibility(False)
        self.database_password_entry.set_size_request(250, 30)
        self.trim_time_entry = Gtk.Entry()
        self.trim_time_label = Gtk.Label("Metrics time intervals (in minutes):")
        self.trim_time_entry.set_size_request(250, 30)
        self.ip_blocking_time_entry = Gtk.Entry()
        self.ip_blocking_time_label = Gtk.Label("Address blocking time (in minutes)")
        self.ip_blocking_time_entry.set_size_request(250, 30)
        self.user_blocking_time_entry = Gtk.Entry()
        self.user_blocking_time_label = Gtk.Label("User blocking time (in minutes)")
        self.user_blocking_time_entry.set_size_request(250, 30)

        self.console_logging_check = Gtk.CheckButton(label="Console logging enabled:", use_underline=True)
        self.email_notification_check = Gtk.CheckButton(label="Email notification enabled:", use_underline=True)
        self.terminal_notification_check = Gtk.CheckButton(label="Terminal notification enabled:", use_underline=True)
        self.gui_mode_check = Gtk.CheckButton(label="Gui mode enabled:", use_underline=True)
        self.address_blocking_check = Gtk.CheckButton(label="User blocking enabled:", use_underline=True)
        self.user_blocking_check = Gtk.CheckButton(label="User blocking enabled:", use_underline=True)

        location.put(self.apply_btn, 470, 580)
        location.put(self.cancel_btn, 630, 580)
        location.put(self.logname_label, 40, 20)
        location.put(self.logname_entry, 40, 40)
        location.put(self.time_entry, 40, 90)
        location.put(self.time_label, 40, 70)
        location.put(self.first_lvl_entry, 40, 140)
        location.put(self.first_lvl_label, 40, 120)
        location.put(self.second_lvl_entry, 40, 190)
        location.put(self.second_lvl_label, 40, 170)
        location.put(self.third_lvl_entry, 40, 240)
        location.put(self.third_lvl_label, 40, 220)
        location.put(self.emails_entry, 40, 290)
        location.put(self.emails_label, 40, 270)
        location.put(self.outlog_entry, 40, 340)
        location.put(self.outlog_label, 40, 320)
        location.put(self.trim_time_entry,  40, 390)
        location.put(self.trim_time_label, 40, 370)
        location.put(self.user_blocking_time_entry, 40, 440)
        location.put(self.user_blocking_time_label, 40, 420)

        location.put(self.outmail_label, 440, 20)
        location.put(self.outmail_entry, 440, 40)
        location.put(self.mailserver_entry, 440, 90)
        location.put(self.mailserver_label, 440, 70)
        location.put(self.mailserver_port_entry, 440, 140)
        location.put(self.mailserver_port_label, 440, 120)
        location.put(self.mailserver_password_entry, 440, 190)
        location.put(self.mailserver_password_label, 440, 170)
        location.put(self.alert_group_entry, 440, 240)
        location.put(self.alert_group_label, 440, 220)
        location.put(self.database_connection_entry, 440, 290)
        location.put(self.database_connection_label, 440, 270)
        location.put(self.database_name_entry, 440, 340)
        location.put(self.database_name_label, 440, 320)
        location.put(self.database_user_entry, 440, 390)
        location.put(self.database_user_label, 440, 370)
        location.put(self.database_password_entry, 440, 440)
        location.put(self.database_password_label, 440, 420)
        location.put(self.ip_blocking_time_entry, 440, 490)
        location.put(self.ip_blocking_time_label, 440, 470)

        location.put(self.console_logging_check, 40, 550)
        location.put(self.email_notification_check, 40, 570)
        location.put(self.terminal_notification_check, 40, 590)
        location.put(self.gui_mode_check, 40, 490)
        location.put(self.address_blocking_check, 40, 510)
        location.put(self.user_blocking_check, 40, 530)

        self.settings_window.add(location)

    def main(self):
        GObject.threads_init()
        Gtk.main()

    def __on_core_stop_click(self, widget):
        self.core.iterator = False
        self.btn1.set_sensitive(True)
        self.btn4.set_sensitive(False)

    def __on_stop_click(self, widget):
        Gtk.main_quit()
        self.logger.info("Shutting down application")
        sys.exit("Application terminated successfully")

    def __on_start_click(self, widget):
        if self.core:
            self.logger.info("Using existing core application instance.")
        else:
            self.core = CoreApplication()
            self.logger.info("Creating new core application instance.")
        self.core.start_core()
        self.btn1.set_sensitive(False)
        self.btn4.set_sensitive(True)

    def __show_settings_window(self, widget):
        self.hide()
        self.__settings_insert_data()
        self.settings_window.show_all()

    def __apply_settings_action(self, widget):
        self.__update_config_file()
        self.settings_window.hide()
        self.show()

    def __cancel_settings_action(self, widget):
        self.settings_window.hide()
        self.show()

    def __settings_insert_data(self):
        reload(config)
        self.logname_entry.set_text(config.logname)
        self.time_entry.set_text(str(config.analyse_time))
        self.first_lvl_entry.set_text(str(config.first_level_val))
        self.second_lvl_entry.set_text(str(config.second_level_val))
        self.third_lvl_entry.set_text(str(config.third_level_val))
        self.emails_entry.set_text(', '.join(config.emails))
        self.outlog_entry.set_text(config.outlog)
        self.outmail_entry.set_text(config.outmail)
        self.mailserver_entry.set_text(config.mailServerName)
        self.mailserver_port_entry.set_text(str(config.mailServerPort))
        self.mailserver_password_entry.set_text(config.password)
        self.alert_group_entry.set_text(config.alert_group)
        self.database_connection_entry.set_text(config.db_connection)
        self.database_name_entry.set_text(config.db_name)
        self.database_user_entry.set_text(config.db_user)
        self.database_password_entry.set_text(config.db_pass)
        self.trim_time_entry.set_text(str(config.trim_time))
        self.ip_blocking_time_entry.set_text(str(config.address_blocking_time))
        self.user_blocking_time_entry.set_text(str(config.user_blocking_time))

        self.console_logging_check.set_active(config.console_log)
        self.email_notification_check.set_active(config.email_notification)
        self.terminal_notification_check.set_active(config.terminal_notification)
        self.gui_mode_check.set_active(config.gui_mode)
        self.user_blocking_check.set_active(config.user_blocking_enabled)
        self.address_blocking_check.set_active(config.address_blocking_enabled)

    def __update_config_file(self):
        for line in fileinput.input('config.py', inplace=True):
            changed = 0
            changed += self.__change_config_variable(self.logname_entry.get_text(), 'logname', line, 'str')
            changed += self.__change_config_variable(self.time_entry.get_text(), 'analyse_time', line, 'int')
            changed += self.__change_config_variable(self.first_lvl_entry.get_text(), 'first_level_val', line, 'int')
            changed += self.__change_config_variable(self.second_lvl_entry.get_text(), 'second_level_val', line,  'int')
            changed += self.__change_config_variable(self.third_lvl_entry.get_text(), 'third_level_val', line,  'int')
            changed += self.__change_config_variable(self.outlog_entry.get_text(), 'outlog', line, 'str')
            changed += self.__change_config_variable(self.outmail_entry.get_text(), 'outmail', line, 'str')
            changed += self.__change_config_variable(self.mailserver_entry.get_text(), 'mailServerName', line,  'str')
            changed += self.__change_config_variable(self.mailserver_port_entry.get_text(), 'mailServerPort', line,  'int')
            changed += self.__change_config_variable(self.mailserver_password_entry.get_text(), 'password', line,  'str')
            changed += self.__change_config_variable(self.alert_group_entry.get_text(), 'alert_group', line, 'str')
            changed += self.__change_config_variable(self.database_connection_entry.get_text(), 'db_connection', line, 'str')
            changed += self.__change_config_variable(self.database_name_entry.get_text(), 'db_name', line, 'str')
            changed += self.__change_config_variable(self.database_user_entry.get_text(), 'db_user', line, 'str')
            changed += self.__change_config_variable(self.database_password_entry.get_text(), 'db_pass', line, 'str')
            changed += self.__change_config_variable(self.trim_time_entry.get_text(), 'trim_time', line, 'int')
            changed += self.__change_config_variable(self.gui_mode_check.get_active(), 'gui_mode', line, 'int')
            changed += self.__change_config_variable(self.email_notification_check.get_active(), 'email_notification', line, 'int')
            changed += self.__change_config_variable(self.terminal_notification_check.get_active(), 'terminal_notification', line, 'int')
            changed += self.__change_config_variable(self.console_logging_check.get_active(), 'console_log', line, 'int')
            changed += self.__change_config_variable(self.emails_entry.get_text(), 'emails', line, 'list')

            changed += self.__change_config_variable(self.ip_blocking_time_entry.get_text(), 'address_blocking_time', line, 'int')
            changed += self.__change_config_variable(self.user_blocking_time_entry.get_text(), 'user_blocking_time', line, 'int')
            changed += self.__change_config_variable(self.address_blocking_check.get_active(), 'address_blocking_enabled', line, 'int')
            changed += self.__change_config_variable(self.user_blocking_check.get_active(), 'user_blocking_enabled', line, 'int')
            if changed == 0:
                print (line),

    def __change_config_variable(self, entry_val, entry, line, var_type):
        if entry in line and ('#' not in line):
            if var_type == 'str':
                print (line.replace(line, "{} = '{}'".format(entry, entry_val)))
            elif var_type == 'int':
                print (line.replace(line, "{} = {}".format(entry, entry_val)))
            else:
                print (line.replace(line, "{} = {}".format(entry, entry_val.split(', '))))
            return 1
        else:
            return 0

    def __load_tables(self, widget):
        self.anomaly_view.set_model(self.create_anomaly_model())

    def __reload_tables(self):
        while True:
            time.sleep(config.analyse_time * 60)
            model = self.third_lvl_view.get_model()
            self.first_lvl_view.set_model(self.create_anomaly_model(1))
            self.second_lvl_view.set_model(self.create_anomaly_model(2))
            self.third_lvl_view.set_model(self.create_anomaly_model(3))
            if len(model) != len(self.third_lvl_view.get_model()):
                GObject.idle_add(self.__show_warning_window)

    def __on_stats_click(self, widget):
        self.__define_statistics_window()
        self.__stats_insert_data()
        self.stats_window.show_all()
        self.btn5.set_sensitive(False)

    def __define_statistics_window(self):
        self.stats_window = Gtk.Window()
        self.stats_window.set_size_request(800, 860)
        background_color = Gdk.color_parse('#bfbfbf')
        self.stats_window.modify_bg(Gtk.StateType.NORMAL, background_color)
        self.stats_window.connect("destroy", self.__on_close_stats)
        self.stats_window.set_resizable(False)
        self.stats_window.set_title("Statistics information")

        self.close_btn = Gtk.Button("Close")
        self.close_btn.set_size_request(150, 40)
        self.close_btn.set_tooltip_text("Close this window.")
        self.close_btn.connect("clicked", self.__on_close_stats)

        self.stats_label1 = Gtk.Label()
        self.stats_label2 = Gtk.Label()
        self.stats_label3 = Gtk.Label()
        self.stats_label4 = Gtk.Label()
        self.stats_label5 = Gtk.Label()
        self.stats_label6 = Gtk.Label()
        self.stats_label7 = Gtk.Label()
        self.stats_label8 = Gtk.Label()

        graph_container1 = Gtk.VBox(False, 8)
        scroll_window1 = Gtk.ScrolledWindow()
        graph_container1.pack_start(scroll_window1, True, True, 0)
        graph_container1.set_size_request(800, 220)
        figure1 = plt.figure(figsize=[0.7, 0.7])
        axis1 = figure1.add_subplot(111)
        connection = DatabaseConnection.init_db_connection()
        cursor = connection.cursor()
        cursor.execute("SELECT count(*) from anomaly where level_id = 3")
        third_lvl_count = cursor.fetchone()
        cursor.execute("SELECT count(*) from anomaly where level_id = 2")
        second_lvl_count = cursor.fetchone()
        cursor.execute("SELECT count(*) from anomaly where level_id = 1")
        first_lvl_count = cursor.fetchone()

        labels = 'Critical level anomalies: {}'.format(int(third_lvl_count[0])),\
                 'Medium level anomalies: {}'.format(int(second_lvl_count[0])), \
                 'Low level anomalies: {}'.format(int(first_lvl_count[0]))
        sizes = [int(third_lvl_count[0]), int(second_lvl_count[0]), int(first_lvl_count[0])]
        colors = ['red', 'orange', 'yellow']
        explode = (0.03, 0.03, 0.03)
        axis1.pie(sizes, explode=explode, labels=labels, colors=colors, shadow=True, startangle=10)
        axis1.set_title("Graphical view of detected anomalies")
        axis1.axis('equal')
        axis1.plot()
        canvas2 = FigureCanvas(figure1)
        scroll_window1.add_with_viewport(canvas2)

        graph_container2 = Gtk.VBox(False, 8)
        scroll_window2 = Gtk.ScrolledWindow()
        graph_container2.pack_start(scroll_window2, True, True, 0)
        graph_container2.set_size_request(800, 400)
        figure2 = plt.figure(figsize=[0.6, 0.6])
        axis2 = figure2.add_subplot(211)
        axis2.set_title("Graphical view of logging process in time.\n Red = Failed logins. Green = Successful logins.")
        cursor.execute(" select concat(concat(dateOccurred_from, ' - '), time_format(dateOccurred_to,'%H:%i'))"
                       " as Time, sum(success_count), sum(fail_count) from userData where dateOccurred_from is not NULL "
                       " group by dateOccurred_from order by dateOccurred_from ")
        output = cursor.fetchall()
        dates = [(r[0]) for r in output]
        success_values = [int(r[1]) for r in output]
        fail_values = [int(r[2]) for r in output]

        x = range(len(dates))
        # use number instead of dates in case of too many x values
        if len(x) < 30:
            axis2.set_xticks(x)
            axis2.set_xticklabels(dates, rotation=50)
        axis2.set_ylabel("Number of login procedures", rotation='vertical')
        axis2.set_xlabel("Date and time", rotation='horizontal')
        axis2.plot(x, success_values, "yo-")
        axis2.plot(x, fail_values, "r.-")
        canvas2 = FigureCanvas(figure2)
        scroll_window2.add_with_viewport(canvas2)

        location = Gtk.Fixed()
        location.put(self.close_btn, 630, 810)
        location.put(self.stats_label1, 10, 20)
        location.put(self.stats_label2, 10, 40)
        location.put(self.stats_label3, 10, 60)
        location.put(self.stats_label4, 10, 80)
        location.put(self.stats_label5, 10, 100)
        location.put(self.stats_label6, 10, 120)
        location.put(self.stats_label7, 10, 140)
        location.put(self.stats_label8, 10, 160)
        location.put(graph_container1, 10, 190)
        location.put(graph_container2, 30, 410)
        self.stats_window.add(location)

    def __on_close_stats(self, widget):
        self.stats_window.hide()
        self.btn5.set_sensitive(True)

    def __stats_insert_data(self):

        connection = DatabaseConnection.init_db_connection()
        cursor = connection.cursor()

        cursor.execute("SELECT count(*) from user")
        result = cursor.fetchone()
        self.stats_label1.set_text("Total number of users logged during running of application: {}"
                                   .format(int(result[0])))

        cursor.execute("SELECT count(*) from address")
        result = cursor.fetchone()
        self.stats_label2.set_text("Total number of IP addresses used for login to system: {}"
                                   .format(int(result[0])))

        cursor.execute("SELECT SUM(success_count) from userData")
        result = cursor.fetchone()
        self.stats_label3.set_text("Total number of successful logins to system: {}"
                                   .format(int(result[0])))

        cursor.execute("SELECT SUM(fail_count) from userData")
        result = cursor.fetchone()
        self.stats_label4.set_text("Total number of failed logins to system: {}"
                                   .format(int(result[0])))

        cursor.execute("SELECT count(*) from anomaly")
        result = cursor.fetchone()
        self.stats_label5.set_text("Total number of detected anomalies: {}"
                                   .format(int(result[0])))

        cursor.execute("SELECT sum(success_count+fail_count) from userData")
        result = cursor.fetchone()
        self.stats_label6.set_text("Total number of analysed log records: {}"
                                   .format(int(result[0])))

        cursor.execute("SELECT count(*) from blockingAccount where status='blocked'")
        result = cursor.fetchone()
        self.stats_label7.set_text("Number of blocked user accounts: {}"
                                   .format(int(result[0])))

        cursor.execute("SELECT count(*) from blockingAddress where status='blocked'")
        result = cursor.fetchone()
        self.stats_label8.set_text("Number of blocked IP addresses: {}"
                                   .format(int(result[0])))

    def __show_warning_window(self):
        dialog = Gtk.MessageDialog(self, 0, Gtk.MessageType.WARNING,
                                   Gtk.ButtonsType.OK, "NEW CRITICAL ANOMALIES DETECTED!")
        dialog.format_secondary_text(
            "Please consider make some actions to prevent gaining unauthorised access to this system.")
        dialog.run()
        dialog.destroy()

