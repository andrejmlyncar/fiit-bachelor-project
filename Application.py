# system

import os
import sys
import datetime
import time
import logging
import threading
# custom
import config   
from FileLoader import FileLoader
import CustomLogger
import DatabaseConnection
from MetricsHandler import MetricsComputer
from BlockingUtils import UserBlocker, AddressBlocker


class CoreApplication(object):
  
    def __init__(self):
        self.iterator = True
        self.logger = logging.getLogger('SecurityMetricIDS')
        self.__is_file_valid(config.logname)
        self.__log_loader = FileLoader()

    def start_core(self):
        core_app = threading.Thread(target=self.__start_core_thread, args=())
        core_app.daemon = True
        core_app.start()

    def __is_file_valid(self, filename):
        if not os.path.exists(filename):
            try:
                raise Exception("""Process terminated at {}. Selected path of logging file is not valid.
                 Please specify correct authentication log path.""".format(datetime.datetime.now()))
            except Exception as err:
                self.logger.error(err)
                sys.exit(1)
        else:
            self.logger.info("File validation successful, file {} is available".format(filename))

    def __start_core_thread(self):
        self.logger.info("Starting core of the application")
        self.iterator = True

        metrics_computer = MetricsComputer()
        last_modified_config = os.stat('config.py').st_mtime
        reload(config)
        while self.iterator:
            self.logger.info("New analyse iteration started.")
            self.__log_loader.read_file()
            metrics_computer.compute_metrics()
            time.sleep(config.analyse_time*60)
            if not last_modified_config == os.stat('config.py').st_mtime:
                self.logger.info("Config file was changed. Reloading config.")
                last_modified_config = os.stat('config.py').st_mtime
                reload(config)
        self.logger.info("Reading log data finished.")
        return


class UserInterface(object):

    def __init__(self):
        self.logger = CustomLogger.setup_logger(config.outlog)
        DatabaseConnection.check_database()
        self.start_unblocking()

    def start_unblocking(self):
        unblocking_thread = threading.Thread(target=self.__start_unblocking_thread, args=())
        unblocking_thread.daemon = True
        unblocking_thread.start()

    def __start_unblocking_thread(self):
        self.logger.info("Starting user and IP address unblocking daemon.")
        cursor = DatabaseConnection.init_db_connection().cursor()
        user_blocker = UserBlocker()
        address_blocker = AddressBlocker()
        while True:
            # self.logger.info("Executing unblocking iteration")
            cursor.execute("Select blockingAccount.id, username from blockingAccount "
                           "join user on user.id = blockingAccount.user_id "
                           "where date_unblocked < NOW() and status='blocked'")
            output = cursor.fetchall()
            for item in output:
                user_blocker.unblock_user(item[1], item[0])

            cursor.execute("Select blockingAddress.id, ip_address from blockingAddress "
                           "join address on address.id = blockingAddress.ip_address_id "
                           "where date_unblocked < NOW() and status='blocked'")
            output = cursor.fetchall()
            for item in output:
                address_blocker.unblock_address(item[1], item[0])

            time.sleep(15)



