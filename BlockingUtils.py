import subprocess
import logging
import os
import DatabaseConnection
import config


class AddressBlocker(object):
    def __init__(self):
        self.__logger = logging.getLogger('SecurityMetricIDS')
        self.__logger.info("Initializing address blocking utility.")
        self.__dev_null = open(os.devnull, 'w')
        self.cursor = DatabaseConnection.init_db_connection().cursor()

    def block_address(self, ip_address):
        self.__logger.warn("Blocking ip address: {}".format(ip_address))
        try:
            self.cursor.execute("SELECT id from blockingAddress where "
                                "ip_address_id = (SELECT id from address where ip_address = '{}')"
                                "and status = 'blocked' ".format(ip_address))
            result = self.cursor.fetchone()
            if result:
                self.cursor.execute("UPDATE blockingAddress set "
                                    "date_unblocked = DATE_ADD(NOW(), INTERVAL {} MINUTE) "
                                    "where id = {}".format(config.user_blocking_time, result[0]))
            else:
                subprocess.check_call(['iptables', '-A', 'INPUT', '-s', ip_address, '-j', 'DROP'],
                                      stdout=self.__dev_null, stderr=self.__dev_null)
                self.cursor.execute("INSERT INTO blockingAddress(`ip_address_id`, date_blocked, date_unblocked) "
                                    "values((SELECT id from address where ip_address='{}'), "
                                    "NOW(), DATE_ADD(NOW(), INTERVAL {} MINUTE))".format(ip_address, config.address_blocking_time))
        except subprocess.CalledProcessError:
            self.__logger.error("Block of ip address {} was not successful.".format(ip_address))

    def unblock_address(self, ip_address, blocking_db_id):
        self.__logger.warn("Unblocking ip address: {}".format(ip_address))
        try:
            subprocess.check_call(['iptables', '-D', 'INPUT', '-s', ip_address, '-j', 'DROP'],
                                  stdout=self.__dev_null, stderr=self.__dev_null)
            self.cursor.execute("UPDATE blockingAddress set status='unblocked' where id = {}".format(blocking_db_id))
        except subprocess.CalledProcessError as detail:
            self.__logger.error("Unblock of user IP address {} was not successful: {}".format(ip_address, detail))


class UserBlocker(object):
    def __init__(self):
        self.__logger = logging.getLogger('SecurityMetricIDS')
        self.__logger.info("Initializing user blocking utility.")
        self.__dev_null = open(os.devnull, 'w')
        self.cursor = DatabaseConnection.init_db_connection().cursor()

    def block_user(self, user):
        self.__logger.warn("Blocking user account: {}".format(user))
        if user == "andrej":  # temporary workaround
            return
        try:
            self.cursor.execute("SELECT id from blockingAccount where "
                                "user_id = (SELECT id from user where username = '{}') "
                                "and status='blocked'".format(user))
            result = self.cursor.fetchone()
            if result:
                self.cursor.execute("UPDATE blockingAccount set "
                                    "date_unblocked = DATE_ADD(NOW(), INTERVAL {} MINUTE) "
                                    "where id = {}".format(config.user_blocking_time, result[0]))
            else:
                subprocess.check_call(['passwd', '-l', user], stdout=self.__dev_null, stderr=self.__dev_null)
                self.cursor.execute("INSERT INTO blockingAccount(`user_id`, date_blocked, date_unblocked) "
                                    "values((SELECT id from user where username='{}'), "
                                    "NOW(), DATE_ADD(NOW(), INTERVAL {} MINUTE))".format(user, config.user_blocking_time))

        except subprocess.CalledProcessError:
            self.__logger.error("Block of user account {} was not successful.".format(user))

    def unblock_user(self, user,  blocking_db_id):
        self.__logger.warn("Unblocking user account: {}".format(user))
        if user == "andrej":  # temporary workaround
            return
        try:
            subprocess.check_call(['passwd', '-u', user], stdout=self.__dev_null, stderr=self.__dev_null)
            self.cursor.execute("UPDATE blockingAccount set status='unblocked' where id = {}".format(blocking_db_id))
        except subprocess.CalledProcessError as detail:
            self.__logger.error("Unblock of user account {} was not successful: {}".format(user, detail))