import DatabaseConnection
import logging
import config
from EmailUtils import EmailServerConnection
from Anomaly import Anomaly
import MessageAlertUtils
from BlockingUtils import UserBlocker, AddressBlocker


class MetricsComputer(object):

    def __init__(self):
        self.__logger = logging.getLogger('SecurityMetricIDS')
        self.__logger.info("Initializing metric database computer.")

    def compute_metrics(self):
        self.__logger.info("Search for anomalies started.")
        __user_blocker = None
        __address_blocker = None
        connection = DatabaseConnection.init_db_connection()
        c = connection.cursor()
        c.execute("SELECT userData.id, fail_count, success_count, username "
                  "from userData "
                  "join user on user.id = userData.user_id "
                  "where metric_set=0")
        user_data_to_analyse = c.fetchall()
        self.__logger.info("User records to recompute: {}".format(c.rowcount))

        for record in user_data_to_analyse:
            c.execute("UPDATE userData set metric_set=1 where id={}".format(int(record[0])))
            fail_count = record[1]
            success_count = record[2]
            anomaly = Anomaly(success_count, fail_count)

            if anomaly.is_valid:
                self.__logger.warn("Anomaly detected. Checking if existing anomaly should be updated, or new created.")
                c.execute("SELECT id from anomaly where data_id = {} and type=1".format(int(record[0])))
                existing_anomaly = c.fetchone()
                if existing_anomaly:
                    self.__logger.info("Updating anomaly.")
                    self.__update_anomaly(existing_anomaly[0], anomaly, c)
                else:
                    self.__logger.info("Inserting new anomaly.")
                    self.__insert_anomaly(record[0], anomaly, c, 1)
                self.__send_alert(anomaly, record[3])
                self.__logger.info("New anomaly data stored. Alert was sent according to level of anomaly")

                if anomaly.level == 3 and config.user_blocking_enabled:
                    if not __user_blocker:
                        __user_blocker = UserBlocker()
                    __user_blocker.block_user(record[3])

        c.execute("SELECT addressData.id, fail_count, success_count, ip_address "
                  "from addressData "
                  "join address on address.id = addressData.ip_address_id "
                  "where metric_set=0")
        ip_data_to_analyse = c.fetchall()
        self.__logger.info("Ip records to recompute: {}".format(c.rowcount))

        for record in ip_data_to_analyse:
            c.execute("UPDATE addressData set metric_set=1 where id={}".format(int(record[0])))
            fail_count = record[1]
            success_count = record[2]
            anomaly = Anomaly(success_count, fail_count)

            if anomaly.is_valid:
                self.__logger.info("Anomaly detected. Checking if existing anomaly should be updated, or new created.")
                c.execute("SELECT id from anomaly where data_id = {} and type=2".format(int(record[0])))
                existing_anomaly = c.fetchone()
                if existing_anomaly:
                    self.__logger.info("Updating anomaly.")
                    self.__update_anomaly(existing_anomaly[0], anomaly, c)
                else:
                    self.__logger.info("Inserting new anomaly.")
                    self.__insert_anomaly(record[0], anomaly, c, 2)
                self.__send_alert(anomaly, record[3])
                self.__logger.info("New anomaly data stored. Alert was sent according to level of anomaly")

                if anomaly.level == 3 and config.address_blocking_enabled:
                    if not __address_blocker:
                        __address_blocker = AddressBlocker()
                    __address_blocker.block_address(record[3])

    def __insert_anomaly(self, record_id, anomaly, cursor, anomaly_type):
        try:
            cursor.execute("INSERT INTO anomaly (data_id, value, type, level_id) values({}, {}, {}, {})"
                           .format(record_id, anomaly.value, anomaly_type, anomaly.level))
        except Exception as db_error:
            self.__logger.error(db_error)

    def __update_anomaly(self, anomaly_id, anomaly, cursor):
        try:
            cursor.execute("UPDATE anomaly set value={}, level_id={} where id={}"
                           .format(anomaly.value, anomaly.level, anomaly_id))
        except Exception as db_error:
            self.__logger.error(db_error)

    def __send_alert(self, anomaly, data_info):
        if config.email_notification and (anomaly.level == 2 or anomaly.level == 3):
                email = EmailServerConnection()
                email.send_message(anomaly.level, data_info, anomaly.value)

        if anomaly.level == 3:
            if config.terminal_notification:
                MessageAlertUtils.send_alert(data_info, anomaly.value)





