from Application import UserInterface, CoreApplication
import DatabaseConnection
import sys


class UiApplication(UserInterface):

    def __init__(self):
        UserInterface.__init__(self)
        self.core = None
        print """Enter one of following commands:

start: starts core of the application
stop: terminates core thread
exit: terminates application
show anomalies: displays anomaly data
show address data: displays address data gathered from logs
show user data: displays user data gathered from logs"""

    def start_ui(self):
        self.logger.info("Starting ui of the application")

        while True:
            var = raw_input(">")
            if var == 'stop':
                if self.core is None or not self.core.iterator:
                    print "Core thread is not running, you are not able to terminate core."
                else:
                    self.core.iterator = False
            elif var == 'exit':
                self.__stop()
            elif var == 'show anomalies':
                self.__show_anomalies()
            elif var == '' \
                        '':
                print ">"
            elif var == 'start':
                if self.core:
                    self.logger.info("Using existing core application instance.")
                else:
                    self.core = CoreApplication()
                    self.logger.info("Creating new core application instance.")
                print "Starting core"
                self.core.start_core()
            elif var == 'show address data':
                self.__show_address_data()
            elif var == 'show user data':
                self.__show_user_data()
            else:
                print "Unrecognised command."

    @staticmethod
    def __show_anomalies():
        connection = DatabaseConnection.init_db_connection()
        cursor = connection.cursor()
        cursor.execute("select username, level_id, fail_count, success_count, "
                       "value, dateOccurred_from, dateOccurred_to "
                       "from anomaly join userData on userData.id = anomaly.data_id "
                       "join user on user.id = userData.user_id "
                       "where type=1")
        output = cursor.fetchall()

        cursor.execute("select ip_address, level_id, fail_count, success_count, "
                       "value, dateOccurred_from, dateOccurred_to "
                       "from anomaly join addressData on addressData.id = anomaly.data_id "
                       "join address on address.id = addressData.ip_address_id "
                       "where type=2")
        output += cursor.fetchall()
        print '_'*109
        print "|{:15} | {:6} | {:10} | {:14} | {:12} | {:16} | {:16}|"\
            .format("User or Ip", "Level", "Fail rate", "Success rate", "Metric value", "Date from", "Date to")
        for item in output:
            if item[5]:
                print "|{:15} | {:6} | {:10} | {:14} | {:12} | {:16} | {:16}|"\
                    .format(item[0], item[1], item[2], item[3], item[4],
                            item[5].strftime("%Y-%m-%d %H:%M"), item[6].strftime("%Y-%m-%d %H:%M"))
            else:
                print "|{:15} | {:6} | {:10} | {:14} | {:12} | {:16} | {:16}|"\
                    .format(item[0], item[1], item[2], item[3], item[4],
                            item[5], item[6])
        print '_'*109

    @staticmethod
    def __show_address_data():
        connection = DatabaseConnection.init_db_connection()
        cursor = connection.cursor()
        cursor.execute("select ip_address, fail_count, success_count, "
                       "dateOccurred_from, dateOccurred_to from addressData "
                       "join address on addressData.ip_address_id = address.id")
        output = cursor.fetchall()
        print '_'*84
        print "|{:15} | {:10} | {:14} | {:16} | {:16}|"\
            .format("Ip address",  "Fail rate", "Success rate", "Date from", "Date to")

        for item in output:
            if item[3]:
                print "|{:15} | {:10} | {:14} | {:16} | {:16}|"\
                    .format(item[0], item[1], item[2], item[3].strftime("%Y-%m-%d %H:%M"), item[4].strftime("%Y-%m-%d %H:%M"))
            else:
                print "|{:15} | {:10} | {:14} | {:16} | {:16}|"\
                    .format(item[0], item[1], item[2], item[3], item[4])
        print '_'*84

    @staticmethod
    def __show_user_data():
        connection = DatabaseConnection.init_db_connection()
        cursor = connection.cursor()
        cursor.execute("select username, fail_count, success_count, "
                       "dateOccurred_from, dateOccurred_to from userData "
                       "join user on userData.user_id = user.id")
        output = cursor.fetchall()
        print '_'*84
        print "|{:15} | {:10} | {:14} | {:16} | {:16}|"\
            .format("Username",  "Fail rate", "Success rate", "Date from", "Date to")

        for item in output:
            if item[3]:
                print "|{:15} | {:10} | {:14} | {:16} | {:16}|"\
                    .format(item[0], item[1], item[2], item[3].strftime("%Y-%m-%d %H:%M"), item[4].strftime("%Y-%m-%d %H:%M"))
            else:
                print "|{:15} | {:10} | {:14} | {:16} | {:16}|"\
                    .format(item[0], item[1], item[2], item[3], item[4])
        print '_'*84

    def __stop(self):
        self.logger.info("Shutting down application")
        sys.exit("Application terminated successfully")
