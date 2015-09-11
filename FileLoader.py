
import logging
import sys
import datetime
import config
from dateutil.parser import parse
import traceback
import DatabaseConnection


class FileLoader:

    def __init__(self):
        self.logger = logging.getLogger('SecurityMetricIDS')
        self.__ipList = []
        self.__userList = []
        self.__ipTimeList = []
        self.__userTimeList = []
        self.__logInfo = {'LastLine': None, 'LineStr': None}

    def read_file(self):
        try:
            self.logger.info("Opening log file")
            log = open(config.logname, "r")
        except IOError:
            self.logger.error("Unable to open file right now. Please check if you "
                              "have permissions to read this file or if specified correct path to log file")
            return

        self.logger.info("Started analysis of log {} at {}".format(log.name, datetime.datetime.now()))
        connection = DatabaseConnection.init_db_connection()
        lines = log.readlines()

        lines = self.__crop_logfile(lines)
        self.logger.info("Log records to analyse: {}.".format(len(lines)))
        for item in lines:
            self.__parse_message(item)

        if not log.closed:
            log.close()
            self.logger.info(
                """Log analysis completed at {}. File was successfully closed.""".format(datetime.datetime.now()))
        self.__insert_data(connection)
        self.__clear_data_lists()

        if connection:
            connection.close()

    def __parse_message(self, msg):
        try:
            # print msg
            if "Failed" in msg and "invalid" not in msg:
                msg = msg.replace('  ', ' ')
                array = msg.split(' ')
                dtime = "{} {} {}".format(array[0], array[1], array[2])
                user = array[8]
                ip = array[10]
                self.__update_dictionary(user, ip, 1, dtime)

            elif "Accepted password" in msg:
                # Successfull login
                # print "Found acceptation: {}".format(msg)
                msg = msg.replace('  ', ' ')
                array = msg.split(' ')
                dtime = "{} {} {}".format(array[0], array[1], array[2])
                user = array[8]
                ip = array[10]
                self.__update_dictionary(user, ip, 2, dtime)

        except Exception as parse_error:
            self.logger.error(parse_error)
            traceback.print_exc(file=sys.stdout)

    def __update_dictionary(self, user, ip, msg_type, timestamp):
        user_occurrence = filter(lambda user_search: user_search['user'] == user,
                                 self.__userList)
        if not user_occurrence:
            if msg_type == 1:
                new_item = {'user': user, 'failed_count': 1, 'success_count': 0}
            else:
                new_item = {'user': user, 'failed_count': 0, 'success_count': 1}
            self.__userList.append(new_item)
        else:
            if msg_type == 1:
                user_occurrence[0]['failed_count'] += 1
            elif msg_type == 2:
                user_occurrence[0]['success_count'] += 1

        ip_occurrence = filter(lambda ip_search: ip_search['ip'] == ip,
                               self.__ipList)
        if not ip_occurrence:
            if msg_type == 1:
                new_item = {'ip': ip, 'failed_count': 1, 'success_count': 0}
            else:
                new_item = {'ip': ip, 'failed_count': 0, 'success_count': 1}
            self.__ipList.append(new_item)
        else:
            if msg_type == 1:
                ip_occurrence[0]['failed_count'] += 1
            elif msg_type == 2:
                ip_occurrence[0]['success_count'] += 1

        dt = parse(timestamp)
        trimmed_time = dt - datetime.timedelta(minutes=dt.minute % config.trim_time,
                                               seconds=dt.second,
                                               microseconds=dt.microsecond)
        trimmed_time_to = trimmed_time + datetime.timedelta(0, 0, 0, 0, config.trim_time)

        user_time_occurrence = filter(lambda user_search: user_search['user'] == user
                                      and user_search['time_from'] == trimmed_time
                                      and user_search['time_to'] == trimmed_time_to,
                                      self.__userTimeList)
        if not user_time_occurrence:
            if msg_type == 1:
                new_item = {'user': user, 'failed_count': 1, 'success_count': 0,
                            'time_from': trimmed_time, 'time_to': trimmed_time_to}
            else:
                new_item = {'user': user, 'failed_count': 0, 'success_count': 1,
                            'time_from': trimmed_time, 'time_to': trimmed_time_to}
            self.__userTimeList.append(new_item)
        else:
            if msg_type == 1:
                user_time_occurrence[0]['failed_count'] += 1
            elif msg_type == 2:
                user_time_occurrence[0]['success_count'] += 1

        ip_time_occurrence = filter(lambda address_search: address_search['ip'] == ip
                                    and address_search['time_from'] == trimmed_time
                                    and address_search['time_to'] == trimmed_time_to,
                                    self.__ipTimeList)

        if not ip_time_occurrence:
            if msg_type == 1:
                new_item = {'ip': ip, 'failed_count': 1, 'success_count': 0,
                            'time_from': trimmed_time, 'time_to': trimmed_time_to}
            else:
                new_item = {'ip': ip, 'failed_count': 0, 'success_count': 1,
                            'time_from': trimmed_time, 'time_to': trimmed_time_to}
            self.__ipTimeList.append(new_item)
        else:
            if msg_type == 1:
                ip_time_occurrence[0]['failed_count'] += 1
            else:
                ip_time_occurrence[0]['success_count'] += 1

    def __insert_data(self, connection):
        self.logger.info("Inserting analysed data to database.")
        try:
            with connection:
                c = connection.cursor()
                for item in self.__userList:
                    c.execute("INSERT IGNORE INTO user(username) values('{}')".format(item['user']))
                    c.execute("SELECT id from user where username='{}'".format(item['user']))
                    uid = c.fetchone()
                    c.execute("SELECT id from userData where user_id = {} "
                              "and dateOccurred_from is NULL".format(uid[0]))
                    output = c.fetchone()
                    if output:
                        c.execute("UPDATE userData set success_count = success_count+{}, "
                                  "fail_count = fail_count+{}, metric_set=0 where id = {}".
                                  format(item['success_count'], item['failed_count'], output[0]))
                    else:
                        c.execute("INSERT INTO userData(user_id, success_count, fail_count) "
                                  "values({}, {}, {})".format(int(uid[0]), item['success_count'], item['failed_count']))

                for item in self.__ipList:
                    c.execute("INSERT IGNORE INTO address(ip_address) values('{}')".format(item['ip']))
                    c.execute("SELECT id from address where ip_address='{}'".format(item['ip']))
                    ipid = c.fetchone()
                    c.execute("SELECT id from addressData where ip_address_id = {} "
                              "and dateOccurred_from is NULL".format(ipid[0]))
                    output = c.fetchone()
                    if output:
                        c.execute("UPDATE addressData set success_count = success_count+{}, "
                                  "fail_count = fail_count+{}, metric_set=0 where id = {}".
                                  format(item['success_count'], item['failed_count'], output[0]))
                    else:
                        c.execute("INSERT INTO addressData(ip_address_id, success_count, fail_count) "
                                  "values({}, {}, {})".format(int(ipid[0]), item['success_count'], item['failed_count']))

                for item in self.__ipTimeList:
                    c.execute("INSERT IGNORE INTO address(ip_address) values('{}')".format(item['ip']))
                    c.execute("SELECT id from address where ip_address='{}'".format(item['ip']))
                    ipid = c.fetchone()
                    c.execute("SELECT id from addressData where ip_address_id = {} "
                              "and dateOccurred_from = '{}' and dateOccurred_to = '{}' ".
                              format(ipid[0], item['time_from'], item['time_to']))
                    output = c.fetchone()
                    if output:
                        c.execute("UPDATE addressData set success_count = success_count+{}, "
                                  "fail_count = fail_count+{}, metric_set=0  where id = {}".
                                  format(item['success_count'], item['failed_count'], output[0]))
                    else:
                        c.execute("INSERT INTO addressData"
                                  "(ip_address_id, fail_count, success_count, dateOccurred_from, dateOccurred_to) "
                                  "values({}, {}, {}, '{}', '{}')"
                                  .format(int(ipid[0]), item['failed_count'], item['success_count'],
                                          item['time_from'], item['time_to']))

                for item in self.__userTimeList:
                    c.execute("INSERT IGNORE INTO user(username) values('{}')".format(item['user']))
                    c.execute("SELECT id from user where username='{}'".format(item['user']))
                    uid = c.fetchone()
                    c.execute("SELECT id from userData where user_id = {} "
                              "and dateOccurred_from = '{}' and dateOccurred_to = '{}' ".
                              format(uid[0], item['time_from'], item['time_to']))
                    output = c.fetchone()
                    if output:
                        c.execute("UPDATE userData set success_count = success_count+{}, "
                                  "fail_count = fail_count+{}, metric_set=0 where id = {}".
                                  format(item['success_count'], item['failed_count'], output[0]))
                    else:
                        c.execute("INSERT INTO userData"
                                  "(user_id, success_count, fail_count, dateOccurred_from, dateOccurred_to) "
                                  "values({}, {}, {}, '{}', '{}')"
                                  .format(int(uid[0]), item['success_count'], item['failed_count'],
                                          item['time_from'], item['time_to']))

        except Exception as db_error:
            self.logger.error(db_error)
            traceback.print_exc(file=sys.stdout)

        self.logger.info("Data inserted to database successfully")

    def __crop_logfile(self, lines):
        sublist = None
        if not self.__logInfo['LastLine'] or len(lines) < self.__logInfo['LastLine'] or\
           self.__logInfo['LineStr'] != lines[self.__logInfo['LastLine'] - 1]:
            self.logger.info("Performing first log file read.")
        else:
            self.logger.info("This file was already read by this application, reading from last line.")
            sublist = lines[self.__logInfo['LastLine']-1:len(lines)-1]

        self.__logInfo['LastLine'] = len(lines)
        self.__logInfo['LineStr'] = lines[self.__logInfo['LastLine'] - 1]

        if sublist is not None:
            return sublist
        else:
            return lines

    def __clear_data_lists(self):
        self.__userList = []
        self.__ipList = []
        self.__userTimeList = []
        self.__ipTimeList = []