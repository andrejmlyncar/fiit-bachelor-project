import smtplib
import config
import logging


class EmailServerConnection(object):

    __server = None
    _instance = None

    def __init__(self):
        self.__logger = logging.getLogger('SecurityMetricIDS')
        if not EmailServerConnection.__server:
            EmailServerConnection.__server = self.__init_server()

    def __new__(cls, *args, **kwargs):
        if not cls._instance:
            cls._instance = super(EmailServerConnection, cls).__new__(cls, *args, **kwargs)
        return cls._instance

    def send_message(self, level, data_info, value):
        if level == 2:
            body = "Hello, security thread in logging process detected:\n" \
                   "Username or ip address: {}.\n" \
                   "Security metric value: {}.\n" \
                   "For more info check application ui or database.\n".format(data_info, value)
            message = 'Subject: %s\n\n%s' % ("Security anomaly detected.", body)
        elif level == 3:
            body = "Hello, attack on logging process detected:\n" \
                   "Username or ip address: {}.\n" \
                   "Security metric value: {}.\n" \
                   "Please consider making some actions to prevent attacking on this server.\n" \
                   "For more info check application ui or database.".format(data_info, value)
            message = 'Subject: %s\n\n%s' % ("Security attack detected.", body)

        EmailServerConnection.__server.sendmail(config.outmail, config.emails, message)

    def __init_server(self):
        try:
            if not config.mailServerName:
                self.__logger.info("Establishing SMTP connection")
                server = smtplib.SMTP('localhost')
            else:
                server = smtplib.SMTP(config.mailServerName, config.mailServerPort)
                server.ehlo()
                server.starttls()
                server.ehlo()
                server.login(config.outmail, config.password)
            self.__logger.info("SMTP connection established")
            return server
        except smtplib.SMTPException:
                self.__logger.error("Unable to establish connection with email server: {}".
                                    format(smtplib.SMTPException.message))
