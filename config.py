# logname: name of file which should be analyzed to detect security threads
logname = '/var/log/auth.log'
# time: time in minutes between log analysis
analyse_time = 0.25
# email notification
email_notification = False
# terminal notification
terminal_notification = False
# metric values detecting anomalies, lesser values are, more strict detecting is
first_level_val = 3
second_level_val = 6
third_level_val = 9
# email address/s for notification, use , to separate addresses
emails = ['example@example.com', 'example@example.com']
# outlog: log file for application messages, if not exists, created one with permissions 700
outlog = '/path/to/out/file'
# outgoing mail server, if not filled, it message is sent from default localhost
outmail = 'example@example.com'
mailServerName = ''
mailServerPort = 123456
password = 'pass'
# group to alert security threads
alert_group = 'security'
# database info
db_connection = 'local'
db_name = 'db_name'
db_user = 'user'
db_pass = 'userpass'
# group time: time intervals in which are metrics calculated
trim_time = 30
# enable console logging:
console_log = True
# if gui interface should be enabled
gui_mode = True
# enable user blocking
user_blocking_enabled = False
# user blocking time (minutes)
user_blocking_time = 5
# address blocking
address_blocking_enabled = False
address_blocking_time = 5
