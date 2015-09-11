import subprocess
import config
import logging

__logger = logging.getLogger('SecurityMetricIDS')


def send_alert(data_info, value):
    alert = "Serious security thread detected, someone is attacking this server through the logging process.\n" \
            "Username or ip address: {}.\n" \
            "Security metric value: {}.\n" \
            "Please consider making some actions to prevent attacking on this server.\n".format(data_info, value)

    if config.alert_group:
        process = subprocess.Popen(['getent', 'group', 'security'],
                                   stdout=subprocess.PIPE,
                                   stderr=subprocess.PIPE)
        output, err = process.communicate()

        data = output.split(":")
        users_str = data[len(data)-1]
        users = users_str.split(',')

        for user in users:
            user = user.translate(None, '\n')
            __logger.info("Sending message to terminal of '{}'".format(user))
            echo_process = subprocess.Popen(['echo', alert],
                                            stdout=subprocess.PIPE,
                                            stderr=subprocess.PIPE)
            write_process = subprocess.Popen(['write', user],
                                             stdin=echo_process.stdout,
                                             stdout=subprocess.PIPE,
                                             stderr=subprocess.PIPE)
            out, err = write_process.communicate()
    else:
        __logger.info("Sending message to terminal of all users")
        echo_process = subprocess.Popen(['echo', alert],
                                        stdout=subprocess.PIPE,
                                        stderr=subprocess.PIPE)
        write_process = subprocess.Popen(['wall'],
                                         stdin=echo_process.stdout,
                                         stdout=subprocess.PIPE,
                                         stderr=subprocess.PIPE)
        out, err = write_process.communicate()
