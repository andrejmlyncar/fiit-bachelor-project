import logging
import config


class Anomaly(object):

    def __init__(self, success_value, fail_value):
        self.__logger = logging.getLogger('SecurityMetricIDS')
        self.value = self.__get_metric_value(success_value, fail_value)
        self.is_valid = self.__check_if_valid()
        self.level = self.set_level()

    def set_level(self):
        if self.is_valid:
            if self.value < config.second_level_val:
                return 1
            elif config.second_level_val <= self.value < config.third_level_val:
                return 2
            else:
                return 3

    def __check_if_valid(self):
        if self.value < config.first_level_val:
            return False
        else:
            return True

    @staticmethod
    def __get_metric_value(success_value, fail_value):
        if fail_value == 0:
            fail_value = 0.5
        if success_value == 0:
            success_value = 0.5
        metric_value = fail_value/float(success_value)
        return metric_value


