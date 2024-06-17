import syslog
import json
import warnings

from elastalert.alerts import Alerter, BasicMatchString
from elastalert.util import EAException, elastalert_logger

class SyslogAlerter(Alerter):
    """ Created a Syslog for each alert """
    required_options = frozenset(['syslog_host', 'syslog_port'])

    def __init__(self, rule):
        super(SyslogAlerter, self).__init__(rule)
        self.syslog_host = self.rule.get('syslog_host', None)
        self.syslog_port = self.rule.get('syslog_port', 514)
        self.syslog_facility = self.rule.get('syslog_facility', syslog.LOG_USER)
        self.syslog_level = self.rule.get('syslog_level', syslog.LOG_ALERT)
        self.syslog_ident = self.rule.get('syslog_ident', 'elastalert')
        self.syslog_socktype = self.rule.get('syslog_socktype', None)
        self.syslog_msgid = self.rule.get('syslog_msgid', None)
        self.syslog_pid = self.rule.get('syslog_pid', None)
        self.syslog_format = self.rule.get('syslog_format', None)
        self.syslog_sock = None

    def alert(self, matches):
        for match in matches:
            message = str(BasicMatchString(self.rule, match))

            if self.syslog_format:
                message = self.syslog_format.format(message=message)

            elastalert_logger.info('Alert sent to syslog: %s' % message)
            self.send_to_syslog(message)

    def send_to_syslog(self, message):
        if self.syslog_sock is None:
            elastalert_logger.info('Opening syslog socket to %s:%d' % (self.syslog_host, self.syslog_port))
            self.syslog_sock = syslog.socket(self.syslog_socktype, syslog.SOCK_DGRAM)
            self.syslog_sock.connect((self.syslog_host, self.syslog_port))

        self.syslog_sock.send(self.syslog_level | self.syslog_facility, self.syslog_ident, message)

        elastalert_logger.info('Sent alert to syslog')

    def get_info(self):
        return { 'type': 'syslog', 'syslog_host': self.syslog_host, 'syslog_port': self.syslog_port }