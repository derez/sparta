#!/usr/bin/python

__author__ =  'yunshu(wustyunshu@hotmail.com)'
__version__=  '0.2'

import sys
import xml.dom.minidom

import logging
logger = logging.getLogger(__name__)

class Session:
    def __init__( self, SessionHT ):
        self.start_time = SessionHT.get('start_time', '')
        self.finish_time = SessionHT.get('finish_time', '')
        self.nmap_version = SessionHT.get('nmap_version', '')
        self.scan_args = SessionHT.get('scan_args', '')
        self.total_hosts = SessionHT.get('total_hosts', '')
        self.up_hosts = SessionHT.get('up_hosts', '')
        self.down_hosts = SessionHT.get('down_hosts', '')

if __name__ == '__main__':

    dom = xml.dom.minidom.parse('i.xml')
    dom.getElementsByTagName('finished')[0].getAttribute('timestr')

    MySession = { 'finish_time': dom.getElementsByTagName('finished')[0].getAttribute('timestr'), 'nmap_version' : '4.79', 'scan_args' : '-sS -sV -A -T4', 'start_time' : dom.getElementsByTagName('nmaprun')[0].getAttribute('startstr'), 'total_hosts' : '1', 'up_hosts' : '1', 'down_hosts' : '0' }

    s = Session( MySession )

    logger.info('start_time:' + s.start_time)
    logger.info('finish_time:' + s.finish_time)
    logger.info('nmap_version:' + s.nmap_version)
    logger.info('nmap_args:' + s.scan_args)
    logger.info('total hosts:' + s.total_hosts)
    logger.info('up hosts:' + s.up_hosts)
    logger.info('down hosts:' + s.down_hosts)
