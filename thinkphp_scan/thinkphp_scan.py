#!/usr/bin/env python
# coding: utf-8
import os
import sys
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
    updateDate = '2019-2-20'
    references = ['https://github.com/Lucifer1993/TPscan']
    name = '一键ThinkPHP漏洞检测'
    appPowerLink = ''
    appName = 'thinkphp'
    appVersion = '5.X'
    vulType = VUL_TYPE.CODE_EXECUTION
    category = POC_CATEGORY.EXPLOITS.REMOTE
    desc = '''
    检测脚本是利用 https://github.com/Lucifer1993/TPscan 来检测是否存在漏洞
    '''

    def _verify(self):
        def check_TPscan_exist():
            pyfile = 'TPscan.py'
            pyfile_pathname = os.path.join(os.path.abspath('.'),pyfile)
            if not os.path.exists(pyfile_pathname):
                raise(Exception('{} pyfile not found in current path'.format(pyfile)))

            return pyfile_pathname
        pyfile_pathname = check_TPscan_exist()
        result = {}
        try:
            python_cmds = ['python3','python']
            for python_cmd in python_cmds:
                cmd = python_cmd + ' ' +pyfile_pathname+' '+self.url
                msg = os.popen(cmd).read()
                if 'vulnname' in msg:
                    result['VerifyInfo'] = {}
                    result['VerifyInfo']['URL'] = self.url
                    result['extra'] = {}
                    result['extra']['evidence'] =  msg
                    break
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
