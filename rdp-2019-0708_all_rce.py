#!/usr/bin/env python
# coding: utf-8
import urlparse
import re
import os
import sys
import subprocess
from pocsuite.api.request import req
from pocsuite.api.poc import register
from pocsuite.api.poc import Output, POCBase


class TestPOC(POCBase):
    vulID = '0'
    version = '1.0'
    author = 'hancool'
    vulDate = '2019-5-14'
    createDate = '2019-5-28'
    updateDate = '2019-5-28'
    references = ['https://github.com/zerosum0x0/CVE-2019-0708', ]
    name = 'Remote Desktop Services Remote Code Execution Vulnerability（CVE-2019-0708）Check'
    appPowerLink = 'https://portal.msrc.microsoft.com/en-US/security-guidance/advisory/CVE-2019-0708'
    appName = 'Windows'
    appVersion = '2003,XP,7,Server2008,Server2008 R2'
    vulType = 'Remote Code Execution'
    desc = '''
    A remote code execution vulnerability exists in Remote Desktop Services – formerly known as Terminal Services – 
    when an unauthenticated attacker connects to the target system using RDP and sends specially crafted requests. 
    This vulnerability is pre-authentication and requires no user interaction. 
    An attacker who successfully exploited this vulnerability could execute arbitrary code on the target system. 
    An attacker could then install programs; view, change, or delete data; or create new accounts with full user rights.

    PS:
    目前检测脚本是利用 https://github.com/zerosum0x0/CVE-2019-0708 提供的rdesktop来检测是否存在漏洞，在使用本POC时有以下限制：
    1、确保rdesktop在当前路径中 (https://github.com/zerosum0x0/CVE-2019-0708/blob/master/rdesktop-fork-bd6aa6acddf0ba640a49834807872f4cc0d0a773/rdesktop)
    2、只能在X11 GUI Linux environment命令行下使用
    '''

    def _verify(self):
        def check_os_and_rdesktop_exist():
            if not sys.platform.startswith('linux'):
                raise(Exception('POC only can test in linux'))

            RDESKTOP_BIN = 'rdesktop'
            rdesktop_pathname = os.path.join(os.path.abspath('.'),RDESKTOP_BIN)
            if not os.path.exists(rdesktop_pathname):
                raise(Exception('rdesktop binfile not found in current path'))

        def run_rdesktop(target):
            args = ['./rdesktop',target]
            process = subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=False)

            try:
                stdout, stderr = process.communicate()
            except:
                process.kill()
                stdout, stderr = process.communicate()

            returncode = process.returncode

            if returncode != 0:
                return False,None
            elif stdout is not None and re.search('Target is VULNERABLE', stdout.decode('UTF-8')):
                return True,stdout.decode('utf-8')

            return False,None

        check_os_and_rdesktop_exist()
        result = {}
        pr = urlparse.urlparse(self.url)
        if pr.port:  # and pr.port not in ports:
            ports = [pr.port]
        else:
            ports = [3389,13389,23389]
        for port in ports:
            try:
                target = '{}:{}'.format(pr.hostname, port)
                status,msg = run_rdesktop(target)
                if status:
                    result['VerifyInfo'] = {}
                    result['VerifyInfo']['URL'] = target
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


register(TestPOC)
