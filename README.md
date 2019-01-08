# some_pocsuite

本项目是用于企业内部进行漏洞排查与验证的的pocsuite验证POC代码（Pocsuite是知道创宇安全团队的开源漏洞测试框架）；参考了网上的开源代码并进行了修改。

## 插件代码编写

使用Pocsuite 漏洞测试框架，插件编写请参考 Pocsuite 项目插件编写要求；陆续扩充中...

[PoC 编写规范及要求说明](https://github.com/knownsec/Pocsuite/blob/master/docs/CODING.md)

| 序号 | poc                                     | 说明                                                         |
| ---- | --------------------------------------- | ------------------------------------------------------------ |
| 1    | hikvision-2013-4976_web_login-bypass.py | 海康威视cve-2013-4976匿名登录验证绕过                        |
| 2    | weblogic-vul-check_all_rce.py           | weblogic反序列化漏洞（CVE-2016-0638，CVE-2016-3510，CVE-2017-3248，CVE-2018-2628，CVE-2018-2893） |
| 3    | weblogic-wls-2017_10271_all_rce.py      | weblogic WLS组件反序列化漏洞CVE-2017-10271                   |
| 4    | zookeeper_all_unauthorized.py           | zookeeper未授权访问                                          |
| 5    | redis_all_unauthorized.py               | redis未授权访问（ [pocsuite_poc_collect](https://github.com/njcx/pocsuite_poc_collect)） |
| 6    | memcached_all_unauthorized.py           | memchached未授权访问                                         |
| 7    | snmp_v2_unauthorized.py                 | snmp未授权访问（需要安装pysnmp模块）                         |

## 参考及依赖项目

- [Pocsuite](https://github.com/knownsec/Pocsuite)

- [pocsuite_poc_collect](https://github.com/njcx/pocsuite_poc_collect)

- [w9scan](https://github.com/boy-hack/w9scan)

- [Fuxi-scanner](https://github.com/jeffzh3ng/Fuxi-Scanner)
