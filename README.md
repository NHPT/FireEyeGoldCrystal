# 火眼金睛(FireEyeGoldCrystal) —— 一个GitHub监控和信息收集工具(A GitHub Monitor and Infomation Collection Tools) 

# 简介(Introduction)

火眼金睛是一个GitHub监控和信息收集工具，支持监控和收集CVE、免杀、漏洞利用等内置关键字和自定义关键字。支持钉钉、Server酱和Telegram推送，过滤敏感词，查找包含关键字的所有仓库并输出到FEGC.xlsx文件。默认关键字列表有限，可通过文件指定关键字和敏感词，由于GitHub API速率限制，目前仅实现单线程。

FireEyeGoldCrystal is A GitHub Monitor and Infomation Collection Tools,It supports monitoring and collecting built-in keywords and custom keywords such as CVE, kill free, vulnerability exploitation, etc.Support DingTalk ,ServerChan and Telegram Push,Filter Sensitive Words,Find all warehouses containing keywords and output to the FEGC.xlsx file.The default keyword list is limited. You can specify keywords and sensitive words through files. Due to the rate limit of GitHub API, only single thread is implemented at present.

![image](https://github.com/NHPT/FireEyeGoldCrystal/blob/main/images/Structure.png)

默认关键字列表(Default Keyword List)：
```
["CVE-"+str(current_year) , "免杀" , "Bypass Antivirus" , "Exploit" ,
 "漏洞利用", "红队", "Red Team" , "蓝队", "Blue Team" , "计算机取证" , 
 "Computer Forensics" ,  "应急响应" , "Emergency response" , "Penetration" ,
  "Pentest" , "内网渗透", "网络攻防",   "网络安全" , "主机安全" , "信息收集" ,
   "溯源" , "工控安全" , "Industrial Control Safety" ,"ICS"]
```

# 选项(Options)

```
optional arguments:
  -h, --help  show this help message and exit
  -m          监控模式，定时推送
  -c          信息收集模式
  -p P        设置代理地址，如：http://127.0.0.1:8080
  -t T        设置超时时间，单位：秒
  -H H        设置HTTP请求头，json格式，如：{"X-Forwarded-For":"127.0.0.1"}
  -mT MT      设置监控阈值，默认5分钟
  -iF IF      设置关键字文件
  -sW SW      设置敏感词文件
```

# 示例(Example)

## 信息收集模式(Information collection mode)

根据内置关键词收集存储库：`py FireEyeGoldCrystal.py -c`

![image](https://github.com/NHPT/FireEyeGoldCrystal/blob/main/images/c.png)

根据指定关键词文件收集存储库：`py FireEyeGoldCrystal.py -c -iF search.txt -sW black.txt`

![image](https://github.com/NHPT/FireEyeGoldCrystal/blob/main/images/c2.png)

![image](https://github.com/NHPT/FireEyeGoldCrystal/blob/main/images/result.png)

## 监控模式

根据内置关键词监控存储库：`py FireEyeGoldCrystal.py -m`

根据指定关键词文件收集存储库，并过滤指定敏感词：`py FireEyeGoldCrystal.py -m -iF search.txt -sW black.txt`

根据内置关键词监控存储库，监控阈值为4小时，并输出日志文件：`python3 FireEyeGoldCrystal.py -m -mT 240 >fegc.log`

![image](https://github.com/NHPT/FireEyeGoldCrystal/blob/main/images/monitor.png)
