#!/usr/bin/python3
import requests
import json
import time
import hmac
import hashlib
import base64
import urllib.parse
from openpyxl import Workbook
import argparse
import schedule
from bs4 import BeautifulSoup
import random

result=[]
flag = False

# 钉钉机器人的加签密钥
secret = ''
# 钉钉机器人的Webhook
webhook = ''
# 企业微信webhook
wxwork_url=''

def clearResult():
    global flag
    flag = True

def get_bing_wallpapers_of_the_day():
    # 设置用户代理标头
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/100.0.0.0 Safari/537.36'
    }

    # 发送HTTP请求获取页面内容
    url = 'https://bing.ioliu.cn/'
    response = requests.get(url, headers=headers)

    # 检查响应是否成功
    if response.status_code == 200:
        # 使用Beautiful Soup解析页面内容
        soup = BeautifulSoup(response.text, 'html.parser')

        # 找到所有壁纸的图片元素
        image_elements = soup.find_all('img', class_='progressive__img')

        # 获取所有壁纸的URL并添加到列表
        wallpaper_urls = []
        for image_element in image_elements:
            wallpaper_url = image_element['data-progressive']
            wallpaper_urls.append(wallpaper_url)

        return wallpaper_urls
    else:
        print('请求失败，状态码:', response.status_code)
        return None

def get_random_bing_wallpaper():
    # 获取一天中所有Bing壁纸的URL列表
    bing_wallpaper_urls = get_bing_wallpapers_of_the_day()
    
    if bing_wallpaper_urls:
        # 随机选择一个壁纸URL
        random_wallpaper_url = random.choice(bing_wallpaper_urls)
        return random_wallpaper_url
    else:
        return None

def proxy(proxy):
    try:
        key=proxy.split('://')[0]
        return {key:proxy}
    except:
        exit('[!] 代理地址格式有误！')

def headers(header):
    try:
        headers=json.loads(header)
        return headers
    except:
        exit('[!] HTTP请求头格式有误！')

# 钉钉推送
def DingDing(msg):
    timestamp = str(round(time.time() * 1000))
    secret_enc = secret.encode('utf-8')
    string_to_sign = '{}\n{}'.format(timestamp, secret)
    string_to_sign_enc = string_to_sign.encode('utf-8')
    hmac_code = hmac.new(secret_enc, string_to_sign_enc, digestmod=hashlib.sha256).digest()
    sign = urllib.parse.quote_plus(base64.b64encode(hmac_code))
    url=webhook+'&timestamp='+timestamp+'&sign='+sign
    #json={"msgtype": "text","text": {"content": msg},"isAtAll": True}
    msglist=[{
                "title": "GitHub情报"+str(len(msg))+"条",
                "picURL": get_random_bing_wallpaper()
            }]
    for i in range(len(msg)):
        tmpj = {"title": msg[i]['存储库描述'],
                "messageURL": msg[i]['存储库链接']
                }
        msglist.append(tmpj)
    json ={
    "msgtype": "feedCard",
    "feedCard": {
        "links": msglist
    }
}
    r=requests.post(url,json=json,headers=head,proxies=proxies,timeout=timeout,verify=False)
    global result,flag
    if flag:
        result.clear()
        flag = False
    #print(r.text)

# 企业微信推送
def WXWork(msg):
    #json格式化发送的数据信息
    if not msg:
        return
    res = "# GitHub情报"+str(len(msg))+"条\n"
    for i in range(len(msg)):
        res+=str(i+1)+". ["+msg[i]['存储库描述']+"]("+msg[i]['存储库链接']+")\n"
    data = json.dumps({
        "msgtype": "markdown",
        "markdown": {
            "content": res
            }
        })
    # 指定机器人发送消息
    resp = requests.post(wxwork_url,data,auth=('Content-Type', 'application/json'))
    global result,flag
    if flag:
        result.clear()
        flag = False
    #print(resp.json)

# 获取GitHub存储库更新信息
def GetNewSearch():
    # 存储包含各关键字的存储库的数量
    init_count=[]
    
    sl=len(SearchList)
    i=0
    while i<sl:
        search_url = "https://api.github.com/search/repositories?q="+SearchList[i]+"&sort=updated"
        try:
            init = requests.get(search_url,headers=head,proxies=proxies,timeout=timeout,verify=False).text
        except Exception as e:
            print(e)
            time.sleep(10)
            continue
        if 'API rate limit exceeded' in init:
            time.sleep(10)
            continue
        #print(json.loads(init).get('total_count'))
        # 获取包含当前关键字的存储库总数
        init_count.append(json.loads(init).get('total_count'))
        time.sleep(6)
        i+=1
    #print(init_count)
    #print("[*] total_count",total_count)
    # 设置监控阈值
    #time.sleep(60*mt)
    temp=[]
    for i in range(len(SearchList)):
        try:
            github_api = "https://api.github.com/search/repositories?q="+SearchList[i]+"&sort=updated"
            res = requests.get(github_api,headers=head,proxies=proxies,timeout=timeout,verify=False).text
            json_res=json.loads(res)
            # 获取包含当前关键字的存储库总数
            current_count=json_res.get('total_count')
            if current_count==None:
                continue
            newRes_num=current_count > init_count[i]
            if newRes_num > 0:
                items=json_res.get('items')
                # 更新的存储库总在前边显示，因此只需取前N个即可
                for i in range(newRes_num):
                    newRes=items[i]
                    html_url=newRes.get('html_url')
                    desc=newRes.get('description')
                    if desc==None:
                        desc=SearchList[i] + html_url.split('/')[-1]
                    else:
                        # 过滤包含敏感词的存储库
                        if Filter(desc):
                            continue
                    #print("仓库描述：",desc,"仓库链接：",newRes.get('html_url'))
                    # 过滤黑名单用户
                    if FilterUser(html_url):
                        continue
                    result.append({"存储库描述":desc,"存储库链接":html_url})
                    temp.append({"存储库描述":desc,"存储库链接":html_url})
                time.sleep(6)
        except Exception as e:
            print(time.strftime("%Y-%m-%d %H:%M:%S",time.localtime()),e)
    print(temp)
    if temp and args.r:
        DingDing(temp)
        WXWork(temp)
        #ServerChan(temp)
        #Telegram(temp)

# 获取单页中的存储库描述和链接地址
def GetOnePageData(jsonResp,sheet):
    json_res=json.loads(jsonResp)
    item_num=len(json_res.get('items'))
    for i in range(item_num):
        desc=json_res.get('items')[i].get('description')
        if desc==None:
            desc="空"
        else:
            # 过滤包含敏感词的存储库
            if Filter(desc):
                continue
        html_url=json_res.get('items')[i].get('html_url')
        # 过滤黑名单用户
        if FilterUser(html_url):
            continue
        print(desc,html_url)
        # 写入sheet
        sheet.append([desc,html_url])

# 获取GitHub所有存储库
def GetAll():
    # 实例化Excel工作簿
    wb=Workbook()
    sl=len(SearchList)
    # 创建Sheet
    sheets=[]
    for s in SearchList:
        sheets.append(wb.create_sheet(s))
    i=0
    while i<sl:
        url="https://api.github.com/search/repositories?q="+SearchList[i]+"&per_page=100"
        r = requests.get(url,headers=head,proxies=proxies,timeout=timeout,verify=False)
        if 'API rate limit exceeded' in r.text:
            time.sleep(6)
            continue
        try:
            # 获取查询结果总页数
            link=r.headers['Link']
            page=int(link.split('page=')[-1].split('>')[0])
            # 获取第一页数据
            GetOnePageData(r.text,sheets[i])
            # 获取其它页数据
            j=2
            while j<=page:
                url="https://api.github.com/search/repositories?q="+SearchList[i]+"&per_page=100&page="+str(j)
                r=requests.get(url,headers=head,proxies=proxies,timeout=timeout,verify=False)
                if 'API rate limit exceeded' in r.text:
                    time.sleep(6)
                    continue
                GetOnePageData(r.text,sheets[i])
                time.sleep(3)
                j+=1
        except KeyError:
            GetOnePageData(r.text,sheets[i])
        time.sleep(6)
        # 设置Sheet颜色
        sheets[i].sheet_properties.tabColor = "9AFF9A"
        i+=1
    wb.remove(wb['Sheet'])
    wb.save('FEGC.xlsx')

# 过滤敏感词
def Filter(msg):
    for w in SensitiveWords:
        if w in msg:
            return True
    return False

# 过滤黑名单用户
def FilterUser(url):
    user=url.split("/")[3]
    if user in BlacklistUsers:
        return True
    else:
        return False

# Server酱推送
def ServerChan(msg):
    # sckey为自己的server SCKEY
    sckey = ''
    url = 'https://sc.ftqq.com/'+sckey+'.send?text=GitHub&desp='+msg
    requests.get(url,headers=head,proxies=proxies,timeout=timeout,verify=False)


# Telegram推送
def Telegram(msg):
    import telegram
    # 自己的Telegram Bot Token
    token = ''
    bot = telegram.Bot(token=token)
    # 自己的Group ID
    group_id = ''
    bot.send_message(chat_id=group_id, text=msg)

procdesc="FireEyeGoldCrystal 是一个GitHub监控和信息收集工具，支持钉钉、Server酱和Telegram推送，过滤敏感词，查找包含关键字的所有仓库并输出到FEGC.xlsx文件     --By NHPT"
parser=argparse.ArgumentParser(description=procdesc,epilog="GitHub:https://github.com/nhpt")

group = parser.add_mutually_exclusive_group(required=True)
group.add_argument('-m',action='store_true',help='监控模式，定时推送')
group.add_argument('-c',action='store_true',help='信息收集模式')

parser.add_argument('-p',help='设置代理地址，如：http://127.0.0.1:8080')
parser.add_argument('-t',help='设置超时时间，单位：秒')
parser.add_argument('-r',action='store_true',help='是否实时推送')
parser.add_argument('-d',default='09:00',help='设置每天定时推送时间，默认为：09:00，需要使用24小时格式')
parser.add_argument('-H',help='设置HTTP请求头，json格式，如：{"X-Forwarded-For":"127.0.0.1"}')
parser.add_argument('-mT',type=int,default=5,help='设置监控阈值，单位：分，默认5分钟')
parser.add_argument('-iF',type=argparse.FileType('r',encoding='utf8'),help='设置关键字文件')
parser.add_argument('-sW',type=argparse.FileType('r',encoding='utf8'),help='设置敏感词文件')

args=parser.parse_args()

requests.packages.urllib3.disable_warnings()
# 当前年份
current_year=time.localtime()[0]
# 监控阈值，默认5分钟
mt=args.mT
timeout=None
proxies=None
head = {
    "User-Agent":"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/83.0.4103.116 Safari/537.36"
}
# 关键字列表
SearchList=["CVE-"+str(current_year) ,"CVE-"+str(current_year-1),"CVE-"+str(current_year-2), "免杀" , "Bypass Antivirus" , "Exploit" ,
 "漏洞利用", "红队", "Red Team" , "蓝队", "Blue Team" , "计算机取证" , "Computer Forensics" ,
  "应急响应" , "Emergency response" , "Penetration" , "Pentest" , "内网渗透", "网络攻防",
   "网络安全" , "主机安全" , "信息收集" , "溯源" , "工控安全" , "Industrial Control Safety" ,"ICS"]

# 敏感词列表
SensitiveWords=[]

# 黑名单用户
BlacklistUsers=["thathttp01","thatjohn0a","thatjohn01","redflagblog-com"]

if args.p:
    proxies=proxy(args.p)
if args.t:
    timeout=float(args.t)
if args.H:
    head=headers(args.H)
if args.mT:
    mt=args.mT
if args.iF:
    SearchList=[x.strip('\n') for x in args.iF.readlines()]
if args.sW:
    SensitiveWords=[x.strip('\n') for x in args.sW.readlines()]
if args.c:
    GetAll()
if args.m:
    schedule.every(mt).minutes.do(GetNewSearch)
    if args.d:
        schedule.every().day.at(args.d).do(WXWork,result).tag('wxwork')
        schedule.every().day.at(args.d).do(DingDing,result).tag('dingding')
        schedule.every().day.at(args.d).do(clearResult).tag('clearflag')
    while 1:
        schedule.run_pending()
        time.sleep(1)
