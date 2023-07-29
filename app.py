from string import Template
import datetime
import re,random,string
import phishtank
import virustotal
import hibp
from flask import Flask, request, jsonify,render_template

app = Flask(__name__)
app.config['TEMPLATES_AUTO_RELOAD'] = True

@app.route("/")
def hello():
    return "Hello, World!"

def current_time_past(target_time_str):
    # 將目前時間轉換為與指定時間相同的格式
    current_time = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    
    # 將指定時間和目前時間轉換為 datetime 物件
    target_time = datetime.datetime.strptime(target_time_str, '%Y-%m-%d %H:%M:%S')
    current_time = datetime.datetime.strptime(current_time, '%Y-%m-%d %H:%M:%S')
    
    # 比較目前時間是否超過指定時間
    score=(current_time - target_time).days
    if score<=0:
        return 0
    if score>=365:
        return 100
    return score/365

def upperbound(a,b):
    if a>b:
        return b
    return a

@app.route('/url', methods=['POST'])
def posturl():
    #     # 取得前端傳過來的數值
    with open("index.html", 'r',encoding='utf-8') as f:
        html = f.read()

    s = Template(html)
    url = request.values.get('url')
    if is_valid_url(url):
        domain = extract_domain_from_url(url)
        hp = hibp.get_domain(domain)
        vt = virustotal.get_domain(domain)
        phish = phishtank.search_url(url)

        reputation=vt['reputation']
        ssl=vt['last_https_certificate']
        las_harmless=vt['last_analysis_stats']['harmless']
        las_malicious=vt['last_analysis_stats']['malicious']
        las_suspicious=vt['last_analysis_stats']['suspicious']
        las_undetected=vt['last_analysis_stats']['undetected']
        las_timeout=vt['last_analysis_stats']['timeout']

        las1=((100-(abs((las_malicious+las_suspicious)*1.35-las_harmless))*0.30))*0.35 if (las_malicious+las_suspicious)>5 else ((100-abs(((las_malicious+las_suspicious)*1.15)-las_harmless))*0.3)*0.01*35
        rp1=(100-(upperbound(reputation, 100))) * 0.05
        time1=current_time_past(ssl)*0.1
        vote1=(1 if vt['total_votes']['harmless']<vt['total_votes']['malicious'] else 0)*0.05
        ph1=phish*0.05
        pc1=(upperbound(hp["PwnCount"],10000)/10000)*0.05
        dc1=upperbound(len(hp["DataClasses"]),10)%0.1
        cal_one=las1+rp1+time1+vote1+ph1+pc1+dc1
        ##rp2=((100-reputation) * 0.05)
        #las2_m=las_malicious * 7 * 0.4
        #las2_s=las_suspicious * 3 * 0.2
        #vote2=(vt['total_votes']['malicious']/((vt['total_votes']['harmless']+vt['total_votes']['malicious'])*50+1))*0.05
        #ph2=phish*0.05
        #pc2=(upperbound(hp["PwnCount"],10000)/10000*0.5+upperbound(len(hp["DataClasses"]),5)*10*0.5)*0.05
    
        rp2 = (100-(upperbound(reputation, 100)) * 0.05)
        las2_m = las_malicious * 7 * 0.4
        las2_s = las_suspicious * 3 * 0.2
        time1 = upperbound(current_time_past(ssl), 365) / 365 * 10
        vote2 = (vt['total_votes']['malicious']/((vt['total_votes']['harmless']+vt['total_votes']['malicious']) * 50 + 1)) * 0.05
        ph2 = phish * 0.05
        pc2 = (upperbound(hp["PwnCount"], 10000) / 10000 * 0.5 + upperbound(len(hp['DataClasses']), 5) * 10 * 0.5) * 0.05
        cal_two = rp2+las2_m + las2_s + vote2 + ph2 + pc2
        score= (cal_one+cal_two)/2

        data = {
            'PwnCount': hp["PwnCount"],
            'DataClasses': hp["DataClasses"],
            "Phish": phish,
            'las_harmless': las_harmless,
            'las_malicious': las_malicious,
            'las_suspicious': las_suspicious,
            'las_timeout': las_timeout,
            'las_undetected': las_undetected,
            "last_https_certificate": ssl,
            "registrar": vt["registrar"],
            "reputation": reputation,
            "tv_harmless": vt['total_votes']['harmless'],
            "tv_malicious": vt['total_votes']['malicious'],
            "score": round(score,2)
        }
        # return s.substitute(data)
        key=generate_random_string(5)
        with open("templates/"+"xxxxx"+".html", 'w',encoding='utf-8') as f:
            f.write(s.substitute(data))
        return str(round(score,2))
    

    return "format error", 400

@app.route("/html/<id>")
def index(id):
    return render_template(f'{id}.html')

@app.route('/pw', methods=['POST'])
def postpw():
    #     # 取得前端傳過來的數值
    pw = request.values.get('pw')
    if is_sha1(pw):
        # data={
        #     "hibp":
        # }
        return hibp.get_password(pw)

    return "format error", 400


def extract_domain_from_url(url):
    # 定義正則表達式來捕獲 domain
    pattern = r'^https?://(?:www\.)?([^/]+)'
    # 使用 re 模組尋找匹配的 domain
    match = re.match(pattern, url)
    # 若找到匹配，返回 domain；否則返回空字串
    if match:
        return match.group(1)

    return ''


def is_valid_url(url):
    # 定義 URL 的正規表達式
    pattern = r'^(https?|ftp)://[^\s/$.?#].[^\s]*$'

    # 使用 re 模組檢測是否符合正規表達式
    match = re.match(pattern, url)

    # 若找到匹配，表示是有效的 URL；否則不是
    return bool(match)


def is_sha1(input_string):
    # 定義 SHA-1 的正規表達式
    sha1_pattern = r"^[0-9a-fA-F]{40}$"

    # 使用 re 模組檢測是否符合 SHA-1 格式
    if re.match(sha1_pattern, input_string):
        return True

    return False






def generate_random_string(length):
    # 可視字元集合
    visible_chars = string.ascii_letters + string.digits
    
    # 隨機選取字元組成亂碼
    random_string = ''.join(random.choice(visible_chars) for _ in range(length))
    
    return random_string
