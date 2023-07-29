import requests
import orjson
from hashlib import sha1
import re

def get_domain(domain):
    result = requests.get(
        'https://haveibeenpwned.com/api/v3/breaches?domain='+domain, timeout=5)
    if result.text=='[]':
        return {"PwnCount":0,"DataClasses":[]} #"ModifiedDate":0,
    data=orjson.loads(result.text[1:-1])
    return {"PwnCount":data["PwnCount"],"DataClasses":data["DataClasses"]}

def get_password(password):
    # pw = sha1()
    # pw.update(password.encode())
    # pw = pw.hexdigest().upper()
    result = requests.get("https://api.pwnedpasswords.com/range/"+password[:5], timeout=5).text
    print(result)
    counter=re.search(password[5:]+r":(\d*)", result)
    if counter is None:
        return counter
    return counter.group(1)

