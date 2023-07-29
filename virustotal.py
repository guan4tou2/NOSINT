# apikey="e8695c6e0fd2ed7ec1de4d3231db19812c68fec161da3757df0caeb87fd0318a"
apikey="cc855fa0db979f063e3eb5322d4ac691c110e73030f5d063881d1cf310f5b725"
import requests
import orjson

def get_domain(domain:str):
    url = "https://www.virustotal.com/api/v3/domains/"+domain

    headers = {
        "accept": "application/json",
        "x-apikey": apikey
    }
    response = requests.get(url, headers=headers)
    data=orjson.loads(response.text)["data"]["attributes"]
    return {'last_analysis_stats':data['last_analysis_stats'],'registrar':data['registrar'],'reputation':data['reputation'],'last_https_certificate':data['last_https_certificate']["validity"]["not_after"],"total_votes":data["total_votes"]}

def get_url_report(id:str):
    url = "https://www.virustotal.com/api/v3/urls/"+id 

    headers = {
        "accept": "application/json",
        "x-apikey": apikey
    }

    response = requests.get(url, headers=headers)

    return response.text

def get_url(url:str):
    url = "https://www.virustotal.com/api/v3/urls"

    payload = { "url": url }
    headers = {
        "accept": "application/json",
        "x-apikey": apikey,
        "content-type": "application/x-www-form-urlencoded"
    }

    response = requests.post(url, data=payload, headers=headers)

    url_id=orjson.loads(response.text)["data"]['id']
    url_id=url_id.split('-')[1]
    return orjson.loads(get_url_report(url_id))["data"]["attributes"]

