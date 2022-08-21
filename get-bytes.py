from urllib import request
import json
from lxml import html
import base64
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_v1_5

"""
settings
"""
username_plain = "admin"
password_plain = ""
ip = "192.168.1.1"
fw_version = "v1.0.12"


"""
Login
"""
#GET enc_pub_key
key_url = "http://" + ip + "/api/login"

key_req = request.Request(key_url)
with request.urlopen(key_req) as key_res:
    key_results = json.load(key_res)
enc_pub_key = key_results["enc_pub_key"]

def jsencrypt_modoki(input):
    pub_key = '-----BEGIN PUBLIC KEY-----\n' + enc_pub_key + '\n-----END PUBLIC KEY-----'
    rsakey = RSA.importKey(pub_key)
    ang = PKCS1_v1_5.new(rsakey)
    out_text = base64.b64encode(ang.encrypt(input.encode()))
    return out_text.decode()

username = jsencrypt_modoki(username_plain)
password = jsencrypt_modoki(password_plain)

LoginAPIURL = "http://" + ip + "/api/login"

postdata = {
    "device_name": "NSD-G1000T",
    "device_type": "NSD-G1000T",
    "enc_pub_key": enc_pub_key,
    "error_count": "",
    "fw_version": fw_version,
    "lang_code": "jp",
    "password": password,
    "return_code": "",
    "username": username,
    "wait_time": ""
}
headers = {
    'Content-Type': 'application/json',
}

loginreq = request.Request(LoginAPIURL, json.dumps(postdata).encode(), headers)
with request.urlopen(loginreq) as loginres:
    headers = loginres.info()

Set_Cookie = headers["Set-Cookie"]
cookie = Set_Cookie.replace("; Path=/; HttpOnly","")


"""
GET CSRF token
"""
PageURL = "http://" + ip + "/pages.html"

cookie_header = {
    "Cookie": cookie,
}

csrfreq = request.Request(PageURL,headers=cookie_header)
csrfsource = request.urlopen(csrfreq)
csrfdata = csrfsource.read()
load_html = html.fromstring(str(csrfdata))

h1_content = load_html.xpath("//script[1]")
for content in h1_content:
    csrf_data = content.text[25:-7]



"""
GET bytes from API
"""
APIURL = "http://" + ip + "/api/support/wan&csrf_token=" + csrf_data

APIreq = request.Request(APIURL,headers=cookie_header)
with request.urlopen(APIreq) as APIres:
    APIresults = json.load(APIres)

received = APIresults["ipv4_recvd_bytes"] + APIresults["ipv6_recvd_bytes"]
transmitted = APIresults["ipv4_trans_bytes"] + APIresults["ipv6_trans_bytes"]

print(str(received) + "," + str(transmitted))



"""
LOGOUT
"""
LogoutURL = "http://" + ip + "/api/logout&csrf_token=" + csrf_data

logout_postdata = {
    "username": username_plain
}
logout_headers = {
    'Content-Type': 'application/json',
    "Cookie": cookie
}

req = request.Request(LogoutURL, json.dumps(logout_postdata).encode(), logout_headers)
with request.urlopen(req) as res:
    body = res.read()