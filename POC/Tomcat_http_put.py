import requests
import random


def put(url):
    url = url.strip('/')
    text = random.randint(100000000, 200000000)
    payload = '/{}.txt'.format(text)
    url = url + payload
    data = {'{}'.format(text): '{}'.format(text)}
    header = {"user-agent":"Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/62.0.3202.9 Safari/537.36"}
    r = requests.put(url, data=data, allow_redirects=False, verify=False, headers=header)
    if r.status_code == 201:
        print('[+]HTTP METHOD PUT url: {}'.format(url))
    else:
        print('[-]target is not vulnerable')

print('[*]Usage: [URL]')
def check(url):
    put(url)
