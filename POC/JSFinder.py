#!/usr/bin/env python
# coding: utf-8

#匹配输入网址script标签src属性的所有js链接内容+当前页面自定义的JS+当前页面link标签的href属性链接, 使用正则进行提取

#过滤后缀
black_suf = ['vue','svg','css','gif','js','jpg','png','html']
#修改 header 使其能够在后台运作
header = {
	"User-Agent": "Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/62.0.3202.9 Safari/537.36",
	"Connection": "close",
	"Cookie": ''
}

import requests, argparse, sys, re
from requests.packages import urllib3
from urllib.parse import urlparse
#from urlparse import urlparse
from bs4 import BeautifulSoup
import random
urllib3.disable_warnings()

# Regular expression comes from https://github.com/GerbenJavado/LinkFinder
def extract_URL(JS):
	pattern_raw = """
	  (?:"|')                               # Start newline delimiter
	  (
	    ((?:[a-zA-Z]{1,10}://|//)           # Match a scheme [a-Z]*1-10 or //
	    [^"'/]{1,}\.                        # Match a domainname (any character + dot)
	    [a-zA-Z]{2,}[^"']{0,})              # The domainextension and/or path
	    |
	    ((?:/|\.\./|\./)                    # Start with /,../,./
	    [^"'><,;| *()(%%$^/\\\[\]]          # Next character can't be...
	    [^"'><,;|()]{1,})                   # Rest of the characters can't be
	    |
	    ([a-zA-Z0-9_\-/]{1,}/               # Relative endpoint with /
	    [a-zA-Z0-9_\-/]{1,}                 # Resource name
	    \.(?:[a-zA-Z]{1,4}|action)          # Rest + extension (length 1-4 or action)
	    (?:[\?|/][^"|']{0,}|))              # ? mark with parameters
	    |
	    ([a-zA-Z0-9_\-]{1,}                 # filename
	    \.(?:php|asp|aspx|jsp|json|
	         action|html|js|txt|xml)             # . + extension
	    (?:\?[^"|']{0,}|))                  # ? mark with parameters
	  )
	  (?:"|')                               # End newline delimiter
	"""
	pattern = re.compile(pattern_raw, re.VERBOSE)
	result = re.finditer(pattern, str(JS))
	if result == None:
		return None
	js_url = []
	return [match.group().strip('"').strip("'") for match in result
		if match.group() not in js_url]

# GET HTML source
def Extract_html(URL):
	try:
		#后台session请求
		session = requests.Session()
		#verify=False HTTPS请求设置
		raw = session.get(URL, headers=header, timeout=3, verify=False)
		#外网请求
		#raw = requests.get(URL, headers=header, timeout=3)
		charset = raw.apparent_encoding
		raw = raw.content.decode(charset if charset != None else 'utf-8', "ignore")
		#print(raw)
		return raw
	except Exception as e:
		print('url请求出错, %s'%type(e))
		return None

# Handling relative URLs
def process_url(URL, re_URL):
	black_url = ["javascript:"]	# Add some keyword for filter url.
	URL_raw = urlparse(URL)
	ab_URL = URL_raw.netloc
	host_URL = URL_raw.scheme
	if re_URL[0:2] == "//":
		result = host_URL  + ":" + re_URL
	elif re_URL[0:4] == "http":
		result = re_URL
	elif re_URL[0:2] != "//" and re_URL not in black_url:
		if re_URL[0:1] == "/":
			result = host_URL + "://" + ab_URL + re_URL
		else:
			if re_URL[0:1] == ".":
				if re_URL[0:2] == "..":
					result = host_URL + "://" + ab_URL + re_URL[2:]
				else:
					result = host_URL + "://" + ab_URL + re_URL[1:]
			else:
				result = host_URL + "://" + ab_URL + "/" + re_URL
	else:
		result = URL
	return result

def find_last(string,str):
	positions = []
	last_position=-1
	while True:
		position = string.find(str,last_position+1)
		if position == -1:break
		last_position = position
		positions.append(position)
	return positions


def find_by_url(url, js = False):
	if js == False:
		try:
			print("url:" + url)
		except:
			print("Please specify a URL like https://www.baidu.com")
		#print('5')
		html_raw = Extract_html(url)
		if html_raw == None: 
			print("Fail to access " + url)
			return None
		#print(html_raw)
		html = BeautifulSoup(html_raw, "html.parser")
		html_scripts = html.findAll("script")
		script_array = {}
		script_temp = ""
		for html_script in html_scripts:
			script_src = html_script.get("src")
			#script标签没有src属性, 说明是在当前页面script标签里自定义的JS
			if script_src == None:
				script_temp += html_script.get_text() + "\n"
			else:
				purl = process_url(url, script_src)
				script_array[purl] = Extract_html(purl)
		#加上url当前页面script标签自定义的JS
		script_array[url] = script_temp
		#加上请求url返回的html
		script_array[url+'index'] = html_raw
		allurls = []

		# script_array 键是 JS 链接,值是链接返回的 html,在 JS 文件里根据正则匹配结果,然后汇总到 allurls
		for script in script_array:
			#print(script)
			temp_urls = extract_URL(script_array[script])
			if len(temp_urls) == 0: continue
			for temp_url in temp_urls:
				allurls.append(process_url(script, temp_url))
		
		# 添加 url html里link标签下的href属性到 allurls
		html_links = html.findAll("link")
		for html_link in html_links:
			link_href = html_link.get("href")
			if link_href != None:
				allurls.append(process_url(url,link_href))

		result = []
		#过滤后缀
		#black_suf = ['vue','svg','css','gif','js','jpg','png']
		#查找 allurls 中和 url 同根域下的链接, 返回结果为 result 列表
		for singerurl in allurls:
			suf = singerurl[singerurl.rfind('.')+1:]
			if suf in black_suf: continue
			url_raw = urlparse(url)
			domain = url_raw.netloc
			positions = find_last(domain, ".")
			miandomain = domain
			if len(positions) > 1:miandomain = domain[positions[-2] + 1:]
			#print(miandomain)
			suburl = urlparse(singerurl)
			subdomain = suburl.netloc
			#print(singerurl)
			if miandomain in subdomain or subdomain.strip() == "":
				if singerurl.strip() not in result:
					result.append(singerurl)
		return result
	return sorted(set(extract_URL(Extract_html(url)))) or None


def find_subdomain(urls, mainurl):
	url_raw = urlparse(mainurl)
	domain = url_raw.netloc
	miandomain = domain
	positions = find_last(domain, ".")
	if len(positions) > 1:miandomain = domain[positions[-2] + 1:]
	subdomains = []
	for url in urls:
		suburl = urlparse(url)
		subdomain = suburl.netloc
		#print(subdomain)
		if subdomain.strip() == "": continue
		if miandomain in subdomain:
			if subdomain not in subdomains:
				subdomains.append(subdomain)
	return subdomains

def find_by_url_deep(url, links):
	
	html_raw = Extract_html(url)
	if html_raw == None: 
		print("Fail to access " + url)
		return None
	html = BeautifulSoup(html_raw, "html.parser")
	html_as = html.findAll("a")
	#links = []
	for html_a in html_as:
		src = html_a.get("href")
		if src == "" or src == None: continue
		link = process_url(url, src)
		if link not in links:
			links.append(link)

	if links == []: return None
	print("ALL Find " + str(len(links)) + " links")
	urls = []
	i = len(links)
	for link in links:
		#print('1')
		temp_urls = find_by_url(link)
		if temp_urls == None: continue
		print("Remaining " + str(i) + " | Find " + str(len(temp_urls)) + " URL in " + link)
		for temp_url in temp_urls:
			if temp_url not in urls:
				urls.append(temp_url)
		urls.append(link)
		i -= 1
	return urls

#结果输出
def giveresult(urls, domian):
	if urls == None:
		return None
	print("\nFind " + str(len(urls)) + " URL:")
	content_url = ""
	content_subdomain = ""
	for url in urls:
		content_url += url + "\n"
		print(url)
	subdomains = find_subdomain(urls, domian)
	print("\nFind " + str(len(subdomains)) + " Subdomain:")
	for subdomain in subdomains:
		content_subdomain += subdomain + "\n"
		print(subdomain)


print("JSFinder利用说明: 适用于正常引用JS的网站\n1、获取当前页面script标签src属性的JS,和script标签自定义的JS, 访问这些JS后用正则提取相关链接\n2、提取当前页面link标签的href\n3、修改cookies使其能够在后台运作")
def check(**kwargs):
	urls = find_by_url(kwargs['url'])
	#urls = find_by_url_deep(kwargs['url'],urls)
	giveresult(urls, kwargs['url'])


if __name__ == "__main__":
	urls = find_by_url('http://www.so50.com/contactus/')
	urls = find_by_url_deep('http://www.so50.com/contactus/',urls)
	giveresult(urls, 'http://www.so50.com/contactus/')
	





















