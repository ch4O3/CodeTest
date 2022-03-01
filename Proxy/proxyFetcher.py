# -*- coding: utf-8 -*-
"""
-------------------------------------------------
   File Name：     proxyFetcher
   Description :
   Author :        JHao
   date：          2016/11/25
-------------------------------------------------
   Change Activity:
                   2016/11/25: proxyFetcher
-------------------------------------------------
"""
__author__ = 'JHao'
import re
from time import sleep

from Proxy.WebRequest import WebRequest

class ProxyFetcher(object):
    """
    proxy getter
    """

    @staticmethod
    def freeProxy01(page_count=3):
        """
        米扑代理 https://proxy.mimvp.com/
        :return:
        """
        url_list = [
            'https://proxy.mimvp.com/freeopen',
            'https://proxy.mimvp.com/freeopen?proxy=in_tp'
        ]
        url = 'https://proxy.mimvp.com/freeopen?proxy=in_hp&sort=&page={}'
        port_img_map = {'DMxMjg': '3128', 'Dgw': '80', 'DgwODA': '8080',
                        'DgwOA': '808', 'DgwMDA': '8000', 'Dg4ODg': '8888',
                        'DgwODE': '8081', 'Dk5OTk': '9999'}
        for i in range(1, page_count + 1):
        #for url in url_list:
            html_tree = WebRequest().get(url.format(i)).tree
            for tr in html_tree.xpath(".//table[@class='mimvp-tbl free-proxylist-tbl']/tbody/tr"):
                try:
                    ip = ''.join(tr.xpath('./td[2]/text()'))
                    port_img = ''.join(tr.xpath('./td[3]/img/@src')).split("port=")[-1]
                    port = port_img_map.get(port_img[14:].replace('O0O', ''))
                    https = ''.join(tr.xpath('./td[4]/text()'))
                    anonymous = ''.join(tr.xpath('./td[5]/text()'))
                    if port:
                        proxy = ip+':'+port
                        yield '%s|%s|%s' % (proxy, https, anonymous)
                except Exception as e:
                    print(e)

    @staticmethod
    def freeProxy02(page_count=3):
        """
        代理66 http://www.66ip.cn/
        :return:
        """
        url = "http://www.66ip.cn/mo.php"

        resp = WebRequest().get(url, timeout=10)
        proxies = re.findall(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}:\d{1,5})', resp.text)
        for proxy in proxies:
            yield proxy

    @staticmethod
    def freeProxy03(page_count=3):
        """
        pzzqz https://pzzqz.com/
        """
        from requests import Session
        from lxml import etree
        session = Session()
        try:
            index_resp = session.get("https://pzzqz.com/", timeout=20, verify=False).text
            x_csrf_token = re.findall('X-CSRFToken": "(.*?)"', index_resp)
            if x_csrf_token:
                data = {"http": "on", "ping": "3000", "country": "cn", "ports": ""}
                proxy_resp = session.post("https://pzzqz.com/", verify=False,
                                          headers={"X-CSRFToken": x_csrf_token[0]}, json=data).json()
                tree = etree.HTML(proxy_resp["proxy_html"])
                for tr in tree.xpath("//tr"):
                    ip = "".join(tr.xpath("./td[1]/text()"))
                    port = "".join(tr.xpath("./td[2]/text()"))
                    yield "%s:%s" % (ip, port)
        except Exception as e:
            print(e)

    @staticmethod
    def freeProxy04(page_count=3):
        """
        神鸡代理 http://www.shenjidaili.com/
        :return:
        """
        url = "http://www.shenjidaili.com/product/open/"
        tree = WebRequest().get(url).tree
        for table in tree.xpath("//table[@class='table table-hover text-white text-center table-borderless']"):
            for tr in table.xpath("./tr")[1:]:
                proxy = ''.join(tr.xpath("./td[1]/text()"))
                yield proxy.strip()

    @staticmethod
    def freeProxy05(page_count=3):
        """
        快代理 https://www.kuaidaili.com
        """
        url_pattern = [
            'https://www.kuaidaili.com/free/inha/{}/',
            'https://www.kuaidaili.com/free/intr/{}/'
        ]
        url_list = []
        for page_index in range(1, page_count + 1):
            for pattern in url_pattern:
                url_list.append(pattern.format(page_index))

        for url in url_list:
            tree = WebRequest().get(url).tree
            proxy_list = tree.xpath('.//table//tr')
            sleep(1)  # 必须sleep 不然第二条请求不到数据
            for tr in proxy_list[1:]:
                proxy = ':'.join(tr.xpath('./td/text()')[0:2])
                yield proxy+'|'+'|'.join(tr.xpath('./td/text()')[2:4][::-1])

    @staticmethod
    def freeProxy06(page_count=3):
        """
        极速代理 https://www.superfastip.com/
        :return:
        """
        url = "https://api.superfastip.com/ip/freeip?page={page_count}"
        for page in range(page_count):
            page_url = url.format(page_count=page + 1)
            try:
                resp_json = WebRequest().get(page_url).json
                for each in resp_json.get("freeips", []):
                    yield "%s:%s" % (each.get("ip", ""), each.get("port", ""))
            except Exception as e:
                print(e)

    @staticmethod
    def freeProxy07(page_count=3):
        """
        云代理 http://www.ip3366.net/free/
        :return:
        """
        urls = ['http://www.ip3366.net/free/?stype=1',
                "http://www.ip3366.net/free/?stype=2"]
        url = 'http://www.ip3366.net/free/?stype=1&page={}'
        for page in range(1, page_count + 1):
        #for url in urls:
            tree = WebRequest().get(url.format(page), timeout=10).tree
            proxy_list = tree.xpath('.//table[contains(@class,"table table-bordered")]//tr')
            sleep(1)  # 必须sleep 不然第二条请求不到数据
            for tr in proxy_list[1:]:
                proxy = ':'.join(tr.xpath('./td/text()')[0:2])
                yield proxy+'|'+'|'.join(tr.xpath('./td/text()')[2:4][::-1])
            #proxies = re.findall(r'<td>(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})</td>[\s\S]*?<td>(\d+)</td>', r.text)
            #for proxy in proxies:
                #yield ":".join(proxy)

    @staticmethod
    def freeProxy08(page_count=3):
        """
        小幻代理 https://ip.ihuan.me/
        :return:
        """
        urls = [
            'https://ip.ihuan.me/address/5Lit5Zu9.html',
        ]
        for url in urls:
            tree = WebRequest().get(url, timeout=10).tree
            proxy_list = tree.xpath('.//table[contains(@class,"table table-hover")]//tr')
            sleep(1)  # 必须sleep 不然第二条请求不到数据
            for tr in proxy_list[1:]:
                ip = tr.xpath('./td[1]/a/text()')[0]
                port = tr.xpath('./td[2]/text()')[0]
                https = tr.xpath('./td[5]/text()')[0]
                anonymous = tr.xpath('./td[7]/a/text()')[0]
                yield ip+':'+port+'|'+https+'|'+anonymous
            #proxies = re.findall(r'>\s*?(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s*?</a></td><td>(\d+)</td>',
            #                     r.text)
            #for proxy in proxies:
            #    yield ":".join(proxy)

    @staticmethod
    def freeProxy09(page_count=3):
        """
        http://ip.jiangxianli.com/
        免费代理库
        :return:
        """
        for i in range(1, page_count + 1):
            url = 'http://ip.jiangxianli.com/?country=中国&page={}'.format(i)
            tree = WebRequest().get(url).tree
            proxy_list = tree.xpath('.//table//tr')
            sleep(1)  # 必须sleep 不然第二条请求不到数据
            for tr in proxy_list[1:]:
                if tr.xpath("./td[@colspan='11']"):
                    continue
                ip = tr.xpath("./td[1]/text()")[0]
                port = tr.xpath("./td[2]/text()")[0]
                https = tr.xpath("./td[4]/text()")[0]
                anonymous = tr.xpath("./td[3]/text()")[0]
                yield ip+':'+port+'|'+https+'|'+anonymous
            #for index, tr in enumerate(html_tree.xpath("//table//tr")):
            #    if index == 0:
            #        continue


    # @staticmethod
    # def freeProxy10():
    #     """
    #     墙外网站 cn-proxy
    #     :return:
    #     """
    #     urls = ['http://cn-proxy.com/', 'http://cn-proxy.com/archives/218']
    #     request = WebRequest()
    #     for url in urls:
    #         r = request.get(url, timeout=10)
    #         proxies = re.findall(r'<td>(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})</td>[\w\W]<td>(\d+)</td>', r.text)
    #         for proxy in proxies:
    #             yield ':'.join(proxy)

    # @staticmethod
    # def freeProxy11():
    #     """
    #     https://proxy-list.org/english/index.php
    #     :return:
    #     """
    #     urls = ['https://proxy-list.org/english/index.php?p=%s' % n for n in range(1, 10)]
    #     request = WebRequest()
    #     import base64
    #     for url in urls:
    #         r = request.get(url, timeout=10)
    #         proxies = re.findall(r"Proxy\('(.*?)'\)", r.text)
    #         for proxy in proxies:
    #             yield base64.b64decode(proxy).decode()

    # @staticmethod
    # def freeProxy12():
    #     urls = ['https://list.proxylistplus.com/Fresh-HTTP-Proxy-List-1']
    #     request = WebRequest()
    #     for url in urls:
    #         r = request.get(url, timeout=10)
    #         proxies = re.findall(r'<td>(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})</td>[\s\S]*?<td>(\d+)</td>', r.text)
    #         for proxy in proxies:
    #             yield ':'.join(proxy)

    @staticmethod
    def freeProxy13(page_count=3):
        """
        http://www.89ip.cn/index.html
        89免费代理
        :param page_count:
        :return:
        """
        base_url = 'http://www.89ip.cn/index_{}.html'
        for page in range(1, page_count + 1):
            url = base_url.format(page)
            r = WebRequest().get(url, timeout=10)
            proxies = re.findall(
                r'<td.*?>[\s\S]*?(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})[\s\S]*?</td>[\s\S]*?<td.*?>[\s\S]*?(\d+)[\s\S]*?</td>',
                r.text)
            for proxy in proxies:
                yield ':'.join(proxy)+'|未知'+'|未知'

    @staticmethod
    def freeProxy14(page_count=3):
        """
        http://www.xiladaili.com/
        西拉代理
        :return:
        """
        urls = ['http://www.xiladaili.com/']
        url = 'http://www.xiladaili.com/gaoni/{}/'
        for page in range(1, page_count + 1):
        #for url in urls:
            tree = WebRequest().get(url.format(page), timeout=10).tree
            proxy_list = tree.xpath('.//table[@class="fl-table"]//tr')
            sleep(1)  # 必须sleep 不然第二条请求不到数据
            for tr in proxy_list[1:]:
                proxy = tr.xpath('./td[1]/text()')[0]
                https = tr.xpath('./td[2]/text()')[0]
                anonymous = tr.xpath('./td[3]/text()')[0]
                yield proxy+'|'+https+'|'+anonymous
            #ips = re.findall(r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}:\d{1,5}", r.text)
            #for ip in ips:
            #    yield ip.strip()


if __name__ == '__main__':
    p = ProxyFetcher()
    for _ in p.freeProxy01():
        print(_)
