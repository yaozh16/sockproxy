# -*- coding: utf-8 -*-
# desc: 测试使用socks5代理访问

import socket
import socks
from urllib import request
from urllib.error import URLError

# 设置代理
socks.set_default_proxy(socks.SOCKS5, "183.172.167.238", 22023, username='yaozh16', password='123456')
socket.socket = socks.socksocket

test_url = 'http://learn.tsinghua.edu.cn'
try:
    response = request.urlopen(test_url)
    print(response.read().decode('utf-8'))
except URLError as e:
    print(e.reason)