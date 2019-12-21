# -*- coding: utf-8 -*-

import select
import socket
import json
import struct
from socketserver import StreamRequestHandler as Tcp, ThreadingTCPServer

SOCKS_VERSION = 5                           # socks版本

global_config = {}
"""
+++++++++++++++++++++++++++++++++++++++++++++++++++++++++

    一、客户端认证请求
        +----+----------+----------+
        |VER | NMETHODS | METHODS  |
        +----+----------+----------+
        | 1  |    1     |  1~255   |
        +----+----------+----------+
    二、服务端回应认证
        +----+--------+
        |VER | METHOD |
        +----+--------+
        | 1  |   1    |
        +----+--------+
    三、客户端连接请求(连接目的网络)
        +----+-----+-------+------+----------+----------+
        |VER | CMD |  RSV  | ATYP | DST.ADDR | DST.PORT |
        +----+-----+-------+------+----------+----------+
        | 1  |  1  |   1   |  1   | Variable |    2     |
        +----+-----+-------+------+----------+----------+
    四、服务端回应连接
        +----+-----+-------+------+----------+----------+
        |VER | REP |  RSV  | ATYP | BND.ADDR | BND.PORT |
        +----+-----+-------+------+----------+----------+
        | 1  |  1  |   1   |  1   | Variable |    2     |
        +----+-----+-------+------+----------+----------+

++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
"""


class SockProxy(Tcp):
    def log(self, msg):
        print("[{}]{}".format(self.client_address, msg))

    def getNByte(self, n, msg=""):
        recv = b''
        recv += bytes(self.request.recv(n - len(recv)))
        self.log("[ {} ] recv: ({}/{}): {}".format(msg, len(recv), n, recv))
        while len(recv) < n:
            recv += self.request.recv(n - len(recv))
        return recv

    def handle(self):
        self.log("客户端请求连接！")
        if "*" not in global_config["whitelist"] and self.client_address[0] not in global_config["whitelist"]:
            self.log("异常连接，断开")
            self.server.close_request(self.request)
            return

        """
        一、客户端认证请求
            +----+----------+----------+
            |VER | NMETHODS | METHODS  |
            +----+----------+----------+
            | 1  |    1     |  1~255   |
            +----+----------+----------+
        """
        # 从客户端读取并解包两个字节的数据
        header = self.getNByte(2, "header")
        VER, NMETHODS = struct.unpack("!BB", header)
        # 设置socks5协议，METHODS字段的数目大于0
        assert VER == SOCKS_VERSION, 'SOCKS版本错误'

        # 接受支持的方法
        # 无需认证：0x00    用户名密码认证：0x02
        # assert NMETHODS > 0
        methods = self.IsAvailable(NMETHODS)
        # 检查是否支持该方式，不支持则断开连接
        if 0 not in set(methods):
            self.server.close_request(self.request)
            return

        """
        二、服务端回应认证
            +----+--------+
            |VER | METHOD |
            +----+--------+
            | 1  |   1    |
            +----+--------+
        """
        # 发送协商响应数据包
        if ("username" in global_config and "password" in global_config) and \
                not("auth" in global_config and not global_config["auth"]):
            self.connection.sendall(struct.pack("!BB", SOCKS_VERSION, 0x02))
            # 校验用户名和密码
            if not self.VerifyAuth(self.request):
                self.server.close_request(self.request)
                self.log("Auth failed")
                return
            else:
                self.log("Auth succeed")
        else:
            self.request.sendall(struct.pack("!BB", SOCKS_VERSION, 0x00))

        """
        三、客户端连接请求(连接目的网络)
            +----+-----+-------+------+----------+----------+
            |VER | CMD |  RSV  | ATYP | DST.ADDR | DST.PORT |
            +----+-----+-------+------+----------+----------+
            | 1  |  1  |   1   |  1   | Variable |    2     |
            +----+-----+-------+------+----------+----------+
        """
        version, cmd, _, address_type = struct.unpack("!BBBB", self.request.recv(4))
        assert version == SOCKS_VERSION, 'socks版本错误'

        if address_type == 1:       # IPv4
            # 转换IPV4地址字符串（xxx.xxx.xxx.xxx）成为32位打包的二进制格式（长度为4个字节的二进制字符串）
            address = socket.inet_ntoa(self.request.recv(4))
        elif address_type == 3:     # Domain
            domain_length = ord(self.getNByte(1, 'domain_length'))
            address = self.getNByte(domain_length, "domain")
        else:   # TODO: IPv6
            self.server.close_request(self.request)
            return
        port = struct.unpack('!H', self.request.recv(2))[0]

        self.log("客户端校验成功")
        """
        四、服务端回应连接
            +----+-----+-------+------+----------+----------+
            |VER | REP |  RSV  | ATYP | BND.ADDR | BND.PORT |
            +----+-----+-------+------+----------+----------+
            | 1  |  1  |   1   |  1   | Variable |    2     |
            +----+-----+-------+------+----------+----------+
        """
        # 响应，只支持CONNECT请求
        try:
            if cmd == 1:  # CONNECT
                self.log("尝试连接远程服务器")
                remote = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                remote.connect((address, port))
                bind_address = remote.getsockname()
                self.log('已建立连接到：{}:{} bind:{}'.format(address, port, bind_address))
            else:
                # TODO: exit
                self.log("cmd = {} ,断开".format(cmd))
                self.server.close_request(self.request)
                return
            addr = struct.unpack("!I", socket.inet_aton(bind_address[0]))[0]
            # print(addr)
            # print(struct.unpack("!I", socket.inet_aton(bind_address[0])))
            # print(socket.inet_aton(bind_address[0]))

            port = bind_address[1]
            self.log("构造返回包")
            reply = struct.pack("!BBBBIH", SOCKS_VERSION, 0, 0, 0x01, addr, port)
            self.log("发送返回包")
            self.request.sendall(reply)     # 发送回复包
            self.log("发送返回包完毕")
        except Exception as err:
            self.log(err)
            # 响应拒绝连接的错误
            reply = struct.pack("!BBBBIH", SOCKS_VERSION, 5, 0, address_type, 0, 0)
            self.request.sendall(reply)      # 发送回复包
            self.server.close_request(self.request)
            return

        # 建立连接成功，开始交换数据
        if reply[1] == 0 and cmd == 1:
            self.ExchangeData(self.request, remote)
        self.server.close_request(self.request)
        self.log("handle done")

    def IsAvailable(self, n):
        """
        检查是否支持该验证方式
        """
        methods = []
        for i in range(n):
            methods.append(ord(self.getNByte(1, "method")))
        return methods

    def VerifyAuth(self, current_request):
        """
        校验用户名和密码
        """
        version = ord(self.getNByte(1, "verify version"))
        assert version == 1, print(version)
        username_len = ord(self.getNByte(1))
        username = self.getNByte(username_len, "username").decode('utf-8')
        self.log(username)
        password_len = ord(self.getNByte(1))
        password = self.getNByte(password_len, "password").decode('utf-8')
        self.log(password)
        if username == global_config["username"] and password == global_config["password"]:
            # 验证成功, status = 0
            response = struct.pack("!BB", version, 0)
            current_request.sendall(response)
            return True
        else:
            # 验证失败, status != 0
            response = struct.pack("!BB", version, 0xFF)
            current_request.sendall(response)
            self.server.close_request(current_request)
            return False

    def ExchangeData(self, client, remote):
        """
        交换数据 
        """
        self.log("ready to exchange data")
        #init_data = client.recv(4096)
        #remote.send(init_data)

        while True:
            # 等待数据
            rs, ws, es = select.select([client, remote], [], [])
            if client in rs:
                data = client.recv(4096)
                self.log("client to remote:{}".format(len(data)))
                if remote.send(data) <= 0:
                    break
            if remote in rs:
                data = remote.recv(4096)
                self.log("remote to client:{}".format(len(data)))
                if client.send(data) <= 0:
                    break


if __name__ == '__main__':
    global_config = json.load(open("server_config.json"))
    # 服务器上创建一个TCP多线程服务，监听端口
    Server = ThreadingTCPServer((global_config["server_address"], global_config["server_port"]), SockProxy)
    print("listening")
    Server.serve_forever()