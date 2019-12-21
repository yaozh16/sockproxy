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

    def handle(self):
        print("客户端：", self.client_address, " 请求连接！")
        current_request = self.request
        current_connection = self.connection
        if "*" not in global_config["whitelist"] and self.client_address[0] not in global_config["whitelist"]:
            print("异常连接，断开")
            self.server.close_request(current_request)
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
        header = current_connection.recv(2)
        VER, NMETHODS = struct.unpack("!BB", header)
        # 设置socks5协议，METHODS字段的数目大于0
        assert VER == SOCKS_VERSION, 'SOCKS版本错误'
        
        # 接受支持的方法
        # 无需认证：0x00    用户名密码认证：0x02
        # assert NMETHODS > 0
        methods = self.IsAvailable(NMETHODS, current_connection)
        # 检查是否支持该方式，不支持则断开连接
        if 0 not in set(methods):
            self.server.close_request(current_request)
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
        if "username" in global_config and "password" in global_config:
            current_connection.sendall(struct.pack("!BB", SOCKS_VERSION, 0x02))
            # 校验用户名和密码
            if not self.VerifyAuth(current_request, current_connection):
                self.server.close_request(current_request)
                print("Auth failed")
                return
            else:
                print("Auth succeed")
        else:
            current_connection.sendall(struct.pack("!BB", SOCKS_VERSION, 0x00))

        """
        三、客户端连接请求(连接目的网络)
            +----+-----+-------+------+----------+----------+
            |VER | CMD |  RSV  | ATYP | DST.ADDR | DST.PORT |
            +----+-----+-------+------+----------+----------+
            | 1  |  1  |   1   |  1   | Variable |    2     |
            +----+-----+-------+------+----------+----------+
        """
        version, cmd, _, address_type = struct.unpack("!BBBB", current_connection.recv(4))
        assert version == SOCKS_VERSION, 'socks版本错误'

        if address_type == 1:       # IPv4
            # 转换IPV4地址字符串（xxx.xxx.xxx.xxx）成为32位打包的二进制格式（长度为4个字节的二进制字符串）
            address = socket.inet_ntoa(current_connection.recv(4))
        elif address_type == 3:     # Domain
            domain_length = ord(current_connection.recv(1)[0])
            address = current_connection.recv(domain_length)
        else:   # TODO: IPv6
            self.server.close_request(current_request)
            return
        port = struct.unpack('!H', current_connection.recv(2))[0]

        print("connection built")
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
                remote = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                remote.connect((address, port))
                bind_address = remote.getsockname()
                print(self.client_address, '已建立连接到：', address, port)
            else:
                # TODO: exit
                self.server.close_request(current_request)
                return
            addr = struct.unpack("!I", socket.inet_aton(bind_address[0]))[0]
            port = bind_address[1]
            reply = struct.pack("!BBBBIH", SOCKS_VERSION, 0, 0, address_type, addr, port)
            current_connection.sendall(reply)      # 发送回复包
        except Exception as err:
            print(err)
            # 响应拒绝连接的错误
            reply = struct.pack("!BBBBIH", SOCKS_VERSION, 5, 0, address_type, 0, 0)
            current_connection.sendall(reply)      # 发送回复包
            self.server.close_request(current_request)
            return

        # 建立连接成功，开始交换数据
        if reply[1] == 0 and cmd == 1:
            self.ExchangeData(current_connection, remote)
        self.server.close_request(current_request)
        print("done")

    def IsAvailable(self, n, current_connection):
        """ 
        检查是否支持该验证方式 
        """
        methods = []
        for i in range(n):
            methods.append(ord(current_connection.recv(1)))
        return methods

    def VerifyAuth(self, current_request, current_connection):
        """
        校验用户名和密码
        """
        version = ord(current_connection.recv(1))
        assert version == 1, print(version)
        username_len = ord(current_connection.recv(1))
        username = current_connection.recv(username_len).decode('utf-8')
        print(username)
        password_len = ord(current_connection.recv(1))
        password = current_connection.recv(password_len).decode('utf-8')
        print(password)
        if username == global_config["username"] and password == global_config["password"]:
            # 验证成功, status = 0
            response = struct.pack("!BB", version, 0)
            current_connection.sendall(response)
            return True
        else:
            # 验证失败, status != 0
            response = struct.pack("!BB", version, 0xFF)
            current_connection.sendall(response)
            self.server.close_request(current_request)
            return False

    def ExchangeData(self, client, remote):
        """ 
        交换数据 
        """
        print("exchange data")
        while True:
            # 等待数据
            rs, ws, es = select.select([client, remote], [], [])
            if client in rs:
                data = client.recv(4096)
                print("client to remote:", len(data))
                if remote.send(data) <= 0:
                    break
            if remote in rs:
                data = remote.recv(4096)
                print("remote to client:", len(data))
                if client.send(data) <= 0:
                    break


if __name__ == '__main__':
    global_config = json.load(open("server_config.json"))
    # 服务器上创建一个TCP多线程服务，监听端口
    Server = ThreadingTCPServer((global_config["server_address"], global_config["server_port"]), SockProxy)
    print("listening")
    Server.serve_forever()
