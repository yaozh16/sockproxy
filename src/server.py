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
        address, port, cmd = self.HandShakeWithLocal(self.request)
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

            port = bind_address[1]
            self.log("构造返回包")
            reply = struct.pack("!BBBBIH", SOCKS_VERSION, 0, 0, 0x01, addr, port)
            self.log("发送返回包")
            self.request.sendall(self.Encrypt(reply))     # 发送回复包
            self.log("发送返回包完毕")
        except Exception as err:
            self.log(err)
            self.server.close_request(self.request)
            return

        # 建立连接成功，开始交换数据
        if reply[1] == 0 and cmd == 1:
            self.ExchangeData(self.request, remote)
        self.server.close_request(self.request)
        self.log("handle done")

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
                if remote.send(self.Decrypt(data)) <= 0:
                    break
            if remote in rs:
                data = remote.recv(4096)
                self.log("remote to client:{}".format(len(data)))
                if client.send(self.Encrypt(data)) <= 0:
                    break

    def HandShakeWithLocal(self, client):
        return "0.0.0.0", 80, 1

    def Encrypt(self, msg):
        return msg

    def Decrypt(self, msg):
        return msg

if __name__ == '__main__':
    global_config = json.load(open("server_config.json"))
    # 服务器上创建一个TCP多线程服务，监听端口
    Server = ThreadingTCPServer((global_config["server_address"], global_config["server_port"]), SockProxy)
    print("listening")
    Server.serve_forever()
