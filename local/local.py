# -*- coding: utf-8 -*-
import random
import select
import socket
import json
import os
import struct
import hashlib
from diffiehellman.diffiehellman import DiffieHellman
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
from handler import Handler


class SockProxy(Handler):
    def handle(self):
        self.load_config(global_config)
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
        if header is None:
            self.server.close_request(self.request)
            return
        VER, NMETHODS = struct.unpack("!BB", header)
        # 设置socks5协议，METHODS字段的数目大于0
        assert VER == SOCKS_VERSION, 'SOCKS版本错误'

        # 接受支持的方法
        # 无需认证：0x00    用户名密码认证：0x02
        # assert NMETHODS > 0
        methods = self.IsAvailable(NMETHODS)
        auth_method_used = "username" in global_config and \
                           "password" in global_config and \
                           "auth" in global_config and \
                           global_config["auth"]
        auth_method_used_code = 0x02 if auth_method_used else 0x00
        # 检查是否支持该方式，不支持则断开连接
        if (methods is None) or (auth_method_used_code not in set(methods)):
            self.log("浏览器sock5协议配置出错：需要给出{} 但是浏览器仅有{}".format(auth_method_used_code,set(methods)))
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
        if auth_method_used:
            self.connection.sendall(struct.pack("!BB", SOCKS_VERSION, 0x02))
            # 校验用户名和密码
            if not self.VerifyAuth(self.request):
                self.server.close_request(self.request)
                self.log("Auth failed")
                return
            else:
                self.log("Auth succeed")
        else:
            # 无需校验
            self.request.sendall(struct.pack("!BB", SOCKS_VERSION, 0x00))

        self.log("客户端校验成功")

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
            dst_address = socket.inet_ntoa(self.request.recv(4))
        elif address_type == 3:     # Domain
            domain_length = self.getNByte(1, 'domain_length')
            if domain_length is None:
                self.server.close_request(self.request)
                return
            dst_address = self.getNByte(ord(domain_length), "domain")
            if dst_address is None:
                self.server.close_request(self.request)
                return
        else:   # TODO: IPv6
            self.server.close_request(self.request)
            return
        dst_port = struct.unpack('!H', self.request.recv(2))[0]

        # 第四阶段由server完成
        try:
            address = global_config["server_address"]
            port = global_config["server_port"]
            remote = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            remote.connect((address, port))
            bind_address = remote.getsockname()
            self.log('已建立连接到：{}:{} bind:{}'.format(address, port, bind_address))
        except Exception as err:
            self.log(err)
            self.server.close_request(self.request)
            return
        if None is self.HandShakeWithServer(remote, dst_address, dst_port, cmd):
            self.server.close_request(self.request)
            return
        # 建立连接成功，开始交换数据
        self.ExchangeData(self.request, remote)
        self.server.close_request(self.request)
        self.log("handle done")

    def IsAvailable(self, n):
        """
        检查是否支持该验证方式
        """
        methods = []
        for i in range(n):
            tmp = self.getNByte(1, "method")
            if tmp is None:
                return None
            methods.append(ord(tmp))
        return methods

    def VerifyAuth(self, current_request):
        """
        校验用户名和密码
        """
        version = self.getNByte(1, "verify version")
        if version is None or ord(version) == 1:
            return False
        version = ord(version)
        username = self.getByteUnit(msg="username")
        if username is None:
            return False
        username = username.decode('utf-8')
        self.log(username)
        password = self.getByteUnit(msg="password")
        if password is None:
            return False
        password = password.decode('utf-8')
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
            return False

    def ExchangeData(self, client, remote):
        """
        交换数据 
        """
        self.log("ready to exchange data")

        while True:
            # 等待数据
            rs, ws, es = select.select([client, remote], [], [])
            if client in rs:
                data = client.recv(4096)
                self.log("client to remote:{}".format(len(data)))
                if len(data) == 0 or remote.send(self.sess_encrypt(data)) <= 0:
                    break
            if remote in rs:
                data = remote.recv(4096)
                self.log("remote to client:{}".format(len(data)))
                if len(data) == 0 or client.send(self.sess_decrypt(data)) <= 0:
                    break

    def HandShakeWithServer(self, remote, dst_address, dst_port, cmd):
        """
            设计交互协议：
                1. server 给出哈希种子 S : 形式: | 1 | Variable |   这一步希望保障两边RandomSeed不一样
                2. local 生成P1与对应Y1，server生成P2与对应Y2
                3. local 传输字符串X1、server的public公钥加密Y1的EY1、local私钥加密前面两部分HASH结果的E1 给server:
                    形式: | 1 | L | Variable | 1 | L | Variable | 1 | L | Variable |
                4. server 通过X1、EY1的HASH的结果与E1解密结果对比，判断是否是local，如果否则断开，否则继续
                5. server 传输字符串X2、public公钥加密Y2的EY2、server私钥加密前面两部分HASH结果的E2 给local:
                    形式: | 1 | L | Variable | 1 | L | Variable | 1 | L | Variable |
                6. local 通过X2、EY2的HASH的结果与E2解密结果对比，判断是否是server，如果否则断开，否则继续
                7. local根据P1和Y2、server根据P2和Y1计算共同的会话密钥 SK
                8. local向server传输 address, port, cmd
        """
        # step 1
        self.log("step1")
        HASH_SEED = self.getLongByteUnit(msg="HASH SEED", from_socket=remote)
        if HASH_SEED is None:
            return None
        self.encryptor_step = int(str(HASH_SEED, encoding='utf8'))

        # step 2
        self.log("step2")
        DH = DiffieHellman(group=5, key_length=200)
        DH.generate_private_key()
        DH.generate_public_key()
        Y = DH.public_key
        # step 3
        self.log("step3")
        X1 = bytes("".join([chr(random.randint(0, 127)) for i in range(100)]), encoding='utf-8')
        EY1 = bytes(self.pub_encrypt(bytes(str(Y), encoding='utf8'), global_config["server_pub"]))
        E1 = self.pri_sign(X1+EY1, global_config["local_pri"])
        self.sendLongByteUnit(X1, to_socket=remote)
        self.sendLongByteUnit(EY1, to_socket=remote)
        self.sendLongByteUnit(E1, to_socket=remote)

        # step 6
        self.log("step6")
        X2 = self.getLongByteUnit(from_socket=remote)
        if X2 is None:
            return None
        EY2 = self.getLongByteUnit(from_socket=remote)
        if EY2 is None:
            return None
        E2 = self.getLongByteUnit(from_socket=remote)
        if E2 is None:
            return None
        if not self.pub_verify(X2 + EY2, pub=global_config["server_pub"],signature=E2):
            self.log("签名无效！")
            return None
        # step 7
        DH.generate_shared_secret(int(str(self.pri_decrypt(EY2, global_config["local_pri"]),
                                          encoding='utf8')))

        self.SessionKey = DH.shared_key
        self.log("[SessionKey build]: {}({})".format(self.SessionKey, len(self.SessionKey)))
        # step 8
        dst_address = str(dst_address,encoding='utf8') if type(dst_address) != str else dst_address
        print([dst_port, dst_address, cmd])
        control_msg = ":".join([dst_address, str(dst_port), str(cmd)])
        self.sendLongByteUnit(self.sess_encrypt(bytes(control_msg, encoding='utf8')), to_socket=remote)
        return True


if __name__ == '__main__':
    global_config = json.load(open("local_config.json"))
    print("run at {}".format((global_config["local_address"], global_config["local_port"])))
    # 服务器上创建一个TCP多线程服务，监听端口
    Server = ThreadingTCPServer((global_config["local_address"], global_config["local_port"]), SockProxy)
    print("listening")
    Server.serve_forever()
