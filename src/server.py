# -*- coding: utf-8 -*-
from diffiehellman.diffiehellman import DiffieHellman
import select
import socket
import json
import struct
import os
import hashlib
from socketserver import StreamRequestHandler as Tcp, ThreadingTCPServer
from Handler import Handler
import time
import random
SOCKS_VERSION = 5                           # socks版本
global_config = {}


class SockProxy(Handler):
    def handle(self):
        self.log("客户端请求连接！")
        if "*" not in global_config["whitelist"] and self.client_address[0] not in global_config["whitelist"]:
            self.log("异常连接，断开")
            self.server.close_request(self.request)
            return
        ret = self.HandShakeWithLocal()
        if ret is None:
            self.server.close_request(self.request)
            return
        address, port, cmd = ret
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

    def HandShakeWithLocal(self):
        """
             设计交互协议：
                1. server 向 client 给出哈希种子 S : 形式: | 1 | Variable |
                2. local 生成P1与对应Y1，server生成P2与对应Y2
                3. local 传输字符串X1、server的public公钥加密Y1的EY1、local私钥加密前面两部分HASH结果的E1 给server:
                    形式: | 1 | L | Variable | 1 | L | Variable | 1 | L | Variable |
                4. server 通过X1、EY1的HASH的结果与E1解密结果对比，判断是否是local，如果否则断开，否则继续
                5. server 传输字符串X2、public公钥加密Y2的EY2、server私钥加密前面两部分HASH结果的E2 给local:
                    形式: | 1 | L | Variable | 1 | L | Variable | 1 | L | Variable |
                6. local 通过X2、EY2的HASH的结果与E2解密结果对比，判断是否是server，如果否则断开，否则继续
                7. local 根据P1和Y2、server根据P2和Y1计算共同的会话密钥 SK
                8. local 向 server传输 address, port, cmd
        """
        # step 1

        self.log("step1")
        random.seed(time.time())
        HASH_SEED = bytes("".join([chr(random.randint(ord('a'), ord('z'))) for i in range(10)]),encoding="utf8")
        self.log("HASH SEED:{}".format(HASH_SEED))
        self.sendByteStream(HASH_SEED, to_socket=self.request)
        os.environ['PYTHONHASHSEED'] = str(HASH_SEED,encoding="utf8")

        self.log("step2")
        # step 2
        DH = DiffieHellman(group=5, key_length=200)
        DH.generate_private_key()
        DH.generate_public_key()
        Y = DH.public_key

        # step 4
        self.log("step4")
        X1 = self.getLongByteStream(msg="X1")
        if X1 is None:
            return None
        EY1 = self.getLongByteStream(msg="EY1")
        if EY1 is None:
            return None
        HASHED_1 = self.getLongByteStream(msg="HASHED_1")
        if HASHED_1 is None:
            return None
        if self.pub_decrypt(HASHED_1,pub=global_config["local_pub"]) != hashlib.new("sha256", X1+EY1).digest():
            self.log("签名无效！")
            return False

        # step 5
        self.log("step5")
        X2 = bytes("".join([chr(random.randint(0, 127)) for i in range(100)]), encoding='utf-8')
        EY2 = bytes(self.pub_encrypt(bytes(str(Y),encoding='utf8'), global_config["local_pub"]))
        HASHED_2 = hashlib.new("sha256", X2 + EY2).digest()
        E2 = self.pri_encrypt(HASHED_2, global_config["server_pri"])
        self.sendLongByteStream(X2)
        self.sendLongByteStream(EY2)
        self.sendLongByteStream(E2)

        # step 7
        DH.generate_shared_secret(int(str(self.pri_decrypt(EY1, global_config["server_pri"]),
                                          encoding='utf8')))
        self.SessionKey = DH.shared_key
        self.log("[SessionKey build]: {}".format(self.SessionKey))
        # step 8
        control_msg = self.getByteStream("control_msg")
        if control_msg is None:
            return None
        control_msg = str(self.Decrypt(control_msg), encoding="utf8").split(":")
        try:
            return control_msg[0], int(control_msg[1]), int(control_msg[2])
        except Exception as e:
            self.log(e)
            return None

    def pri_encrypt(self, msg_bytes: bytes, pri):
        return msg_bytes

    def pri_decrypt(self, msg_bytes: bytes, pri):
        return msg_bytes

    def pub_encrypt(self, msg_bytes: bytes, pub):
        return msg_bytes

    def pub_decrypt(self, msg_bytes: bytes, pub):
        return msg_bytes

    def Encrypt(self, msg):
        return msg

    def Decrypt(self, msg):
        return msg

if __name__ == '__main__':
    global_config = json.load(open("server_config.json"))
    print("run at {}".format((global_config["server_address"], global_config["server_port"])))
    # 服务器上创建一个TCP多线程服务，监听端口
    Server = ThreadingTCPServer((global_config["server_address"], global_config["server_port"]), SockProxy)
    print("listening")
    Server.serve_forever()
