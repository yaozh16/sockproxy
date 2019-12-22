
from socketserver import StreamRequestHandler as Tcp, ThreadingTCPServer
from Crypto import Random
from Crypto.Hash import SHA
import base64
from Crypto.Cipher import PKCS1_v1_5 as Cipher_pkcs1_v1_5
from Crypto.Signature import PKCS1_v1_5 as Signature_pkcs1_v1_5
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES

import random
# 伪随机数生成器
random_generator = Random.new().read
# rsa算法生成实例
rsa = RSA.generate(1024, random_generator)




class Handler(Tcp):
    SessionKey = 'a'*64
    sess_left = b''
    handler_config = {}
    block_size = 64
    block_header_size = 4
    block_payload_size = 50
    encryptor_accessed = 0
    encryptor_step = 3

    def load_config(self, handler_config):
        self.handler_config = handler_config

    def log(self, msg):
        print("[{}]{}".format(self.client_address, msg))

    def sendLongByteUnit(self, data: bytes, to_socket=None):
        if to_socket is None:
            to_socket = self.request
        data_len = bytes(str(len(data)), encoding='utf8')
        data_len_len = bytes(str(len(data_len)), encoding='utf8')
        to_send = data_len_len + data_len + data
        self.log("[Send data] : length={}".format(data_len))
        to_socket.sendall(to_send)

    def getLongByteUnit(self, msg="", from_socket=None):
        stream_length = self.getNByte(1, msg="{}(LongByteStream length1)".format(msg), from_socket=from_socket)
        if stream_length is None:
            return None
        stream_length = self.getNByte(int(stream_length), msg="{}(LongByteStream length2)".format(msg), from_socket=from_socket)
        if stream_length is None:
            return None
        stream = self.getNByte(int(stream_length), msg="{}(LongByteStream data)".format(msg), from_socket=from_socket)
        return stream

    def sendByteUnit(self, data, to_socket=None):
        if to_socket is None:
            to_socket = self.request
        assert len(data) < 256
        self.log("send :{}".format(bytes(chr(len(data)), encoding='utf8') + data))
        to_socket.sendall(bytes(chr(len(data)), encoding='utf8') + data)

    def getByteUnit(self, msg="", from_socket=None):
        stream_length = self.getNByte(1, msg=msg, from_socket=from_socket)
        if stream_length is None:
            return None
        stream = self.getNByte(ord(stream_length),from_socket=from_socket)
        return stream

    def getNByte(self, n, msg="", from_socket=None):
        if from_socket is None:
            from_socket = self.request
        recv = b''
        recv += bytes(from_socket.recv(n - len(recv)))
        self.log("[ {} ] recv: ({}/{}):{}".format(msg, len(recv), n, [recv[:20]]))
        while len(recv) < n:
            tmp = from_socket.recv(n - len(recv))
            recv += tmp
            if len(tmp) <= 0:
                return None
        return recv

    def get_header(self, offset: int, length:int):
        header = b''
        offset = bytes(chr(offset), encoding='utf8')
        length = bytes(chr(length), encoding='utf8')
        version = bytes(chr(0x1), encoding='utf8')
        header = offset + length
        while len(header) < self.block_header_size:
            header = header + b'0'
        return header


    def block_unpack(self, msg):
        header = msg[:self.block_header_size]
        offset = int(header[0])
        length = int(header[1])
        payload = msg[offset:offset+length]
        return payload

    def block_pack(self, payload):
        length = len(payload)
        offset = random.randint(self.block_header_size, self.block_size - length)
        header_bytes = self.get_header(offset, length)
        padding_before_payload = offset - self.block_header_size
        padding_after_payload = self.block_size - length - offset
        padding_before_payload = bytes("".join([chr(random.randint(0, 127)) for i in range(padding_before_payload)]),
                                       encoding='utf8')
        padding_after_payload = bytes("".join([chr(random.randint(0, 127)) for i in range(padding_after_payload)]),
                                      encoding='utf8')
        msg = header_bytes + padding_before_payload + payload + padding_after_payload
        return msg

    def get_encryptor(self):
        return AES.new(self.SessionKey[:32], AES.MODE_CBC, self.SessionKey[-16:])

    def sess_encrypt(self, msg):
        encrypted = b''
        for i in range(0, len(msg), self.block_payload_size):
            encrypted += self.get_encryptor().encrypt(self.block_pack(msg[i:i + self.block_payload_size]))
        return encrypted

    def sess_decrypt(self, msg):
        self.sess_left = self.sess_left + msg
        next_group_length = int(len(self.sess_left) // self.block_size) * self.block_size
        decrypted = b''
        for i in range(0, next_group_length, self.block_size):
            decrypted += self.block_unpack(self.get_encryptor(). decrypt(self.sess_left[i:i+self.block_size]))
        self.sess_left = self.sess_left[next_group_length:]
        return decrypted

    def pub_encrypt(self, msg_bytes: bytes, pub):
        with open(pub) as f:
            key = f.read()
            print(len(key))
            rsakey = RSA.importKey(key)
            cipher = Cipher_pkcs1_v1_5.new(rsakey)
            msg_bytes = base64.b64encode(cipher.encrypt(msg_bytes))
        return msg_bytes

    def pri_decrypt(self, msg_bytes: bytes, pri):
        with open(pri) as f:
            key = f.read()
            rsakey = RSA.importKey(key)
            cipher = Cipher_pkcs1_v1_5.new(rsakey)
            msg_bytes = cipher.decrypt(base64.b64decode(msg_bytes), random_generator)
        return msg_bytes

    def pri_sign(self, msg_bytes: bytes, pri):
        with open(pri) as f:
            key = f.read()
            rsakey = RSA.importKey(key)
            signer = Signature_pkcs1_v1_5.new(rsakey)
            digest = SHA.new()
            digest.update(msg_bytes)
            sign = signer.sign(digest)
            msg_bytes = base64.b64encode(sign)
        return msg_bytes

    def pub_verify(self, msg_bytes: bytes, pub, signature):
        with open(pub) as f:
            key = f.read()
            rsakey = RSA.importKey(key)
            verifier = Signature_pkcs1_v1_5.new(rsakey)
            digest = SHA.new()
            digest.update(msg_bytes)
            is_verify = verifier.verify(digest, base64.b64decode(signature))
        return is_verify

    def finish(self):
        super(Handler, self).finish()
        self.log("[finished]")
