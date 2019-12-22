
import pycrypto_utils
from socketserver import StreamRequestHandler as Tcp, ThreadingTCPServer
from Crypto import Random
from Crypto.Hash import SHA
import base64
from Crypto.Cipher import PKCS1_v1_5 as Cipher_pkcs1_v1_5
from Crypto.Signature import PKCS1_v1_5 as Signature_pkcs1_v1_5
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES


# 伪随机数生成器
random_generator = Random.new().read
# rsa算法生成实例
rsa = RSA.generate(1024, random_generator)




class Handler(Tcp):
    SessionKey = 'a'*64
    sess_left = b''

    def log(self, msg):
        print("[{}]{}".format(self.client_address, msg))

    def sendLongByteStream(self, data: bytes, to_socket=None):
        if to_socket is None:
            to_socket = self.request
        data_len = bytes(str(len(data)), encoding='utf8')
        data_len_len = bytes(str(len(data_len)), encoding='utf8')
        self.log("[Send data] : length={}".format(data_len))
        to_socket.sendall(data_len_len + data_len + data)

    def getLongByteStream(self, msg="", from_socket=None):
        stream_length = self.getNByte(1, msg="{}(LongByteStream length1)".format(msg), from_socket=from_socket)
        if stream_length is None:
            return None
        stream_length = self.getNByte(int(stream_length), msg="{}(LongByteStream length2)".format(msg), from_socket=from_socket)
        if stream_length is None:
            return None
        stream = self.getNByte(int(stream_length), msg="{}(LongByteStream data)".format(msg), from_socket=from_socket)
        return stream

    def sendByteStream(self, data, to_socket=None):
        if to_socket is None:
            to_socket = self.request
        assert len(data) < 256
        self.log("send :{}".format(bytes(chr(len(data)), encoding='utf8') + data))
        to_socket.sendall(bytes(chr(len(data)), encoding='utf8') + data)

    def getByteStream(self, msg="", from_socket=None):
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

    def sess_normalize(self, msg, align):
        normalized = b''
        for i in range(0, len(msg), align-1):
            subset = msg[i:i+align-1]
            length = len(subset)
            normalized += bytes(chr(length),encoding='utf8') + subset
        while len(normalized) % align != 0:
            normalized += b'0'
        return normalized

    def sess_recover(self, msg, align):
        recovered = b''
        for i in range(0, len(msg), align):
            subset = msg[i:i + align]
            length = int(subset[0])
            recovered += subset[1:1+length]
        return recovered

    def sess_encrypt(self, msg,align=16):
        normalized = self.sess_normalize(msg,align)
        encrypted = b''
        for i in range(0, len(normalized), align):
            encrypted += AES.new(self.SessionKey[:32], AES.MODE_CBC, self.SessionKey[-16:]). \
                encrypt(normalized[i:i + align])
        return encrypted

    def sess_decrypt(self, msg, align=16):

        self.sess_left = self.sess_left + msg
        next_group_length = int(len(self.sess_left) // align) * align
        decrypted = b''
        for i in range(0, len(self.sess_left), align):
            decrypted += AES.new(self.SessionKey[:32], AES.MODE_CBC, self.SessionKey[-16:]).\
                decrypt(self.sess_left[i:i+align])
        recovered = self.sess_recover(decrypted, align)
        self.sess_left = self.sess_left[next_group_length:]
        return recovered

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


