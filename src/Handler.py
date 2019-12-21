

from socketserver import StreamRequestHandler as Tcp, ThreadingTCPServer


class Handler(Tcp):
    def log(self, msg):
        print("[{}]{}".format(self.client_address, msg))

    def sendLongByteStream(self, data: bytes, to_socket=None):
        if to_socket is None:
            to_socket = self.request
        data_len = bytes(str(len(data)), encoding='utf8')
        data_len_len = bytes(str(len(data_len)), encoding='utf8')

        self.log("[Send] : length 1 :{}".format(data_len_len))
        self.log("[Send] : length 2 :{}".format(data_len))
        to_socket.sendall(data_len_len)
        to_socket.sendall(data_len)
        to_socket.sendall(data)

    def getLongByteStream(self, msg="", from_socket=None):
        stream_length = self.getNByte(1, msg="{}(length1)".format(msg), from_socket=from_socket)
        if stream_length is None:
            return None
        stream_length = self.getNByte(int(stream_length), msg="{}(length2)".format(msg), from_socket=from_socket)
        if stream_length is None:
            return None
        stream = self.getNByte(int(stream_length), msg="{}(data)".format(msg), from_socket=from_socket)
        return stream

    def sendByteStream(self, data, to_socket=None):
        if to_socket is None:
            to_socket = self.request
        assert len(data) < 256
        self.log("send :{}".format(bytes(chr(len(data)), encoding='utf8')+ data))
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
        self.log("[ {} ] recv: ({}/{}): {}".format(msg, len(recv), n, recv))
        while len(recv) < n:
            tmp = from_socket.recv(n - len(recv))
            recv += tmp
            if len(tmp) <= 0:
                return None
        return recv

