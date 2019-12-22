from Crypto import Random
from Crypto.Hash import SHA
from Crypto.Cipher import PKCS1_v1_5 as Cipher_pkcs1_v1_5
from Crypto.Signature import PKCS1_v1_5 as Signature_pkcs1_v1_5
from Crypto.PublicKey import RSA

# 伪随机数生成器
random_generator = Random.new().read
# rsa算法生成实例
rsa = RSA.generate(4096, random_generator)

# master的秘钥对的生成
private_pem = rsa.exportKey()

with open('local-pri.pem', 'wb') as f:
	f.write(private_pem)

public_pem = rsa.publickey().exportKey()
with open('local-pub.pem', 'wb') as f:
	f.write(public_pem)

# ghost的秘钥对的生成
private_pem = rsa.exportKey()
with open('server-pri.pem', 'wb') as f:
	f.write(private_pem)

public_pem = rsa.publickey().exportKey()
with open('server-pub.pem', 'wb') as f:
	f.write(public_pem)