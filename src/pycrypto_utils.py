from Crypto.Cipher import AES
import math

# 补全字符

def align(str, isKey=False):
	zerocount = (16-len(str) % 16)
	if zerocount == 16:
		return str
	for i in range(0, zerocount):
		str = str + b'\0'
	return str

def split(bytes, block_size, left_empty):
	bytes_per_block = block_size - left_empty
	block_num = math.ceil(len(bytes)/bytes_per_block)
	print(len(bytes),bytes_per_block, block_num)
	blocks = []
	for i in range(0,block_num):
		blocks.append(b'\0'*left_empty + bytes[i*bytes_per_block:(i+1)*bytes_per_block])
		if i==block_num-1:
			blocks[i] = align(blocks[i],block_size)
	return blocks

def merge(blocks, left_empty):
	bytes = b''
	for block in blocks:
		bytes+=block[left_empty:]
	return bytes


def encrypt(bytes, key, iv):
	blocks = split(bytes,128,10)
	print("before encrypt,",len(blocks[0]),blocks)
	cryptor = AES.new(key, AES.MODE_CBC, iv)
	for i in range(0,len(blocks)):
		blocks[i] = cryptor.encrypt(blocks[i])
	print("after encrypt,",len(blocks[0]),blocks)
	return merge(blocks,0)

def decrypt(bytes, key, iv):
	blocks = split(bytes,128,0)
	print("before decrypt,",len(blocks[0]),blocks)
	cryptor = AES.new(key, AES.MODE_CBC, iv)
	for i in range(0,len(blocks)):
		blocks[i] = cryptor.decrypt(blocks[i])
		if i==len(blocks)-1:
			blocks[i]= blocks[i].rstrip(b'\0')
	print("after decrypt,",len(blocks[0]),blocks)
	return merge(blocks,10)