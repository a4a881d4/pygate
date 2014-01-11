import struct
import hashlib
from ctypes import *
import evaluation
import math

def uint32(x):
	return x & 0xffffffffL

def bytereverse(x):
	return uint32(( ((x) << 24) | (((x) << 8) & 0x00ff0000) | (((x) >> 8) & 0x0000ff00) | ((x) >> 24) ))

def bytearray_to_uint32(x):
	return uint32(((x[3]) << 24) | ((x[2]) << 16)  | ((x[1]) << 8) | x[0])


def pack256(buf,off,sNum):
	s = int(sNum,16)
	for i in range( 0, 8 ):
		s,b = divmod(s,0x100000000)
		struct.pack_into('I',buf,off+i*4,(b))
	return buf,off+8*4
def packInt(buf,off,s):
	struct.pack_into('I',buf,off,(s))
	return buf,off+4

def unpack256(buf):
	s = struct.unpack('8I',buf)
	r=0;
	for i in range(0,8):
		r*=0x100000000
		r+=s[7-i]
	return r

def check(a):
	for x in [2,3,5,7,11,13,17,19,23,29,31,37,41,43,47]:
		print "%d check %d" % (x, a%x )
			
block = bytearray(80)
block,off = packInt(block,0,2)
block,off = pack256(block,off,"65d4c0205165de62d8de38f651afe54eadb8f79c2269f4aea64b0f01926b0546")
block,off = pack256(block,off,"8567d9f97eb7c8cf767f08ddbb2a83b697776ea626e3b304093ada6421a03100")
block,off = packInt(block,off,1389176014)
block,off = packInt(block,off,164018096)
block,off = packInt(block,off,5405)
#print repr(block)
	
m = hashlib.sha256()
m.update(block)
hash1 = m.digest()
m = hashlib.sha256()
m.update(hash1)
hash2 = m.digest()
ihash = unpack256(hash2)
#print ihash 
#print ihash % 210

	
hHash = CDLL('./libsha256.so')

tt = struct.unpack("8I",hash2)

c_tt_t = c_uint * 8
c_tt = c_tt_t()
c_ttm = c_tt_t()

for i in range(0,8):
	c_tt[i]=c_uint(tt[i])
for i in range(0,8):
	c_ttm[i] = c_tt[i] % 210

mmm = 0x100000000 % 210
for i in [7,6,5,4,3,2,1]:
	c_ttm[i-1]=c_ttm[i-1]+c_ttm[i]*mmm
	c_ttm[i-1]=c_ttm[i-1] % 210

block,off = packInt(block,76,5405-10)
buf = bytearray(128+32+4+4+8+8)
for i in range(0,80):
	buf[i] = block[i]

struct.pack_into('II',buf,128+32,100000000,5)

buff2 = (c_char * len(buf)).from_buffer(buf)

ret = hHash.scanhash_sse2_64(byref(buff2))
#print "ret=%d" % ret
if ret!=-1:
	buf = bytearray(buff2)

	hashout = buf[128:128+32]
	ihash = unpack256(hashout)
	mul = struct.unpack("q",buf[128+32+8:128+32+16])
	print ihash
#	check(ihash)
	print mul
#	check(mul[0])
	print math.pow(evaluation.prob(0.05,mul[0],5000000,1),6)
	print evaluation.sieveEff(0.05,47,5000000,8)
	
	block,off = packInt(block,76,ret)
#	print repr(block)
	
	m = hashlib.sha256()
	m.update(block)
	hash1 = m.digest()
	m = hashlib.sha256()
	m.update(hash1)
	hash2 = m.digest()
	ihash = unpack256(hash2)
	print ihash
#	check(ihash)


