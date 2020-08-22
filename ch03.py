# -*- coding: utf-8 -*-
"""
Created on Tue Aug 18 16:42:49 2020

@author: fzhiy

ch03. 加密技术
"""

import hashlib # 导入内置的哈希运算模块
string = "I love blockchain" #创建一条字符串
value = hashlib.sha256(string.encode()) #调用sha256对象计算哈希值
value 
type(value)
value.digest() #返回字节串摘要
len(value.digest()) 
value.digest_size # 哈希摘要字节长度
value.hexdigest() #返回十六进制字符串摘要
len(value.hexdigest()) 
value.block_size  #内部块长度

hashlib.sha256(b'I love blockchain').hexdigest() #直接计算
h = hashlib.sha256() #生成哈希对象
h.update(b'I love blockchain') # 调用update()方法
h.hexdigest() #返回十六进制字符串摘要

# 雪崩效应(此特性 可以应用于电子文件的防篡改)
s1 = "I love blockchain"
s2 = "i love blockchain"
v1 = hashlib.sha256(s1.encode())
v2 = hashlib.sha256(s2.encode()) 
v1.hexdigest()
v2.hexdigest()
 
"""双哈希的实现"""
# 导入内置哈希运算模块
import hashlib

# 定义双哈希函数名为sha256d,d是double的缩写
# 参数string可以是 字符串或字节串
def sha256d(string):
    
    # 如果输入是字符串，则转化为字节串
    if not isinstance(string, bytes):
        string = string.encode()
    
    #首先计算输入的哈希摘要hashlib.sha256(string).digest(), 为字节串类型
    # 然后计算哈希摘要的哈希值，输出为十六进制字符串
    return hashlib.sha256(hashlib.sha256(string).digest()).hexdigest()

""" SHA256算法实现 """

import struct # struct模块能实现Python值与C语言结构体的转换
import binascii # 实现二进制与ASCII码之间的转换

# 64个常数K
_K = (0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
      0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
      0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
      0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
      0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
      0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
      0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
      0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
      0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
      0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
      0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
      0xd192e8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
      0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
      0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
      0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
      0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2)

# 初始化缓存
_H = (0x6109e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
      0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19)

# 定义sha1_256类
class sha_256:
    
    #输入参数为明文
    def __init__(self, m = None):
        
        # 初始化明文
        self.buffer = b''
        
        # 输入明文长度
        self.counter = 0
        self.H = _H
        self.K = _K
        if m:
            self.update(m)
            
    # 定义循环右移的方法：
    def rotr(self, x, y):
        return ((x >> y) | (x << (32-y))) & 0xFFFFFFFF
    
    #定义对单个分组进行操作的方法
    def operate(self, c):
        
        # 定义长度为64的空列表w
        w = [0] * 64
        
        # 将单个分组转换为16个32位的字，并填充w列表的前16位
        w[0:16] = struct.unpack('!16L', c)
        
        # 填充w列表的后48位
        for i in range(16, 64):
            s0 = self.rotr(w[i-15], 7) ^ self.rotr(w[i-15], 18) ^ (w[i-15] >> 3)
            s1 = self.rotr(w[i-2], 17) ^  self.rotr(w[i-2], 19) ^ (w[i-2] >> 10)
            w[i] = (w[i-16] + s0 + w[i-7] + s1) & 0xFFFFFFFF
        a,b,c,d,e,f,g,h = self.H
        
        # 执行64步迭代操作
        for i in range(64):
            s0 = self.rotr(a, 2) ^ self.rotr(a, 13) ^ self.rotr(a, 22)
            maj = (a & b) ^ (a & c) ^ (b & c) 
            t2 = s0 + maj
            s1 = self.rotr(e, 6) ^ self.rotr(e, 11) ^ self.rotr(e, 25)
            ch = (e & f) ^ ((~e) & g)
            t1 = h + s1 + ch + self.K[i] + w[i]
            h = g
            g = f
            f = e
            e = (d + t1) & 0xFFFFFFFF
            d = c
            c = b
            b = a
            a = (t1 + t2) & 0xFFFFFFFF
            
        # 更新缓存 
        self.H = [(x+y) & 0xFFFFFFFF for x,y in zip(self.H, [a,b,c,d,e,f,g,h])]
        
    # 定义更新N个分组缓存的方法
    def update(self, m):
        if not m:
            return 
        
        # 获取明文
        self.buffer = m
        # 获取明文长度
        self.counter = len(m)
        # 计算明文长度表示的后64位
        length = struct.pack('!Q', int(self.counter*8))
        # 对前N-1个分组进行哈希过程
        while len(self.buffer) >= 64:
            self.operate(self.buffer[:64])
            self.buffer = self.buffer[64:]
            
        # 填充未处理的第N个分组至512位或1024位，并进行哈希过程
        mdi = self.counter % 64
        # 如果第N个分组长度小于56， 则填充至512位
        if mdi < 56:
            padlen = 55-mdi
            self.buffer += (b'\x80' + (b'\x00'*padlen) + length)
            self.operate(self.buffer)
        # 否则填充至1024位
        else:
            padlen = 119 - mdi
            self.buffer += (b'\x80' + (b'\x00'*padlen) + length)
            for i in range(2):
                self.operate(self.buffer[i*64:(i+1)*64])
                
    # 输出明文摘要，字节串类型
    def digest(self):
        return struct.pack('!8L', *self.H)
    
    # 输出名为呢摘要，十六进制字符串类型
    def hexdigest(self):
        return binascii.hexlify(self.digest()).decode()
    
    
"""调用sha_256计算哈希值，并与Python内置hashlib模块中的sha256算法进行对比"""
from simchain.ecc import sha_256
sha_256(b'111').digest() #使用自定义哈希算法计算哈希值
import hashlib
hashlib.sha256(b'111').digest() #使用Python自带的算法计算哈希值
sha_256(b'111').hexdigest()
hashlib.sha256(b'111').hexdigest()


"""3.2.2 私钥 公钥和地址"""
from simchain import Network # 从Simchain中导入Network
net = Network()  # 创建一个网络，初始节点12个
zhangsan = net.peers[0]  # 0号节点命名为张三
lisi  = net.peers[6] # 6号节点命名为李四

zhangsan.wallet.nok # 访问钥匙对的数量，目前数量为1对，nok = number of keys
zhangsan.wallet.keys[0].sk.to_bytes() # 访问张三第一对密钥私钥的字节串编码
zhangsan.wallet.keys[0].pk.to_bytes()
zhangsan.wallet.addrs[0] # 访问张三第一对密钥对应的地址

lisi.wallet.nok # 访问钥匙对的数量，目前数量为1对，nok = number of keys
lisi.wallet.keys[0].sk.to_bytes() # 访问李四第一对密钥私钥的字节串编码
lisi.wallet.keys[0].pk.to_bytes()
lisi.wallet.addrs[0] # 访问李四第一对密钥对应的地址

zhangsan.wallet.generate_keys() #生成新的钥匙、地址对
zhangsan.wallet.nok
zhangsan.wallet.keys[1].sk.to_bytes() #张三第二对密钥私钥的字节串编码
zhangsan.wallet.keys[1].pk.to_bytes() #’‘’‘’‘’‘’‘’‘公钥’‘’‘’‘’‘’‘
zhangsan.wallet.addrs[1]              # 张三第二对密钥对应的地址 

zhangsan.create_transaction(lisi.wallet.addrs[0], 1000) # 指向离地的地址
zhangsan.broadcast_transaction() # 张三广播交易

tx = zhangsan.txs[-1] # 访问节点创建的最新交易
tx
tx.tx_in #访问交易输入列表，只有一个输入单元

zhangsan.blockchain[0].txs[0].id # 张三创建交易使用的UTXO所在的交易编号
vout = zhangsan.blockchain[0].txs[0].tx_out[0] #获取交易的第1个输出单元
vout 
vout.to_addr in zhangsan.wallet.addrs # 该地址属于张三
zhangsan.wallet.addrs #指向张三的第一个地址

lisi.verify_transaction(tx) #李四验证交易通过

# 张三尝试修改被李四验证通过的交易
from simchain import Vin # 从simchain中导入输入单元Vin
vin = tx.tx_in[0] # 获取交易的输入
vin1 = Vin(vin.to_spend, b'1'*64, vin.pubkey) #创建新的输入，放入新的签名
tx.tx_in[0] = vin1 #替换输入单元
lisi.verify_transaction(tx) #李四验证交易不通过 (False)

# 尝试使用张三的第二对密钥
sk = zhangsan.wallet.keys[1].sk
pk = zhangsan.wallet.keys[1].pk
message = b'I love block chain' #选择一条签名明文
signature = sk.sign(message) # 用私钥进行签名
pk.verify(signature, message) #用公钥签证签名
pk1 = zhangsan.wallet.keys[0].pk #用张三的第一对密钥公钥验证签名
pk1.verify(signature, message)  # (Flase)

# 张三尝试用自己的签名消费他人的UTXO
from simchain import Pointer
pointer = Pointer(vin.to_spend.tx_id, 1) # 创建一个新的定位指针
new_out = zhangsan.blockchain[0].txs[0].tx_out[1] #新指针指向的输出单元
new_out
new_out.to_addr
new_out.to_addr in zhangsan.wallet.addrs #该地址不属于张三
vin3 = Vin(pointer, vin.signature, vin.pubkey) #创建一个新的输入单元
tx.tx_in[0] = vin3                      #替换输入单元
lisi.verify_transaction(tx)             # 李四验证交易不通过

'''欧几里得算法求逆元, 参考源文件ecc.py'''
def inv_mod(b, p):
    if b < 0 or p <= b:
        b = b % p
        
    c, d = b, p
    uc, vc, ud, vd, temp = 1, 0, 0, 1, 0
    while c != 0:
        temp = c
        q, c, d = d // c, d % c, temp
        uc, vc, ud, vd = ud-q*uc, vd-q*vc, uc, vc
        
    assert d == 1 #如果d==1, 则报错无解
    if ud > 0:
        return ud
    else:
        return ud + p

inv_mod(2, 23)      #12
3*inv_mod(2, 23)%23 #13

# 验证算法准确性
from simchain.ecc import inv_mod
inv_mod(2, 23)      #12
3*inv_mod(2, 23)%23 #13

'''
例3.2 已知椭圆曲线E_(29): y^2=x^3+4*x+20(mod 29),求该曲线下的所有点。
    方法：有限域上的椭圆曲线上的点可以通过遍历整个有限域的元素得到
 Python代码如下，可参考ecc.py中show_points()函数定义
    '''
def show_points(p,a,b):
    return [(x, y) for x in range(p) for y in range(p) if (y*y-(x*x*x+a*x+b))%p == 0] #如果(y^2-(x^3+a*x+b))%p==0
 
show_points(p=29, a=4, b=20)
    
from simchain.ecc import show_points
show_points(p=29, a=4, b=20)

'''
例3.3 已知椭圆曲线E_5:y^2=x^3+2*x+3(mod 5),计算点(1,4)+(3,1)以及(1,4)x2。
有限域上椭圆曲线的加法分为两种情形，即相同点与不同点。相同点的加法可以看作倍点
Python实现，可参考ecc.py中double()函数定义

加法法则：任意取椭圆曲线上两点P、Q （若P、Q两点重合，则做P点的切线）做直线交于椭圆曲线的另一点R1，过R1做y轴的平行线交于R。
参考文献：https://zhuanlan.zhihu.com/p/42629724
根据椭圆曲线有限域下的加法法则，
对于椭圆曲线y^2=x^3+a*x+b， 已知P(x1,y1)和Q(x2,y2)，即能求出R(x3,y3).
x3 = l^2-x1-x2, y3 = l*(x1-x3)-y1
其中，如果P != Q，l = (y2-y1) / (x2-x1)
     如果P =  Q, l = (3*(x1^2)+a) / (2*y1)
'''
# P = Q时的倍点计算
def double(x, y, p, a, b):
    l = ((3*x*x+a) * inv_mod(2*y, p)) % p
    x3 = (l*l-2*x) % p
    y3 = (l*(x-x3)-y) % p
    return x3, y3

#椭圆曲线有限域下的加法法则实现
def add(x1, y1, x2, y2, p, a, b):
    if x1 == x2 and y1 == y2: #P == Q时
        return double(x1, y1, p, a, b)
    # P!=Q时
    l = ((y2-y1) * inv_mod(x2-x1, p)) % p
    x3 = (l*l - x1 - x2) % p
    y3 = (l * (x1-x3) -y1) % p
    return x3, y3    

# 计算(1,4)+(3,1)
add(1, 4, 3, 1, p=5, a=2, b=3) # (2,0)


'''
椭圆曲线有限域上的乘法计算，可以通过转化二进制做加法运算
如 计算nP,当n=50，n对应的二进制数是110010,则50P=(2^5)*P+(2^4)*P+2*P
计算步骤：
1）反向获取n的二进制数每一位的集合，如二进制数110010,反向集合表示为{0,1,0,0,1,1}
2）实现乘法
'''
# step 1
def get_bits(n):
    bits = []
    while n != 0:
        bits.append(n & 1)
        n >>= 1
    return bits


def leftmost_bit(x):
    assert x > 0
    result = 1
    while result <= x:
        result = 2 * result
    return result // 2

# 椭圆曲线类CurveFp
class CurveFp(object):
    def __init__(self, p, a, b):
        # y^2 = x^3 + a*x + b (mod p) 
        self.p = p 
        self.a = a
        self.b = b
        
    def contains_point(self, x, y):
        return (y*y - (x*x*x + self.a*x + self.b)) % self.p == 0
    
    # 椭圆曲线有限域上的所有点的遍历求解
    def show_all_points(self):
        return [(x,y) for x in range(self.p) for y in range(self.p) 
                if (y*y - (x*x*x + self.a*x + self.b)) % self.p == 0]
    
    def __repr__(self):
        return "Curve(p={0:d}, a={1:d}, b={2,d})".format(self.p, self.a, self.b)
    
class Point(object):
    
    def __init__(self, curve, x, y, order=None):
        
        self.curve = curve
        self.x = x
        self.y = y
        self.order = order 
        #  self.curve is allowed to be None only for INFINITY
        if self.curve:
            assert self.curve.contains_point(x, y)
        if order:
            assert self * order == INFINITY
            
    def __eq__(self, other):
        #是否与另一个点相同
        if self.curve == other.curve and self.x == other.x and self.y == other.y:
            return True
        else:
            return False
        
    def __add__(self, other):
        # 加法
        if other == INFINITY:
            return self
        if self == INFINITY:
            return other
        assert self.curve == other.curve
        
        if self.x == other.x:
            if (self.y + other.y) % self.curve.p == 0:
                return INFINITY
            else :
                return self.double()
            
        p = self.curve.p
        l = ((other.y - self.y) * inv_mod(other.x - self.x, p)) % p
        
        x3 = (l*l - self.x - other.x) % p
        y3 = (l*(self.x - x3) - self.y) % p
        
        return Point(self.curve, x3, y3)
    
    def __mul__(self, other):
        e = other
        if self.order:
            e = e % self.order
        if e == 0:
            return INFINITY
        if self == INFINITY:
            return INFINITY
        
        e3 = 3 * e
        negative_self = Point(self.curve, self.x, -self.y, self.order)
        i = leftmost_bit(e3) // 2
        result = self
        
        while i>1 :
            result = result.double()
            if (e3 & i) != 0 and (e & i) == 0:
                result = result + self
            if (e3 & i) == 0 and (e & i) != 0:
                result = result +negative_self
            i = i // 2
        return result
    
    def __rmul__(self, other):
        # 点 乘以 整数
        return self * other
    
    def __repr__(self):
        if self == INFINITY:
            return "infinity"
        return "({0},{1})".format(self.x, self.y)
    
    def double(self):
        # 求倍点
        if self == INFINITY:
            return INFINITY
        
        p = self.curve.p
        a = self.curve.a
        l = ((3 * self.x * self.x + a) * inv_mod(2 * self.y, p)) % p
        
        x3 = (l * l - 2 * self.x) % p
        y3 = (l * (self.x - x3) - self.y) % p
        
        return Point(self.curve, x3, y3)
    
    # 关于x轴对称的点
    def invert(self):
        return Point(self.curve, self.x, -self.y % self.curve.p)
        
INFINITY = Point(None, None, None)

p,a,b = 29,4,20 #设置椭圆曲线的参数
curve = CurveFp(p, a, b) #定义一条椭圆曲线
p0 = Point(curve, 3, 1)  #选择椭圆曲线上的一个点
p0*2   # (24,7)
p0*20  # (15,27)

"""
例3.4 已知有限域上的椭圆曲线E_(37):y^2=x^3-x+3(mod 37),求点P(2,3)的阶
根据有限域上椭圆曲线上点阶的定义，只需要找到最小的整数n，使得(n-1)P=-P
"""
p,a,b = 37,-1,3
curve = CurveFp(p, a, b) #定义椭圆曲线
p0 = Point(curve, 2, 3) #定义P
_p0 = Point(curve, 2, 34) #定义-P  P(x,y)+Q(x,-y)=infinity,所以定义-P(x,y)=Q(x,-y)；则可定义-P
p1=p0
n=2
while p1 != _p0:
    p1 = n*p0
    n += 1
n  # 7
p1 # (2,34)
p1+p0  # infinity
# 则点P(2,3)的阶位8，因为8P=infinity

'''
3.2.5 椭圆曲线的加密
考虑椭圆曲线Ep:y^2=x^3+a*x+b(mod p)，其上有点G，G的阶为n(nG=infinity).
任选整数k,1<k<n，计算K=kG，则整数k和点K被称为一对密钥，k为私钥，K为公钥，点G称为基点。
'''
#secp256k1椭圆曲线的参数如下
from simchain.ecc import secp256k1
secp256k1.curvefp.a  # 0
secp256k1.curvefp.b  # 7
secp256k1.curvefp.p  # 115792089237316195423570985008687907853269984665640564039457584007908834671663
secp256k1.generator  #基点G (55066263022277343669578718895168534326250603453777594175500187360389116729240,32670510020758816978083085130507043184471273380659243275938904335757337482424)
secp256k1.order      #基点G的阶 115792089237316195423570985008687907852837564279074904382605163141518161494337

# 随机选择一个小于n大的整数作为私钥，并计算对应的公钥
import random
k = random.randint(1, secp256k1.order)  # 生成一个私钥
k
K = secp256k1.generator*k #计算公钥
K
# 通过结果知道 密钥其实就是大整数或整数对， 私钥是一个大整数，公钥是一个大整数对

#调用ecc.py的SigningKey和VerifyingKey对象可以创建私钥和公钥，实质是对整数和整数对的封装
from simchain import SigningKey, VerifyingKey, secp256k1
k = random.randint(1, secp256k1.order) #随机生成私钥整数
sk = SigningKey.from_number(k) #通过整数创建私钥对象
sk.to_bytes() #私钥编码成字节串显示
pk = sk.get_verifying_key()  #获取该私钥对应的公钥对象
pk.to_bytes()  #将公钥编码成字节串显示
k              #查看私钥的数值
from simchain.ecc import bytes_to_number #导入编码函数
bytes_to_number(sk.to_bytes())   #将私钥从字节串转换成整数
(bytes_to_number(pk.to_bytes()[0:32]),bytes_to_number(pk.to_bytes()[32:]))  #将公钥从字符串转换成整数对
secp256k1.generator*k           #直接计算公钥
ppk = VerifyingKey.from_bytes(pk.to_bytes())  #由字节串得到公钥对象
ppk.to_bytes()

'''
从公钥字节串计算地址过程：公钥字节串编码 -> sha256 -> ripemd160 -> 版本号\x00 + 公钥哈希 -> base58check -> 地址
'''
#从内置哈希运算库中导入new和sha256对象
from hashlib import new, sha256
#从base58模块中调用编码函数
from base58 import b58encode_check   #原书中有错误,多了一个下划线

#定义由公钥字节串生成地址的函数
def convert_pubkey_to_addr(pubkey_str):
    
    #对字节串进行sha256哈希运算，结果为sha
    sha = sha256(pubkey_str).digest()
    
    #对sha进行ripemd160哈希运算，结果为ripe
    ripe = new('ripemd160',sha).digest()
    
    #对ripe进行base58编码
    return b58encode_check(b'\x00'+ripe).decode()  

#from simchain.ecc import convert_pubkey_to_addr
convert_pubkey_to_addr(ppk.to_bytes())

'''
小结 私钥、公钥与地址三者之间的关系
    1)三者是一一对应的关系，一个私钥对应一个公钥和地址
    2)在已知椭圆曲线和基点情况下，私钥可以计算公钥，但公钥不能反向计算私钥
    3)公钥能计算地址，但是地址不能反向计算公钥，更不能推算私钥
'''

# Python 实现私钥签名和公钥验证签名过程
import random

#数字签名函数，输入为签名明文，基点G，私钥k
def sign(message, G, k):
    
    #获取基点G的阶
    n = G.order
    
    #计算明文哈希值
    mess_hash = sha256(message).digest()
    
    #将明文哈希值转换成数字
    h = bytes_to_number(mess_hash)
    r, s = 0, 0
    while r == 0 or s == 0:
        #生成随机数
        rk = random.randint(1, n)  #原文SystemRandom().randrange(1,n) ？？？
        rG = rk*G
        r = rG.x
        s = ((h + (r*k)%n)*inv_mod(rk, n)) % n
    return r, s

#验证签名函数，输入为签名，基点G，公钥K，以及明文
def verify(sig, G, K, message):
    #获取签名
    r, s = sig
    #获取基点的阶
    n = G.order
    mess_hash = sha256(message).digest()
    h = bytes_to_number(mess_hash)
    w = inv_mod(s, n)
    u1, u2 = (h * w) % n, (r * w) % n
    p = u1 * G + u2 * K
    return r == p.x % n

from simchain.ecc import secp256k1
G = secp256k1.generator  #获得基点G
message = b"I love blockchain" #选择明文
k = 12345  #选择私钥整数
K = k*G  #计算对应的公钥整数对
K
signature = sign(message, G, k) #私钥签名
signature #两个整数
flag = verify(signature, G, K, message) #用公钥验证签名
flag

# 尝试使用一个新的私钥进行签名
k1 = 123456 #新的私钥
signature1 = sign(message, G, k1)  #新的签名
flag = verify(signature1, G, K, message) #使用旧的 公钥验证
flag  # False，验证签名不通过

# 3.2.6 钱包
# 1.不确定性钱包
from simchain import Wallet #导入钱包
w = Wallet() #创建一个钱包
for _ in range(10): #随机生成10对密钥
    w.generate_keys()
w.nok  #10
w.keys[-1].sk.to_bytes() #访问最后一对密钥中私钥的字节串编码
w.keys[8].sk.to_bytes()  #访问倒数第二对密钥中私钥的字符串编码

# 2.分层确定性钱包

import os 
import hashlib
import hmac #导入HMAC运算模块
from simchain import SigningKey #导入私钥对象
master_seed = os.urandom(32) #生成一个随机种子，256位
master_seed
#使用HMAC-SHA512运算得到512位输出
deriv = hmac.new(key=b'Simchain seed', msg=master_seed, digestmod=hashlib.sha512).digest()  
master_privkey_str = deriv[:32] #取输出的左256位生成主私钥
master_privkey = SigningKey.from_bytes(master_privkey_str)
master_privkey.to_bytes()
master_pubkey = master_privkey.get_verifying_key() #由主私钥生成主公钥
master_pubkey.to_bytes()
from simchain.ecc import convert_pubkey_to_addr
convert_pubkey_to_addr(master_pubkey.to_bytes()) #由主公钥生成主地址

# 父私钥衍生子密钥过程类似于种子生成主私钥过程， 知识HMAC-SHA512运算的输入为父私钥、父链码以及子密钥索引号

'''
3.3 加密算法的可能的破解算法
1) 枚举法
2) BSGS算法
3) Pollard's rho 算法
4) 随机数攻击
5) 如何保护私钥安全
'''
# 1.枚举法 参考ecc.py的crack_by_brute_force()
def crack_by_brute_force(G, K):
    for k in range(G.order):
        if k*G == K:
            return k
        
# BSGS(Baby step giant step 小步大步算法)
# Python实现
from math import sqrt, ceil
def crack_by_bsgs(G, K):
    m = int(ceil(sqrt(G.order)))
    table = {}
    
    #生成表
    for i in range(m):
        iG = i*G
        table[str(iG)] = i 
    
    for j in range(m):
        jmG = j*m*G
        R = K - jmG
        if str(R) in table.keys():
            i = table[str(R)]
            return (i+j*m) % n
        
