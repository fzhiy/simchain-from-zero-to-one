# -*- coding: utf-8 -*-
"""
Spyder Editor

This is a temporary script file.
"""
# 2.3 什么是Simchain
from simchain import Network 
net = Network()
net.make_random_transactions()
net.consensus()

# 2.3.3 simchain使用
from simchain import Network, Peer # 导入Network、Peer对象
net = Network(nop = 1, von = 10000) # 创建区块链网络，初试节点数量为1，创世币为10000分
net.nop #访问网络中的节点数量
net.peers #访问网络中的节点，列表类型，每个节点会随机生成一个坐标，类似IP地址
zhangsan = net.peers[0] # 将0号节点命名为张三
zhangsan.coords # 张三的IP地址，在Simchain中无具体用处
zhangsan.sk # 访问张三的私钥
zhangsan.pk # 访问张三的公钥
zhangsan.addr # 访问张三的地址

zhangsan.get_balance() # 查看张三的余额，为10000分
zhangsan.blockchain[0] #访问创世区块
zhangsan.blockchain[0].txs # 访问创世区块中的交易，数量为1
zhangsan.blockchain[0].txs[0].tx_out #访问创世区块中交易的输出，1个输出单元
zhangsan.get_utxo() #获取张三的UTXO，数量也为1

net.add_peer() #添加一个节点到网络中
lisi = net.peers[1] # 将第二个节点命名为李四，就像中本聪给密码学专家哈尔芬妮发送10比特币一样
lisi.sk # 访问李四的私钥
lisi.pk # 公钥
lisi.addr #访问李四的地址
zhangsan.blockchain = lisi.blockchain # 张三的区块链与李四的区块链相同(区块链系统的正常运行是以全网数据保持一致为前提的)
zhangsan.utxo_set  == lisi.utxo_set # 张三的UTXO集与李四的UTXO集相同
lisi.get_balance()

"""转账
"""

zhangsan.create_transaction(lisi.addr, 100) # 参数为李四的地址和金额
tx = zhangsan.current_tx # 获取当前交易
tx.tx_out   #询问当前的交易输出
zhangsan.get_balance() #张三余额
lisi.get_balance() #李四的余额
zhangsan.broadcast_transaction() #张三将交易广播到网络中
zhangsan.get_balance() #张三余额，10分的交易费
lisi.get_balance() # 李四的余额

zhangsan.get_unconfirmed_utxo() #获取张三未确认的UTXO
lisi.get_unconfirmed_utxo() #获取李四未确认的UTXO
zhangsan.get_height() == lisi.get_height() == 1
zhangsan.mem_pool # 张三的交易池有一条交易
lisi.mem_pool == zhangsan.mem_pool #李四的交易池与张三的相同

net.consensus() #网络中的节点达成共识
zhangsan.get_balance() #张三获得奖励固定为500分，交易费为10分
zhangsan.get_height() == lisi.get_height() == 2
zhangsan.get_unconfirmed_utxo() == lisi.get_unconfirmed_utxo() == []
zhangsan.blockchain[1].txs[0].is_coinbase # 第一条交易为创币交易
zhangsan.blockchain[1].txs[0].tx_out[0].value #奖励为500分，交易费10分


