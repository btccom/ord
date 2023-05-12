# bitcoin
编译bitcoin-cli及bitcoind命令行
* https://github.com/bitcoin/bitcoin

其中bitcoin-cli需要编译wallet模块
* https://github.com/bitcoin/bitcoin/blob/master/doc/build-osx.md
* https://github.com/bitcoin/bitcoin/blob/master/doc/build-unix.md

私链bitcoin.conf配置
```
# rpc
rpcallowip=0.0.0.0/0
txindex=1
maxconnections=1
# network
regtest=1
server=1
# mining
gen=1
# transaction
fallbackfee=0.00001
```

启动btc网络
```
bitcoind -conf=bitcoin.conf
```

创建爆块钱包
```
bitcoin-cli createwallet regtest
```

爆块命令
```
bitcoin-cli -rpcwallet=regtest -generate 1 
```

给ord钱包转账，amount单位是btc
```
bitcoin-cli sendtoaddress {address} {amount}
```

# ord
初始化钱包，钱包名默认ord
```
ord --chain regtest wallet create
```

生成收款地址，rpc-url路径最后一部分是钱包名
```
ord --chain regtest --rpc-url http://127.0.0.1:18443/wallet/ord wallet receive
```

铭刻，只有brc20分支支持times参数
```
ord --chain regtest --rpc-url http://127.0.0.1:18443/wallet/ord wallet inscribe --destination 12i2RTTuStbwogYBq96LaK14cGexGDEuum --dry-run --fee-rate 10  --times 10 {file}
```
输出有2种
```
// 官方返回格式
{
  "commit": "2c239b5af815b25d6271625cd7394760b08dbfba393b387f54bdad8e3dd9b408",
  "inscription": "4cc8b9528dbbc56dd5efc8903ad7f64368422af33cbefb7015f5e12adfb096a0i0",
  "reveal": "4cc8b9528dbbc56dd5efc8903ad7f64368422af33cbefb7015f5e12adfb096a0",
  "fees": 30500
}
```
```
// brc20分支返回格式
{
  "commit": "9597bf1bdbc30e9ffd4d54dbfaba81a90aa5f53ec4b4ec323c4b9b829c9ce732",
  "inscription": "0b9624787e28cfc63654adbb3f4736860c9b867b0388885644c4f0c7a7c8d4a9i0",
  "reveal": "0b9624787e28cfc63654adbb3f4736860c9b867b0388885644c4f0c7a7c8d4a9",
  "fees": 49900,
  "reveals": [
    "7b6761bc72ad4b760384ebc8ccfbc54a16de72a8070d0937a7870cfdb444b52e"
  ]
}
```
