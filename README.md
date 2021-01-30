# tcpsynccount 

抓包统计TCP SYN包的数量，默认运行3秒钟，显示每个端口的IN、OUT SYNC 包数量。

localsubnets.txt 是本地网段。


# 我的使用场景

将出口流量镜像后，使用tcpsynccount统计22、23、1433等常见端口的TCP SYN包数量，并将结果写入influxdb，使用grafana展示。

相关的命令行是：
```
while true; do
	./tcpsynccount -i p1p1 -p22,23,1433 -P tcpsync > $$.tmp
	curl -T $$.tmp http://localhost:8086/write?db=tcpsync&u=*****&p=*****");
	sleep 10;
done
```

一旦发现有较多的OUT SYN包，使用如下命令行查找源IP：
```
tcpdump -i p1p1 -nn "tcp port 22 and ((tcp[tcpflags]&(tcp-syn)!=0)&&(tcp[tcpflags]&(tcp-ack)==0))"
```

