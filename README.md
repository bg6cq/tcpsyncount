# tcpsyncount count tcp syn packets

抓包统计TCP SYN包的数量，默认运行3秒钟，显示每个端口的输入、输出2个方向 SYN 包数量。

localsubnets.txt 是本地网段。


# 我的使用场景

将出口流量镜像后，使用tcpsyncount统计22、23、1433等常见端口的TCP SYN包数量。

## 将结果写入influxdb，并使用grafana展示。

相关的命令行是：
```
while true; do
	./tcpsyncount -i p1p1 -p22,23,1433 -P tcpsyncount > $$.tmp
	curl -X POST -H "Content-Type: text/plain" --data-binary @$$.tmp http://localhost:8086/write?db=tcpsyncount&u=*****&p=*****");
	sleep 10;
done
```

## 结果也可以写入TDengine，使用grafana展示

创建TDengine表命令
```
CREATE DATABASE tcpsyncount;
use tcpsyncount;
CREATE TABLE tcpsyncount(ts TIMESTAMP, in_countINT, outcount INT) TAGS(port INT);
```
grafana中选择数据的SQL查询语句是
```
select ts, outcount from tcpsyncount.tcpsyncount where port=22
select ts, incount from tcpsyncount.tcpsyncount where port=22
```

相关的命令行是：
```
while true; do
	./tcpsyncount -i p1p1 -p22,23,1433 -t | while read d; do
		curl -H "Authorization: Basic cm9vdDp0YW9zZGF0YQ==" -d "$d" http://127.0.0.1:6041/rest/sql
	done
	sleep 10;
done



一旦发现有较多的OUT SYN包，使用如下命令行查找源IP：
```
tcpdump -i p1p1 -nn "tcp port 22 and ((tcp[tcpflags]&(tcp-syn)!=0)&&(tcp[tcpflags]&(tcp-ack)==0))"
```

