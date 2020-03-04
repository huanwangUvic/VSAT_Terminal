#!/bin/sh

ipeth0=`ifconfig eth0|grep 'inet'|cut -d: -f2|awk '{print $1}'`
ipeth1=`ifconfig eth1|grep 'inet'|cut -d: -f2|awk '{print $1}'`
ipeth0bak=192.168.1.104
ipeth1bak=182.168.1.1

function remove_chain(){
    echo -n removing chain...
    {
		iptables -t mangle -D POSTROUTING -j NF_QUEUE_CHAIN
		iptables -t mangle -F NF_QUEUE_CHAIN
        iptables -t mangle -X NF_QUEUE_CHAIN
		iptables -t nat -F
        iptables -t mangle -F
		
    } &>/dev/null
    echo done
}

function create_chain_POSTROUTING(){
    echo -n creating POSTROUTING chain...
	#iptables -A INPUT -i eth1 -j DROP
	iptables -t mangle -N NF_QUEUE_CHAIN
	iptables -t mangle -I POSTROUTING -o eth1 -j NF_QUEUE_CHAIN
    iptables -t mangle -A NF_QUEUE_CHAIN -j NFQUEUE --queue-num 8011
    
    echo done
}

function on_iqh(){
    remove_chain
    exit 1
}

trap on_iqh INT QUIT HUP

echo "8192 2100000 8400000" >/proc/sys/net/ipv4/tcp_mem
echo "8192 2100000 8400000" >/proc/sys/net/ipv4/tcp_rmem
echo "8192 2100000 8400000" >/proc/sys/net/ipv4/tcp_wmem

LD_LIBRARY_PATH=/usr/local/lib/
export LD_LIBRARY_PATH

ifconfig eth1 $ipeth1bak

route add -net 0.0.0.0 dev eth1 &>/dev/null

#这里不需要gw 因为没有mac地址可以填充

remove_chain
create_chain_POSTROUTING
# 441,676,546,3249
# v for debug
./PPsal -q 8011 -v -f 3249
