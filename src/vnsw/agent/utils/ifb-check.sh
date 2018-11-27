#!/usr/bin/env bash
while true
do
    ifbs=$(ls /sys/class/net|grep ifb)
    for item in $ifbs
    do
       cnt=$(echo $item|wc -m)
       if [ "$cnt" == "5" -o $item = "ifbvgw1" -o $item = "ifbvmware" ];then #such as ifb0,ifb1
           continue
       fi
       while true
       do
               tap=$(echo $item|sed -e 's/^ifb/tap/')
	       if [  -e /sys/class/net/$tap ];then
                    break
	       fi
               veth=$(echo $item|sed -e 's/^ifb/veth/')
	       if [  -e /sys/class/net/$veth ];then
                    break
	       fi
               ip link del $item type ifb
               break
       done
    done
    sleep 60
done
