insmod interceptor.ko
sleep $1m
rmmod interceptor
dmesg