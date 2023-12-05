#!/bin/bash

ADDITIONAL=""
for i in `seq 0 900`; do
    curl "http://localhost:7788/index.html?page=${ADDITIONAL}";
    ARG=`cat /proc/sys/kernel/random/uuid | sed 's/[-]//g' | head -c 20; echo`
    #ADDITIONAL="${ADDITIONAL}${ARG}"
    sleep 5;
done


echo "KILL SERVER"
echo "curl http://localhost:7788/overflow.html"
