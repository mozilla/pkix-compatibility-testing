#!/bin/sh
dir=saved$(date -Idate)
i=1
while [ -d $dir ]; do
    i=$((i$i+1))
    dir="$dir-$i"
done
mkdir $dir
mv domains.* $dir
ln -s $dir/domains.retry.txt domains.txt
