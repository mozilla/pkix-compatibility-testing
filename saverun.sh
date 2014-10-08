#!/bin/sh
# Saves the output of a comparison run to a directory.
# Also prepares for a second round by creating the domains.txt symlink

basedir=saved$(date -Idate)
dir=$basedir
i=1
while [ -d $dir ]; do
    i=$(($i+1))
    dir="$basedir-$i"
done
echo Saving to $dir
cat domains.*-*.codes | cut -f 1 -d ' ' - | cut -c 2- - | sort | uniq > domains.retry.txt
mkdir $dir
mv domains.* $dir
ln -s $dir/domains.retry.txt domains.txt
