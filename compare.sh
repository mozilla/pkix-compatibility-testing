#!/bin/sh

n=$1
first=$2
second=$3

for i in $first $second; do
    cut -f 1 -d ' ' domains$n.$i.errors > domains$n.$i.errordomains
done

for i in errors errordomains; do
    diff -U 0 domains$n.$first.$i domains$n.$second.$i | grep -v @@ | tail +3 > domains$n.diff.$i
done

cut -c 2- domains$n.diff.errordomains | uniq > domains$n.retry.txt

echo $(wc -l domains$n.diff.errors) differences
echo $(wc -l domains$n.diff.errordomains) differences in just domains
