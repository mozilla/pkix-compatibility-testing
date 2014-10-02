#!/bin/sh

first=$1
second=${2:-master}

if ! [ -f domains.$first.errors ]; then
    echo "Missing file: domains.$i.errors" 1>&2
    echo "Usage: $0 <branch1> [branch2]" 1>&2
    echo "       branch2 defaults to master" 1>&2
    exit 2
fi

for i in $first $second; do
    cut -f 1 -d ' ' domains.$i.errors > domains.$i.errordomains
done

for i in errors errordomains; do
    diff -U 0 domains.$first.$i domains.$second.$i | grep -v @@ | tail -n +3 > domains.diff.$i
done

cut -c 2- domains.diff.errordomains | uniq > domains.retry.txt

echo $(wc -l domains.diff.errors) differences
echo $(wc -l domains.diff.errordomains) differences in just domains
