#!/bin/sh
# Compare the output of two tests (see runforcompare.sh)
# Collects basic stats and creates files with differences,
# both in domains and the errors that surface.

first=$1
second=$2

if ! [ -f domains.$first.errors -a -f domains.$second.errors ]; then
    echo "Missing file: domains.$i.errors" 1>&2
    echo "Usage: $0 <branch1> <branch2>" 1>&2
    exit 2
fi

for i in $first $second; do
    sort domains.$i.errors > domains.$i.codes
    cut -f 1 -d ' ' domains.$i.codes > domains.$i.domains
done

for i in codes domains; do
    diff -U 0 domains.$first.$i domains.$second.$i | grep -v @@ | tail -n +3 > domains.$first-$second.$i
done

echo $(wc -l domains.$first-$second.codes) differences
echo $(wc -l domains.$first-$second.domains) differences in just domains
