#!/bin/sh
# Run this against a build of gecko to collect data on what works or not
# Create a symlink from domains.txt to the file you want in order to prepare, e.g.:
#   $ ln -s pulse-domains-master.txt domains.txt
# This only supports git repositories, sorry.
gecko="${1-../gecko-dev}"
objdir=$(cd "${gecko}"; ./mach environment | sed '/config topobjdir/,+1 !d' | tail -1)
bin="${objdir}/dist/bin"
branch=$(cd "${gecko}"; git branch | grep '*' | cut -c 3- -)
echo Running test against $(wc -l domains.txt) domains on $branch
exec $bin/run-mozilla.sh $bin/xpcshell getXHRSSLStatus.js domains.txt domains.$branch.errors domains.$branch.ev > domains.$branch.log 2>&1
