#!/bin/sh
number=$1
branch=${2:-master}
exec ../gecko-dev/obj-mac-$branch/dist/bin/run-mozilla.sh ../gecko-dev/obj-mac-$branch/dist/bin/xpcshell getXHRSSLStatus.js domains$number.txt domains$number.$branch.errors domains$number.$branch.ev > domains$number.$branch.log 2>&1
