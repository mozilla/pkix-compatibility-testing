#!/bin/bash

OBJ=/Users/mchew/mozilla-central/obj-ff-dbg/dist/bin

$OBJ/run-mozilla.sh $OBJ/xpcshell getXHRSSLStatus.js &> run.log
