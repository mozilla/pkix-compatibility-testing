# pkix-compatibility-testing

## Running the tests

Edit the script to set SOURCE and EV_OUTPUT/ERROR_OUTPUT file names.  And any
other configuration you like.

Given an `xpcshell` instance, run the following:
```sh
$ .../path/to/xpcshell getXHRSSLStatus.js >output.txt 2>errors.txt
```

For the full list of domains, this could take some time.  Include a shorter set
if you need.

## Comparing runs from different builds

For testing that a change to libssl hasn't regressed anything, you can diff the
files from runs with different builds.
```sh
$ diff -U 0 error-domains1.txt error-domains2.txt | grep -v @@ > changed.txt
```

Or you can build a list of domains over which you can re-run the test:
```sh
$ cut -c 2- changed.txt | cut -f 1 -d ' ' >> retest.txt
```
