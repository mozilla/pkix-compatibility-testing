# pkix-compatibility-testing

## Running a scan

Given an `xpcshell` instance, run the following:
```sh
$ .../xpcshell getXHRSSLStatus.js domains.txt errors.txt ev.txt >output.txt 2>errors.txt
```

For the full list of domains, this could take a long time.  Include a shorter
set if you need.

Additional command line options determine which file any errors are logged to,
and which file EV certificates are logged to.

Additional tweaks can be made by editing the script.  This isn't a full-service
operation :)

## Comparing gecko builds

If you have a local build of gecko in a git repository, you can use
`runforcompare.sh` to set this up.  Simply create a `domains.txt` file and point
the script to your gecko repository.

```sh
$ ln -s pulse-domains-master.txt domains.txt
$ ./runforcompare.sh ../gecko-dev
```

This saves files that use the branch name of your build:
`domains.<branch>.errors` and `domains.<branch>.ev`.  This allows you to compare
different builds easily.

### Comparing runs from different builds

The `compare.sh` script compares the output of two runs.  Simply pass it the
names of the branches involved.

```sh
$ ./compare.sh master bug1024576
```

This produces files including a comparison of the two named runs, including a
list of domains that produce different error codes between the scans, and a file
containing the domains that differ between runs.

### Re-running scans

Sometimes results are a little noisy, so re-running a scan over the set of
domains that might be different is useful.

The `saverun.sh` script saves the current run and builds a list of domains for
rechecking.  This list includes all domains that produced different responses
between all the current runs (for which there might be more than two).  The
(hopefully shorter) list is automatically symlinked to `domains.txt` in
preparation for the next run.
