# foostats

Small Perl script reporting anonymous site stats for my foo.zone web and gemini capsule running on OpenBSD using `httpd` webserver and `relayd`, `inetd` + `vger` for Gemini. 
## Installation

On OpenBSD, install dependencies:

```sh
doas pkg_add p5-Digest-SHA3 p5-PerlIO-gzip p5-JSON p5-String-Util p5-LWP-Protocol-https
```

## Usage

To parse the logs, run:

```sh
doas perl foostats.pl --parse-logs  
```

Note, expected are the logs in OpenBSD's "forwarded" format (see `httpd.conf(5)`).

To fetch logs from partner server, run:

```sh
doas perl foostats.pl --replicate
```

To pretty print the (merged) logs, run:

```sh
doas perl foostats.pl --pretty-print
```
