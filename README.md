# foostats

A web analytics tool for OpenBSD that processes HTTP/HTTPS and Gemini logs.
Per-visitor counters use HMAC-SHA3-512 with a shared private key and stay outside
the web root. Public HTML and Gemtext reports contain aggregate counts.

Read also this blog post: https://foo.zone/gemfeed/2025-11-02-perl-new-features-and-foostats.html

## Features

- **Private counters**: visitor pseudonyms require a secret key; only aggregate reports are public
- **Multi-Protocol Support**: Processes both traditional web server logs (httpd) and Gemini protocol logs (vger/relayd)
- **Distributed Architecture**: Supports replication between multiple nodes for comprehensive statistics
- **Security Filtering**: Blocks and logs suspicious requests based on configurable patterns
- **Comprehensive Reporting**: Generates daily, monthly, and 30-day summary reports in Gemtext format
- **Feed Analytics**: Tracks Atom/RSS and Gemfeed subscribers
- **IPv4/IPv6 Support**: Full support for both protocols

## Installation

On OpenBSD, install dependencies:

```sh
doas pkg_add p5-Digest-SHA3 p5-Digest-HMAC p5-PerlIO-gzip p5-JSON p5-String-Util p5-HTML-Parser rsync perltidy
```

## Dependencies

- Perl 5.38+
- Core: `Time::Piece`, `Getopt::Long`, `Sys::Hostname`, `File::Basename`
- CPAN/Packages: `Digest::SHA3`, `Digest::HMAC`, `PerlIO::gzip`, `JSON`, `String::Util`, `HTML::Entities`; external `rsync`

Notes:
- On OpenBSD, `p5-HTML-Parser` provides `HTML::Entities`.
- The script expects Perl 5.38 features; adjust accordingly if running older Perl.

## Usage

Before parsing, replicating or reporting, install the same random key on both
nodes at `/etc/foostats/ip-hmac.key`: at least 64 hexadecimal characters,
owned by the process user, mode 0600 or 0400, and not a symlink. No key value
belongs in arguments, environment variables, logs or Git. Missing/insecure
keys fail closed. The key is not needed for `--help` or `--version`.

Use `/var/db/foostats` for counters, never a public directory. It must be
owned by the process user, have no access for other users, and be unwritable
by its group. A 0750 root:www directory permits the read-only replication
daemon to read 0640 counters while the chrooted web server cannot reach it.
Standalone directory creation uses 0700. Keep the key outside the exported
counter directory.

### Basic Operations

Parse web and Gemini logs:
```sh
doas perl foostats.pl --parse-logs
```

Replicate statistics from partner nodes:
```sh
doas perl foostats.pl --replicate
```

Generate reports from statistics:
```sh
doas perl foostats.pl --report
```

Perform all operations in sequence:
```sh
doas perl foostats.pl --all
```

### Command-Line Options

```
--parse-logs              Parse web and gemini logs.
--replicate               Replicate stats from partner node.
--report                  Generate a report from the stats.
--all                     Perform all of the above actions (parse, replicate, report).
--stats-dir <path>        Directory to store stats files.
                          Default: /var/db/foostats
--key-file <path>         Private shared HMAC key.
                          Default: /etc/foostats/ip-hmac.key
--output-dir <path>       Directory to write .gmi report files.
                          Default: /var/gemini/stats.foo.zone
--html-output-dir <path>  Directory to write .html report files.
                          Default: /var/www/htdocs/gemtexter/stats.foo.zone
--odds-file <path>        File with odd URI patterns to filter.
                          Default: /etc/foostats/fooodds.txt
--filter-log <path>       Log file for filtered requests.
                          Default: /var/log/fooodds
--partner-node <hostname> Hostname of the partner node for replication.
                          Default: fishfinger.buetow.org or blowfish.buetow.org
--partner-address <host>  Private rsync address, optionally with port.
                          Default: partner's WireGuard hostname
--version                 Show version information.
--help                    Show this help message.
```

## Configuration

### Log Format

Expected log format is OpenBSD's "forwarded" format (see `httpd.conf(5)`). The tool processes:
- httpd access logs from `/var/www/logs/access.log`
- Gemini logs from `/var/log/gemini` (vger) and `/var/log/relayd` (relayd)

### Filter Configuration

Create `/etc/foostats/fooodds.txt` with URI patterns to filter suspicious requests. Example patterns:
```
.php
.asp
/wp-admin
/wordpress
/phpmyadmin
```

## Architecture

The tool consists of several modules:

- **FileHelper**: Handles JSON and gzip file I/O operations
- **DateHelper**: Manages date-related operations
- **Logreader**: Parses httpd and Gemini (vger/relayd) logs
- **Filter**: Filters out suspicious requests based on patterns
- **Aggregator**: Aggregates statistics from log entries
- **FileOutputter**: Outputs statistics to compressed JSON files
- **Replicator**: Replicates stats between partner nodes
- **Merger**: Merges statistics from multiple sources
- **Reporter**: Generates human-readable Gemtext reports

## Output

### Statistics Files

Compressed JSON statistics stored in the stats directory:
- Daily private stats: `web_YYYYMMDD.hostname.json.gz` and `gemini_YYYYMMDD.hostname.json.gz`
- Aggregated data includes: unique visitors, request counts, filtered requests, top URLs, feed subscribers

### Reports

By default, reports are generated for a production environment:
- Gemtext reports: `/var/gemini/stats.foo.zone` (configurable with `--output-dir`)
- HTML reports: `/var/www/htdocs/gemtexter/stats.foo.zone` (configurable with `--html-output-dir`)

For local development, the `Justfile` provides a `reports` command that generates output in local directories:
- Gemtext reports: `out_gmi/`
- HTML reports: `out_html/`

Generated reports include:
- Daily reports: `YYYYMMDD.gmi` / `.html`
- 30-day summary: `30day_summary_YYYYMMDD.gmi` / `.html`
- An `index.gmi` and `index.html` that displays the latest 30-day summary.

## Privacy Considerations

- IP addresses become stable HMAC-SHA3-512 pseudonyms using a secret key shared by the nodes
- No cookies or tracking scripts
- Private counters retain per-visitor sets to merge unique counts; this is pseudonymization, not a claim of anonymous storage
- Only aggregate report artifacts are public; never publish the gzip counter archives or key metadata
- Excessive requests (>1/second) are filtered

Replication uses a hidden read-only `foostats-private` rsync module over the
existing WireGuard mesh, restricted to frontend WG addresses and local
administration. There is no public HTTP fallback. Invalid/legacy archives or
a different key identity are rejected before replacing a good cached replica.
The peer transfer is encrypted by WireGuard, not by rsync itself.

Migration requires a new private dataset. Legacy unsalted IP hashes cannot be
converted to direct IP HMACs without the original addresses. Rebuild from
retained raw logs, preserving existing aggregate report pages for unavailable
dates; the new rolling summary covers the available rebuilt data. Do not copy
legacy archives into the new directory or silently combine keys. Rotation also
requires a coordinated rebuild. Old public raw archives must be removed during
the approved rollout; changing defaults does not remove existing files.

The HMAC construction uses the [Digest::HMAC API](https://metacpan.org/pod/Digest::HMAC)
with SHA3-512's explicit 72-byte block length. Tests include the three full-tag
[NIST HMAC-SHA3-512 examples](https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/HMAC_SHA3-512.pdf),
native loopback replication, cross-node visitor deduplication, public artifact
inspection and negative key/dataset tests.

## License

BSD 3-Clause License (see LICENSE file)
## Testing

Basic test suite using Test::More is included under `t/`.

- Run all tests: `prove -lr t`
- The script now avoids running its CLI when loaded via `require`, enabling unit testing of internal packages.

## Justfile Usage

The project includes a `Justfile` for common development tasks. Install `just` for a convenient command runner.

- `just format`: Formats Perl code with `perltidy` using the project's `.perltidyrc` configuration.
- `just test`: Runs the test suite. It uses `prove -lr t` if available, otherwise falls back to running each test file with `perl`.
- `just check`: Performs a syntax check of `foostats.pl`.
- `just clean`: Removes temporary backup files (`.bak`, `*~`, etc.).
- `just reports`: Generates reports from the sample data in the `stats/` directory into local `out_gmi/` and `out_html/` directories.
- `just gather-fooodds`: Gathers suspicious request logs from remote servers, sorts them, and saves them to `fooodds.log`. This is useful for identifying new patterns to add to `fooodds.txt`.
