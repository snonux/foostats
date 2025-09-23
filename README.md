# foostats

A privacy-respecting web analytics tool for OpenBSD that processes HTTP/HTTPS and Gemini protocol logs to generate anonymous site statistics. Designed for the foo.zone ecosystem and similar sites, it provides comprehensive traffic analysis while preserving visitor privacy through SHA3-512 IP hashing.

## Features

- **Privacy-First**: IP addresses are hashed using SHA3-512 before storage; no personal information retained
- **Multi-Protocol Support**: Processes both traditional web server logs (httpd) and Gemini protocol logs (vger/relayd)
- **Distributed Architecture**: Supports replication between multiple nodes for comprehensive statistics
- **Security Filtering**: Blocks and logs suspicious requests based on configurable patterns
- **Comprehensive Reporting**: Generates daily, monthly, and 30-day summary reports in Gemtext format
- **Feed Analytics**: Tracks Atom/RSS and Gemfeed subscribers
- **IPv4/IPv6 Support**: Full support for both protocols

## Installation

On OpenBSD, install dependencies:

```sh
doas pkg_add p5-Digest-SHA3 p5-PerlIO-gzip p5-JSON p5-String-Util p5-LWP-Protocol-https p5-HTML-Parser perltidy
```

## Dependencies

- Perl 5.38+
- Core: `Time::Piece`, `Getopt::Long`, `Sys::Hostname`, `File::Basename`
- CPAN/Packages: `Digest::SHA3`, `PerlIO::gzip`, `JSON`, `String::Util`, `LWP::UserAgent` (and HTTPS support), `HTML::Entities`

Notes:
- On OpenBSD the packages are: `p5-Digest-SHA3`, `p5-PerlIO-gzip`, `p5-JSON`, `p5-String-Util`, `p5-LWP-Protocol-https`, `p5-HTML-Parser` (provides `HTML::Entities`).
- The script expects Perl 5.38 features; adjust accordingly if running older Perl.

## Usage

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
                          Default: /var/www/htdocs/buetow.org/self/foostats
--output-dir <path>       Directory to write .gmi report files.
                          Default: /var/gemini/stats.foo.zone
--html-output-dir <path>  Directory to write .html report files.
                          Default: /var/www/htdocs/gemtexter/stats.foo.zone
--odds-file <path>        File with odd URI patterns to filter.
                          Default: <stats-dir>/fooodds.txt
--filter-log <path>       Log file for filtered requests.
                          Default: /var/log/fooodds
--partner-node <hostname> Hostname of the partner node for replication.
                          Default: fishfinger.buetow.org or blowfish.buetow.org
--version                 Show version information.
--help                    Show this help message.
```

## Configuration

### Log Format

Expected log format is OpenBSD's "forwarded" format (see `httpd.conf(5)`). The tool processes:
- httpd access logs from `/var/www/logs/access.log`
- Gemini logs from `/var/log/gemini` (vger) and `/var/log/relayd` (relayd)

### Filter Configuration

Create a `fooodds.txt` file in your stats directory with URI patterns to filter out suspicious requests. Example patterns:
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
- Daily stats: `YYYY-MM-DD-hostname.json.gz`
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

- IP addresses are immediately hashed using SHA3-512
- No cookies or tracking scripts
- Only aggregated statistics are stored
- Individual user behavior is not tracked
- Excessive requests (>1/second) are filtered

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
