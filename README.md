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
--parse-logs              Parse web and gemini logs
--replicate               Replicate stats from partner node
--report                  Generate a report from the stats
--all                     Perform all of the above actions
--stats-dir <path>        Directory to store stats files
                          Default: /var/www/htdocs/buetow.org/self/foostats
--odds-file <path>        File with odd URI patterns to filter
                          Default: <stats-dir>/fooodds.txt
--filter-log <path>       Log file for filtered requests
                          Default: /var/log/fooodds
--partner-node <hostname> Hostname of the partner node for replication
                          Default: fishfinger.buetow.org or blowfish.buetow.org
--help                    Show help message
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

Gemtext reports generated in `stats/gemtext/`:
- Daily reports: `YYYY-MM-DD.gmi`
- Monthly reports: `YYYY-MM.gmi`
- 30-day summary: `30-day-summary.gmi`
- Yearly reports: `YYYY.gmi`

Reports include:
- Total requests and unique visitors
- Protocol breakdown (HTTP vs Gemini, IPv4 vs IPv6)
- Top hosts and URLs by unique visitors
- Feed subscriber counts
- Filtered/suspicious request statistics

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

## Development

- Format: `just format` (uses `.perltidyrc`, requires `perltidy`)
- Test: `just test` (uses `prove` if available, otherwise runs tests via `perl`)
- Lint/syntax: `just check`
- Cleanup: `just clean`
- Generate reports (from repo's `stats/`): `just reports`

Tip: install `just` (a command runner) for convenience.
