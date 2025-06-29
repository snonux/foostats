# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

This is a Perl-based log analysis tool for OpenBSD that processes web (httpd) and Gemini server logs. The script anonymizes IP addresses, filters suspicious requests, and generates aggregated statistics.

## Key Commands

### Code Formatting
```bash
# Format code with perltidy (use default settings)
perltidy foostats.pl
```

### Running the Script
```bash
# Parse logs and generate statistics
doas perl foostats.pl --parse-logs

# Replicate data from partner node
doas perl foostats.pl --replicate

# Pretty print statistics
doas perl foostats.pl --pretty-print

# Full options with custom paths
doas perl foostats.pl --parse-logs --stats-dir=/custom/path --odds-file=fooodds.txt --filter-log=/var/log/foostats-filter.log
```

## Architecture

The codebase follows an object-oriented design with the following key components:

1. **Main Script** (`foostats.pl`): Entry point that orchestrates the workflow
2. **Core Packages**:
   - `FileHelper`: Handles JSON+gzip file I/O operations
   - `DateHelper`: Date parsing and manipulation utilities
   - `Foostats::Logreader`: Parses httpd and Gemini logs from `/var/log/` and `/var/www/logs/`
   - `Foostats::Filter`: Filters requests based on patterns in `fooodds.txt`
   - `Foostats::Aggregator`: Aggregates filtered data into statistics
   - `Foostats::FileOutputter`: Writes JSON output to stats directory
   - `Foostats::Replicator`: Handles HTTPS replication with partner nodes
   - `Foostats::Merger`: Merges local and replicated data
   - `Foostats::Reporter`: Generates human-readable reports

## Development Notes

- The script uses modern Perl 5.38 features with experimental builtin functions
- IP addresses are anonymized using SHA3-512 hashing
- Data is stored in JSON format with gzip compression
- The blocklist file (`fooodds.txt`) contains patterns for filtering suspicious requests
- All file operations use the `FileHelper` package for consistency
- Date operations should use the `DateHelper` package

## Dependencies

Install required Perl modules via OpenBSD's package manager:
```bash
doas pkg_add p5-Digest-SHA3 p5-PerlIO-gzip p5-JSON p5-String-Util p5-LWP-Protocol-https
```

## Important Considerations

- This tool is OpenBSD-specific and reads from system log locations
- Always test with `--filter-log` option to debug filtering behavior
- The script requires elevated privileges (`doas`) to read system logs
- Partner replication uses HTTPS with mutual authentication