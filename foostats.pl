#!/usr/bin/perl

use v5.38;

# Those are enabled automatically now w/ this version of Perl
# use strict;
# use warnings;

use builtin      qw(true false);
use experimental qw(builtin);

use feature qw(refaliasing);
no warnings qw(experimental::refaliasing);

# Debugging aids like diagnostics are noisy in production.
# Removed per review: enable locally when debugging only.

use constant VERSION => 'v0.2.0';

# Package: FileHelper — small file/JSON helpers
# - Purpose: Atomic writes, gzip JSON read/write, and line reading.
# - Notes: Dies on I/O errors; JSON encoding uses core JSON.
package FileHelper {
    use JSON;

    # Sub: write
    # - Purpose: Atomic write to a file via "$path.tmp" and rename.
    # - Params: $path (str) destination; $content (str) contents to write.
    # - Return: undef; dies on failure.
    sub write ($path, $content) {
        open my $fh, '>', "$path.tmp" or die "\nCannot open file: $!";
        print $fh $content;
        close $fh;
        rename "$path.tmp", $path;
    }

    # Sub: write_json_gz
    # - Purpose: JSON-encode $data and write it gzipped atomically.
    # - Params: $path (str) destination path; $data (ref/scalar) Perl data.
    # - Return: undef; dies on failure.
    sub write_json_gz ($path, $data) {
        my $json = encode_json $data;

        say "Writing $path";
        open my $fd, '>:gzip', "$path.tmp" or die "$path.tmp: $!";
        print $fd $json;
        close $fd;

        rename "$path.tmp", $path or die "$path.tmp: $!";
    }

    # Sub: read_json_gz
    # - Purpose: Read a gzipped JSON file and decode to Perl data.
    # - Params: $path (str) path to .json.gz file.
    # - Return: Perl data structure.
    sub read_json_gz ($path) {
        say "Reading $path";
        open my $fd, '<:gzip', $path or die "$path: $!";
        my $json = decode_json <$fd>;
        close $fd;
        return $json;
    }

    # Sub: read_lines
    # - Purpose: Slurp file lines and chomp newlines.
    # - Params: $path (str) file path.
    # - Return: list of lines (no trailing newlines).
    sub read_lines ($path) {
        my @lines;
        open(my $fh, '<', $path) or die "$path: $!";
        chomp(@lines = <$fh>);
        close($fh);
        return @lines;
    }
}

# Package: DateHelper — date range helpers
# - Purpose: Produce date strings used for report windows.
# - Format: Dates are returned as YYYYMMDD strings.
package DateHelper {
    use Time::Piece;

    # Sub: last_month_dates
    # - Purpose: Return dates for today back to 30 days ago (inclusive).
    # - Params: none.
    # - Return: list of YYYYMMDD strings, newest first.
    sub last_month_dates () {
        my $today = localtime;
        my @dates;

        for my $days_ago (1 .. 31) {
            my $date = $today - ($days_ago * 24 * 60 * 60);
            push @dates, $date->strftime('%Y%m%d');
        }

        return @dates;
    }

}

# Package: Foostats::Logreader — parse and normalize logs
# - Purpose: Read web and gemini logs, anonymize IPs, and emit normalized events.
# - Output Event: { proto, host, ip_hash, ip_proto, date, time, uri_path, status }
package Foostats::Logreader {
    use Digest::SHA3 'sha3_512_base64';
    use File::stat;
    use PerlIO::gzip;
    use Time::Piece;
    use String::Util qw(contains startswith endswith);

    # Make log locations configurable (env overrides) to enable testing.
    # Sub: gemini_logs_glob
    # - Purpose: Glob for gemini-related logs; env override for testing.
    # - Return: glob pattern string.
    sub gemini_logs_glob { $ENV{FOOSTATS_GEMINI_LOGS_GLOB} // '/var/log/daemon*' }

    # Sub: web_logs_glob
    # - Purpose: Glob for web access logs; env override for testing.
    # - Return: glob pattern string.
    sub web_logs_glob { $ENV{FOOSTATS_WEB_LOGS_GLOB} // '/var/www/logs/access.log*' }

    # Sub: anonymize_ip
    # - Purpose: Classify IPv4/IPv6 and map IP to a stable SHA3-512 base64 hash.
    # - Params: $ip (str) source IP.
    # - Return: ($hash, $proto) where $proto is 'IPv4' or 'IPv6'.
    sub anonymize_ip ($ip) {
        my $ip_proto = contains($ip, ':') ? 'IPv6' : 'IPv4';
        my $ip_hash  = sha3_512_base64 $ip;
        return ($ip_hash, $ip_proto);
    }

    # Sub: read_lines
    # - Purpose: Iterate files matching glob by age; invoke $cb for each line.
    # - Params: $glob (str) file glob; $cb (code) callback ($year, @fields).
    # - Return: undef; stops early if callback returns undef for a file.
    sub read_lines ($glob, $cb) {
        my sub year ($path) {
            localtime((stat $path)->mtime)->strftime('%Y');
        }

        my sub open_file ($path) {
            my $flag = $path =~ /\.gz$/ ? '<:gzip' : '<';
            open my $fd, $flag, $path or die "$path: $!";
            return $fd;
        }

        my $last = false;
        say 'File path glob matches: ' . join(' ', glob $glob);

    LAST:
        for my $path (sort { -M $a <=> -M $b } glob $glob) {
            say "Processing $path";

            my $file = open_file $path;
            my $year = year $file;

            while (<$file>) {
                next if contains($_, 'logfile turned over');

                # last == true means: After this file, don't process more
                $last = true unless defined $cb->($year, split / +/);
            }

            say "Closing $path (last:$last)";
            close $file;
            last LAST if $last;
        }
    }

    # Sub: parse_web_logs
    # - Purpose: Parse web log lines into normalized events and pass to callback.
    # - Params: $last_processed_date (YYYYMMDD int) lower bound; $cb (code) event consumer.
    # - Return: undef.
    sub parse_web_logs ($last_processed_date, $cb) {
        my sub parse_date ($date) {
            my $t = Time::Piece->strptime($date, '[%d/%b/%Y:%H:%M:%S');
            return ($t->strftime('%Y%m%d'), $t->strftime('%H%M%S'));
        }

        my sub parse_web_line (@line) {
            my ($date, $time) = parse_date $line [4];
            return undef if $date < $last_processed_date;

            # X-Forwarded-For?
            my $ip = $line[-2] eq '-' ? $line[1] : $line[-2];
            my ($ip_hash, $ip_proto) = anonymize_ip $ip;

            return {
                proto    => 'web',
                host     => $line[0],
                ip_hash  => $ip_hash,
                ip_proto => $ip_proto,
                date     => $date,
                time     => $time,
                uri_path => $line[7],
                status   => $line[9],
            };
        }

        read_lines web_logs_glob(), sub ($year, @line) {
            $cb->(parse_web_line @line);
        };
    }

    # Sub: parse_gemini_logs
    # - Purpose: Parse vger/relayd lines, merge paired entries, and emit events.
    # - Params: $last_processed_date (YYYYMMDD int); $cb (code) event consumer.
    # - Return: undef.
    sub parse_gemini_logs ($last_processed_date, $cb) {
        my sub parse_date ($year, @line) {
            my $timestr = "$line[0] $line[1]";
            return Time::Piece->strptime($timestr, '%b %d')->strftime("$year%m%d");
        }

        my sub parse_vger_line ($year, @line) {
            my $full_path = $line[5];
            $full_path =~ s/"//g;
            my ($proto, undef, $host, $uri_path) = split '/', $full_path, 4;
            $uri_path = '' unless defined $uri_path;

            return {
                proto    => 'gemini',
                host     => $host,
                uri_path => "/$uri_path",
                status   => $line[6],
                date     => int(parse_date($year, @line)),
                time     => $line[2],
            };
        }

        my sub parse_relayd_line ($year, @line) {
            my $date = int(parse_date($year, @line));

            my ($ip_hash, $ip_proto) = anonymize_ip $line [12];
            return {
                ip_hash  => $ip_hash,
                ip_proto => $ip_proto,
                date     => $date,
                time     => $line[2],
            };
        }

        # Expect one vger and one relayd log line per event! So collect
        # both events (one from one log line each) and then merge the result hash!
        my ($vger, $relayd);
        read_lines gemini_logs_glob(), sub ($year, @line) {
            if ($line[4] eq 'vger:') {
                $vger = parse_vger_line $year, @line;
            }
            elsif ($line[5] eq 'relay' and startswith($line[6], 'gemini')) {
                $relayd = parse_relayd_line $year, @line;
                return undef
                    if $relayd->{date} < $last_processed_date;
            }

            if (defined $vger and defined $relayd and $vger->{time} eq $relayd->{time}) {
                $cb->({ %$vger, %$relayd });
                $vger = $relayd = undef;
            }

            true;
        };
    }

    # Sub: parse_logs
    # - Purpose: Coordinate parsing for both web and gemini, aggregating into stats.
    # - Params: $last_web_date, $last_gemini_date (YYYYMMDD int), $odds_file, $odds_log.
    # - Return: stats hashref keyed by "proto_YYYYMMDD".
    sub parse_logs ($last_web_date, $last_gemini_date, $odds_file, $odds_log) {
        my $agg = Foostats::Aggregator->new($odds_file, $odds_log);

        say "Last web date: $last_web_date";
        say "Last gemini date: $last_gemini_date";

        parse_web_logs $last_web_date, sub ($event) {
            $agg->add($event);
        };
        parse_gemini_logs $last_gemini_date, sub ($event) {
            $agg->add($event);
        };

        return $agg->{stats};
    }
}

# Package: Foostats::Filter — request filtering and logging
# - Purpose: Identify odd URI patterns and excessive requests per second per IP.
# - Notes: Maintains an in-process blocklist for the current run.
package Foostats::Filter {
    use String::Util qw(contains startswith endswith);

    # Sub: new
    # - Purpose: Construct a filter with odd patterns and a log path.
    # - Params: $odds_file (str) pattern list; $log_path (str) append-only log file.
    # - Return: blessed Foostats::Filter instance.
    sub new ($class, $odds_file, $log_path) {
        say "Logging filter to $log_path";
        my @odds = FileHelper::read_lines($odds_file);
        bless { odds => \@odds, log_path => $log_path }, $class;
    }

    # Sub: ok
    # - Purpose: Check if an event passes filters; updates block state/logging.
    # - Params: $event (hashref) normalized request.
    # - Return: true if allowed; false if blocked.
    sub ok ($self, $event) {
        state %blocked = ();
        return false if exists $blocked{ $event->{ip_hash} };

        if ($self->odd($event) or $self->excessive($event)) {
            ($blocked{ $event->{ip_hash} } //= 0)++;
            return false;
        }
        else {
            return true;
        }
    }

    # Sub: odd
    # - Purpose: Match URI path against user-provided odd patterns (substring match).
    # - Params: $event (hashref) with uri_path.
    # - Return: true if odd (blocked), false otherwise.
    sub odd ($self, $event) {
        \my $uri_path = \$event->{uri_path};

        for ($self->{odds}->@*) {
            next if !defined $_ || $_ eq '' || /^\s*#/;
            next unless contains($uri_path, $_);
            $self->log('WARN', $uri_path, "contains $_ and is odd and will therefore be blocked!");
            return true;
        }

        $self->log('OK', $uri_path, "appears fine...");
        return false;
    }

    # Sub: log
    # - Purpose: Deduplicated append-only logging for filter decisions.
    # - Params: $severity (OK|WARN), $subject (str), $message (str).
    # - Return: undef.
    sub log ($self, $severity, $subject, $message) {
        state %dedup;

        # Don't log if path was already logged
        return if exists $dedup{$subject};
        $dedup{$subject} = 1;

        open(my $fh, '>>', $self->{log_path}) or die $self->{log_path} . ": $!";
        print $fh "$severity: $subject $message\n";
        close($fh);
    }

    # Sub: excessive
    # - Purpose: Block if an IP makes more than one request within the same second.
    # - Params: $event (hashref) with time and ip_hash.
    # - Return: true if blocked; false otherwise.
    sub excessive ($self, $event) {
        \my $time    = \$event->{time};
        \my $ip_hash = \$event->{ip_hash};

        state $last_time = $time;    # Time with second: 'HH:MM:SS'
        state %count     = ();       # IPs accessing within the same second!

        if ($last_time ne $time) {
            $last_time = $time;
            %count     = ();
            return false;
        }

        # IP requested site more than once within the same second!?
        if (1 < ++($count{$ip_hash} //= 0)) {
            $self->log('WARN', $ip_hash, "blocked due to excessive requesting...");
            return true;
        }

        return false;
    }
}

# Package: Foostats::Aggregator — in-memory stats builder
# - Purpose: Apply filters and accumulate counts, unique IPs per feed/page.
package Foostats::Aggregator {
    use String::Util qw(contains startswith endswith);

    use constant {
        ATOM_FEED_URI => '/gemfeed/atom.xml',
        GEMFEED_URI   => '/gemfeed/index.gmi',
        GEMFEED_URI_2 => '/gemfeed/',
    };

    # Sub: new
    # - Purpose: Construct aggregator with a filter and empty stats store.
    # - Params: $odds_file (str), $odds_log (str).
    # - Return: Foostats::Aggregator instance.
    sub new ($class, $odds_file, $odds_log) {
        bless { filter => Foostats::Filter->new($odds_file, $odds_log), stats => {} }, $class;
    }

    # Sub: add
    # - Purpose: Apply filter, update counts and unique-IP sets, and return event.
    # - Params: $event (hashref) normalized event; ignored if undef.
    # - Return: $event; filtered events increment filtered count only.
    sub add ($self, $event) {
        return undef unless defined $event;

        my $date     = $event->{date};
        my $date_key = $event->{proto} . "_$date";

        # Stats data model per protocol+day (key: "proto_YYYYMMDD"):
        # - count: per-proto request count, per IP version, and filtered count
        # - feed_ips: unique IPs per feed type (atom_feed, gemfeed)
        # - page_ips: unique IPs per host and per URL
        $self->{stats}{$date_key} //= {
            count    => { filtered => 0, },
            feed_ips => {
                atom_feed => {},
                gemfeed   => {},
            },
            page_ips => {
                hosts => {},
                urls  => {},
            },
        };

        \my $s = \$self->{stats}{$date_key};
        unless ($self->{filter}->ok($event)) {
            $s->{count}{filtered}++;
            return $event;
        }

        $self->add_count($s, $event);
        $self->add_page_ips($s, $event) unless $self->add_feed_ips($s, $event);
        return $event;
    }

    # Sub: add_count
    # - Purpose: Increment totals by protocol and IP version.
    # - Params: $stats (hashref) date bucket; $event (hashref).
    # - Return: undef.
    sub add_count ($self, $stats, $event) {
        \my $c = \$stats->{count};
        \my $e = \$event;

        ($c->{ $e->{proto} }    //= 0)++;
        ($c->{ $e->{ip_proto} } //= 0)++;
    }

    # Sub: add_feed_ips
    # - Purpose: If event hits feed endpoints, add unique IP and short-circuit.
    # - Params: $stats (hashref), $event (hashref).
    # - Return: 1 if feed matched; 0 otherwise.
    sub add_feed_ips ($self, $stats, $event) {
        \my $f = \$stats->{feed_ips};
        \my $e = \$event;

        # Atom feed (exact path match, allow optional query string)
        if ($e->{uri_path} =~ m{^/gemfeed/atom\.xml(?:[?#].*)?$}) {
            ($f->{atom_feed}->{ $e->{ip_hash} } //= 0)++;
            return 1;
        }

        # Gemfeed index: '/gemfeed/' or '/gemfeed/index.gmi' (optionally with query)
        if ($e->{uri_path} =~ m{^/gemfeed/(?:index\.gmi)?(?:[?#].*)?$}) {
            ($f->{gemfeed}->{ $e->{ip_hash} } //= 0)++;
            return 1;
        }

        return 0;
    }

    # Sub: add_page_ips
    # - Purpose: Track unique IPs per host and per URL for .html/.gmi pages.
    # - Params: $stats (hashref), $event (hashref).
    # - Return: undef.
    sub add_page_ips ($self, $stats, $event) {
        \my $e = \$event;
        \my $p = \$stats->{page_ips};

        return if !endswith($e->{uri_path}, '.html') && !endswith($e->{uri_path}, '.gmi');

        ($p->{hosts}->{ $e->{host} }->{ $e->{ip_hash} } //= 0)++;
        ($p->{urls}->{ $e->{host} . $e->{uri_path} }->{ $e->{ip_hash} } //= 0)++;
    }
}

# Package: Foostats::FileOutputter — write per-day stats to disk
# - Purpose: Persist aggregated stats to gzipped JSON files under a stats dir.
package Foostats::FileOutputter {
    use JSON;
    use Sys::Hostname;
    use PerlIO::gzip;

    # Sub: new
    # - Purpose: Create outputter with stats_dir; ensures directory exists.
    # - Params: %args (hash) must include stats_dir.
    # - Return: Foostats::FileOutputter instance.
    sub new ($class, %args) {
        my $self = bless \%args, $class;
        mkdir $self->{stats_dir} or die $self->{stats_dir} . ": $!" unless -d $self->{stats_dir};
        return $self;
    }

    # Sub: last_processed_date
    # - Purpose: Determine the most recent processed date for a protocol for this host.
    # - Params: $proto (str) 'web' or 'gemini'.
    # - Return: YYYYMMDD int (0 if none found).
    sub last_processed_date ($self, $proto) {
        my $hostname  = hostname();
        my @processed = glob $self->{stats_dir} . "/${proto}_????????.$hostname.json.gz";
        my ($date)    = @processed ? ($processed[-1] =~ /_(\d{8})\.$hostname\.json.gz/) : 0;
        return int($date);
    }

    # Sub: write
    # - Purpose: Write one gzipped JSON file per date bucket to stats_dir.
    # - Params: none (uses $self->{stats}).
    # - Return: undef.
    sub write ($self) {
        $self->for_dates(
            sub ($self, $date_key, $stats) {
                my $hostname = hostname();
                my $path     = $self->{stats_dir} . "/${date_key}.$hostname.json.gz";
                FileHelper::write_json_gz $path, $stats;
            }
        );
    }

    # Sub: for_dates
    # - Purpose: Iterate date-keyed stats in sorted order and call $cb.
    # - Params: $cb (code) receives ($self, $date_key, $stats).
    # - Return: undef.
    sub for_dates ($self, $cb) {
        $cb->($self, $_, $self->{stats}{$_}) for sort keys $self->{stats}->%*;
    }
}

# Package: Foostats::Replicator — pull partner stats files over HTTP(S)
# - Purpose: Fetch recent partner node stats into local stats dir.
package Foostats::Replicator {
    use JSON;
    use File::Basename;
    use LWP::UserAgent;
    use String::Util qw(endswith);

    # Sub: replicate
    # - Purpose: For each proto and last 31 days, replicate newest files.
    # - Params: $stats_dir (str) local dir; $partner_node (str) hostname.
    # - Return: undef (best-effort fetches).
    sub replicate ($stats_dir, $partner_node) {
        say "Replicating from $partner_node";

        for my $proto (qw(gemini web)) {
            my $count = 0;

            for my $date (DateHelper::last_month_dates) {
                my $file_base = "${proto}_${date}";
                my $dest_path = "${file_base}.$partner_node.json.gz";

                replicate_file(
                    "https://$partner_node/foostats/$dest_path",
                    "$stats_dir/$dest_path",
                    $count++ < 3,    # Always replicate the newest 3 files.
                );
            }
        }
    }

    # Sub: replicate_file
    # - Purpose: Download a single URL to a destination unless already present (unless forced).
    # - Params: $remote_url (str) source; $dest_path (str) destination; $force (bool/int).
    # - Return: undef; logs failures.
    sub replicate_file ($remote_url, $dest_path, $force) {

        # $dest_path already exists, not replicating it
        return if !$force && -f $dest_path;

        say "Replicating $remote_url to $dest_path (force:$force)... ";
        my $response = LWP::UserAgent->new->get($remote_url);
        unless ($response->is_success) {
            say "\nFailed to fetch the file: " . $response->status_line;
            return;
        }

        FileHelper::write $dest_path, $response->decoded_content;
        say 'done';
    }
}

# Package: Foostats::Merger — merge per-host daily stats into a single view
# - Purpose: Merge multiple node files per day into totals and unique counts.
package Foostats::Merger {

    # Sub: merge
    # - Purpose: Produce merged stats for the last month (date => stats hashref).
    # - Params: $stats_dir (str) directory with daily gz JSON files.
    # - Return: hash (not ref) of date => merged stats.
    sub merge ($stats_dir) {
        my %merge;
        $merge{$_} = merge_for_date($stats_dir, $_) for DateHelper::last_month_dates;
        return %merge;
    }

    # Sub: merge_for_date
    # - Purpose: Merge all node files for a specific date into one stats hashref.
    # - Params: $stats_dir (str), $date (YYYYMMDD str/int).
    # - Return: { feed_ips => {...}, count => {...}, page_ips => {...} }.
    sub merge_for_date ($stats_dir, $date) {
        printf "Merging for date %s\n", $date;
        my @stats = stats_for_date($stats_dir, $date);
        return {
            feed_ips => feed_ips(@stats),
            count    => count(@stats),
            page_ips => page_ips(@stats),
        };
    }

    # Sub: merge_ips
    # - Purpose: Deep-ish merge helper: sums numbers, merges hash-of-hash counts.
    # - Params: $a (hashref target), $b (hashref source), $key_transform (code|undef).
    # - Return: undef; updates $a in place; dies on incompatible types.
    sub merge_ips ($a, $b, $key_transform = undef) {
        my sub merge ($a, $b) {
            while (my ($key, $val) = each %$b) {
                $a->{$key} //= 0;
                $a->{$key} += $val;
            }
        }

        my $is_num = qr/^\d+(\.\d+)?$/;

        while (my ($key, $val) = each %$b) {
            $key = $key_transform->($key) if defined $key_transform;

            if (not exists $a->{$key}) {
                $a->{$key} = $val;
            }
            elsif (ref($a->{$key}) eq 'HASH' && ref($val) eq 'HASH') {
                merge($a->{$key}, $val);
            }
            elsif ($a->{$key} =~ $is_num && $val =~ $is_num) {
                $a->{$key} += $val;
            }
            else {
                die "Not merging tkey '%s' (ref:%s): '%s' (ref:%s) with '%s' (ref:%s)\n",
                    $key,
                    ref($key), $a->{$key},
                    ref($a->{$key}),
                    $val,
                    ref($val);
            }
        }
    }

    # Sub: feed_ips
    # - Purpose: Merge feed unique-IP sets from per-proto stats into totals.
    # - Params: @stats (list of stats hashrefs) each with {proto, feed_ips}.
    # - Return: hashref with Total and per-proto feed counts.
    sub feed_ips (@stats) {
        my (%gemini, %web);

        for my $stats (@stats) {
            my $merge = $stats->{proto} eq 'web' ? \%web : \%gemini;
            printf "Merging proto %s feed IPs\n", $stats->{proto};
            merge_ips($merge, $stats->{feed_ips});
        }

        my %total;
        merge_ips(\%total, $web{$_})    for keys %web;
        merge_ips(\%total, $gemini{$_}) for keys %gemini;

        my %merge = (
            'Total'          => scalar keys %total,
            'Gemini Gemfeed' => scalar keys $gemini{gemfeed}->%*,
            'Gemini Atom'    => scalar keys $gemini{atom_feed}->%*,
            'Web Gemfeed'    => scalar keys $web{gemfeed}->%*,
            'Web Atom'       => scalar keys $web{atom_feed}->%*,
        );

        return \%merge;
    }

    # Sub: count
    # - Purpose: Sum request counters across stats for the day.
    # - Params: @stats (list of stats hashrefs) each with {count}.
    # - Return: hashref of summed counters.
    sub count (@stats) {
        my %merge;

        for my $stats (@stats) {
            while (my ($key, $val) = each $stats->{count}->%*) {
                $merge{$key} //= 0;
                $merge{$key} += $val;
            }
        }

        return \%merge;
    }

    # Sub: page_ips
    # - Purpose: Merge unique IPs per host and per URL; coalesce truncated endings.
    # - Params: @stats (list of stats hashrefs) with {page_ips}{urls,hosts}.
    # - Return: hashref with urls/hosts each mapping => unique counts.
    sub page_ips (@stats) {
        my %merge = (
            urls  => {},
            hosts => {}
        );

        for my $key (keys %merge) {
            merge_ips(
                $merge{$key},
                $_->{page_ips}->{$key},
                sub ($key) {
                    $key =~ s/\.gmi$/\.html/;
                    $key;
                }
            ) for @stats;

            # Keep only uniq IP count
            $merge{$key}->{$_} = scalar keys $merge{$key}->{$_}->%* for keys $merge{$key}->%*;
        }

        return \%merge;
    }

    # Sub: stats_for_date
    # - Purpose: Load all stats files for a date across protos; tag proto/path.
    # - Params: $stats_dir (str), $date (YYYYMMDD).
    # - Return: list of stats hashrefs.
    sub stats_for_date ($stats_dir, $date) {
        my @stats;

        for my $proto (qw(gemini web)) {
            for my $path (<$stats_dir/${proto}_${date}.*.json.gz>) {
                printf "Reading %s\n", $path;
                push @stats, FileHelper::read_json_gz($path);
                @{ $stats[-1] }{qw(proto path)} = ($proto, $path);
            }
        }

        return @stats;
    }
}

# Package: Foostats::Reporter — build gemtext/HTML daily and summary reports
# - Purpose: Render daily reports and rolling summaries (30/365), and index pages.
package Foostats::Reporter {
    use Time::Piece;
    use HTML::Entities qw(encode_entities);

    our @TRUNCATED_URL_MAPPINGS;

    sub reset_truncated_url_mappings { @TRUNCATED_URL_MAPPINGS = (); }

    sub _record_truncated_url_mapping {
        my ($truncated, $original) = @_;
        push @TRUNCATED_URL_MAPPINGS, { truncated => $truncated, original => $original };
    }

    sub _lookup_full_url_for {
        my ($candidate) = @_;
        for my $idx (0 .. $#TRUNCATED_URL_MAPPINGS) {
            my $entry = $TRUNCATED_URL_MAPPINGS[$idx];
            next unless $entry->{truncated} eq $candidate;
            my $original = $entry->{original};
            splice @TRUNCATED_URL_MAPPINGS, $idx, 1;
            return $original;
        }
        return undef;
    }

    # Sub: truncate_url
    # - Purpose: Middle-ellipsize long URLs to fit within a target length.
    # - Params: $url (str), $max_length (int default 100).
    # - Return: possibly truncated string.
    sub truncate_url {
        my ($url, $max_length) = @_;
        $max_length //= 100;    # Default to 100 characters
        return $url if length($url) <= $max_length;

        # Calculate how many characters we need to remove
        my $ellipsis         = '...';
        my $ellipsis_length  = length($ellipsis);
        my $available_length = $max_length - $ellipsis_length;

        # Split available length between start and end, favoring the end
        my $keep_start = int($available_length * 0.4);       # 40% for start
        my $keep_end   = $available_length - $keep_start;    # 60% for end

        my $start = substr($url, 0, $keep_start);
        my $end   = substr($url, -$keep_end);

        return $start . $ellipsis . $end;
    }

    # Sub: truncate_urls_for_table
    # - Purpose: Truncate URL cells in-place to fit target table width.
    # - Params: $url_rows (arrayref of [url,count]), $count_column_header (str).
    # - Return: undef; mutates $url_rows.
    sub truncate_urls_for_table {
        my ($url_rows, $count_column_header) = @_;

        # Calculate the maximum width needed for the count column
        my $max_count_width = length($count_column_header);
        for my $row (@$url_rows) {
            my $count_width = length($row->[1]);
            $max_count_width = $count_width if $count_width > $max_count_width;
        }

        # Row format: "| URL... | count |" with padding
        # Calculate: "| " (2) + URL + " | " (3) + count_with_padding + " |" (2)
        my $max_url_length = 100 - 7 - $max_count_width;
        $max_url_length = 70 if $max_url_length > 70;    # Cap at reasonable length

        # Truncate URLs in place
        for my $row (@$url_rows) {
            my $original  = $row->[0];
            my $truncated = truncate_url($original, $max_url_length);
            if ($truncated ne $original) {
                _record_truncated_url_mapping($truncated, $original);
            }
            $row->[0] = $truncated;
        }
    }

    # Sub: format_table
    # - Purpose: Render a simple monospace table from headers and rows.
    # - Params: $headers (arrayref), $rows (arrayref of arrayrefs).
    # - Return: string with lines separated by \n.
    sub format_table {
        my ($headers, $rows) = @_;

        my @widths;
        for my $col (0 .. $#{$headers}) {
            my $max_width = length($headers->[$col]);
            for my $row (@$rows) {
                my $len = length($row->[$col]);
                $max_width = $len if $len > $max_width;
            }
            push @widths, $max_width;
        }

        my $header_line    = '|';
        my $separator_line = '|';
        for my $col (0 .. $#{$headers}) {
            $header_line    .= sprintf(" %-*s |", $widths[$col], $headers->[$col]);
            $separator_line .= '-' x ($widths[$col] + 2) . '|';
        }

        my @table_lines;
        push @table_lines, $separator_line;    # Add top terminator
        push @table_lines, $header_line;
        push @table_lines, $separator_line;

        for my $row (@$rows) {
            my $row_line = '|';
            for my $col (0 .. $#{$row}) {
                $row_line .= sprintf(" %-*s |", $widths[$col], $row->[$col]);
            }
            push @table_lines, $row_line;
        }

        push @table_lines, $separator_line;    # Add bottom terminator

        return join("\n", @table_lines);
    }

    # Convert gemtext to HTML
    # Sub: gemtext_to_html
    # - Purpose: Convert a subset of Gemtext to compact HTML, incl. code blocks and lists.
    # - Params: $content (str) Gemtext.
    # - Return: HTML string (fragment).
    sub gemtext_to_html {
        my ($content) = @_;
        my $html      = "";
        my @lines     = split /\n/, $content;
        my $i         = 0;

        while ($i < @lines) {
            my $line = $lines[$i];

            if ($line =~ /^```/) {
                my @block_lines;
                $i++;    # Move past the opening ```
                while ($i < @lines && $lines[$i] !~ /^```/) {
                    push @block_lines, $lines[$i];
                    $i++;
                }
                $html .= _gemtext_to_html_code_block(\@block_lines);
            }
            elsif ($line =~ /^### /) {
                $html .= _gemtext_to_html_heading($line);
            }
            elsif ($line =~ /^## /) {
                $html .= _gemtext_to_html_heading($line);
            }
            elsif ($line =~ /^# /) {
                $html .= _gemtext_to_html_heading($line);
            }
            elsif ($line =~ /^=> /) {
                $html .= _gemtext_to_html_link($line);
            }
            elsif ($line =~ /^\* /) {
                my @list_items;
                while ($i < @lines && $lines[$i] =~ /^\* /) {
                    push @list_items, $lines[$i];
                    $i++;
                }
                $html .= _gemtext_to_html_list(\@list_items);
                $i--;    # Decrement to re-evaluate the current line in the outer loop
            }
            elsif ($line !~ /^\s*$/) {
                $html .= _gemtext_to_html_paragraph($line);
            }

            # Else, it's a blank line, which we skip for compact output.
            $i++;
        }

        return $html;
    }

    sub _gemtext_to_html_code_block {
        my ($lines) = @_;
        if (is_ascii_table($lines)) {
            return convert_ascii_table_to_html($lines);
        }
        else {
            my $html = "<pre>\n";
            for my $code_line (@$lines) {
                $html .= encode_entities($code_line) . "\n";
            }
            $html .= "</pre>\n";
            return $html;
        }
    }

    sub _gemtext_to_html_heading {
        my ($line) = @_;
        if ($line =~ /^### (.*)/) {
            return "<h3>" . encode_entities($1) . "</h3>\n";
        }
        elsif ($line =~ /^## (.*)/) {
            return "<h2>" . encode_entities($1) . "</h2>\n";
        }
        elsif ($line =~ /^# (.*)/) {
            return "<h1>" . encode_entities($1) . "</h1>\n";
        }
        return '';
    }

    sub _gemtext_to_html_link {
        my ($line) = @_;
        if ($line =~ /^=> (\S+)\s+(.*)/) {
            my ($url, $text) = ($1, $2);

            # Drop 365-day summary links from HTML output
            return '' if $url =~ /(?:^|[\/.])365day_summary_\d{8}\.gmi$/;

            # Convert .gmi links to .html
            $url =~ s/\.gmi$/\.html/;
            return "<p><a href=\"" . encode_entities($url) . "\">" . encode_entities($text) . "</a></p>\n";
        }
        return '';
    }

    sub _gemtext_to_html_list {
        my ($lines) = @_;
        my $html = "<ul>\n";
        for my $line (@$lines) {
            if ($line =~ /^\* (.*)/) {
                $html .= "<li>" . linkify_text($1) . "</li>\n";
            }
        }
        $html .= "</ul>\n";
        return $html;
    }

    sub _gemtext_to_html_paragraph {
        my ($line) = @_;
        return "<p>" . linkify_text($line) . "</p>\n";
    }

    # Check if the lines form an ASCII table
    # Sub: is_ascii_table
    # - Purpose: Heuristically detect if a code block is an ASCII table.
    # - Params: $lines (arrayref of strings).
    # - Return: 1 if likely table; 0 otherwise.
    sub is_ascii_table {
        my ($lines) = @_;
        return 0 if @$lines < 3;    # Need at least header, separator, and one data row

        # Check for separator lines with dashes and pipes
        for my $line (@$lines) {
            return 1 if $line =~ /^\|?[\s\-]+\|/;
        }
        return 0;
    }

    # Convert ASCII table to HTML table
    # Sub: convert_ascii_table_to_html
    # - Purpose: Convert simple ASCII table lines to an HTML <table>.
    # - Params: $lines (arrayref of strings).
    # - Return: HTML string.
    sub convert_ascii_table_to_html {
        my ($lines)       = @_;
        my $html          = "<table>\n";
        my $row_count     = 0;
        my $total_col_idx = -1;

        for my $line (@$lines) {

            # Skip separator lines
            next if $line =~ /^\|?[\s\-]+\|/ && $line =~ /\-/;

            # Parse table row
            my @cells = split /\s*\|\s*/, $line;
            @cells = grep { length($_) > 0 } @cells;    # Remove empty cells

            if (@cells) {
                my $is_total_row = (trim($cells[0]) eq 'Total');
                $html .= "<tr>\n";

                if ($row_count == 0) {                  # Header row
                    for my $i (0 .. $#cells) {
                        if (trim($cells[$i]) eq 'Total') {
                            $total_col_idx = $i;
                            last;
                        }
                    }
                }

                my $tag = ($row_count == 0) ? "th" : "td";
                for my $i (0 .. $#cells) {
                    my $val          = trim($cells[$i]);
                    my $cell_content = linkify_text($val);

                    if ($is_total_row || ($i == $total_col_idx && $row_count > 0)) {
                        $html .= "  <$tag><b>" . $cell_content . "</b></$tag>\n";
                    }
                    else {
                        $html .= "  <$tag>" . $cell_content . "</$tag>\n";
                    }
                }
                $html .= "</tr>\n";
                $row_count++;
            }
        }

        $html .= "</table>\n";
        return $html;
    }

    # Trim whitespace from string
    # Sub: trim
    # - Purpose: Strip leading/trailing whitespace.
    # - Params: $str (str).
    # - Return: trimmed string.
    sub trim {
        my ($str) = @_;
        $str =~ s/^\s+//;
        $str =~ s/\s+$//;
        return $str;
    }

    # Build an href for a token that looks like a URL or FQDN
    # Sub: _guess_href
    # - Purpose: Infer absolute href for a token (supports gemini for .gmi).
    # - Params: $token (str) token from text.
    # - Return: href string or undef.
    sub _guess_href {
        my ($token) = @_;
        my $t = $token;
        $t =~ s/^\s+//;
        $t =~ s/\s+$//;

        # Already absolute http(s)
        return $t if $t =~ m{^https?://}i;

        # Extract trailing punctuation to avoid including it in href
        my $trail = '';
        if ($t =~ s{([)\]\}.,;:!?]+)$}{}) { $trail = $1; }

        # host[/path]
        if ($t =~ m{^([A-Za-z0-9.-]+\.[A-Za-z]{2,})(/[^\s<]*)?$}) {
            my ($host, $path) = ($1, $2 // '');
            my $is_gemini = defined($path) && $path =~ /\.gmi(?:[?#].*)?$/i;
            my $scheme    = 'https';

            # If truncated, fall back to host root
            my $href = sprintf('%s://%s%s', $scheme, $host, ($path eq '' ? '/' : $path));
            return ($href . $trail);
        }

        return undef;
    }

    # Turn any URLs/FQDNs in the provided text into anchors
    # Sub: linkify_text
    # - Purpose: Replace URL/FQDN tokens in text with HTML anchors.
    # - Params: $text (str) input text.
    # - Return: HTML string with entities encoded.
    sub linkify_text {
        my ($text) = @_;
        return '' unless defined $text;

        my $out = '';
        my $pos = 0;
        while ($text =~ m{((?:https?://)?[A-Za-z0-9.-]+\.[A-Za-z]{2,}(?:/[^\s<]*)?)}g) {
            my $match = $1;
            my $start = $-[1];
            my $end   = $+[1];

            # Emit preceding text
            $out .= encode_entities(substr($text, $pos, $start - $pos));

            # Separate trailing punctuation from the match
            my ($core, $trail) = ($match, '');
            if ($core =~ s{([)\]\}.,;:!?]+)$}{}) { $trail = $1; }

            my $display = $core;
            if (my $full = _lookup_full_url_for($core)) {
                $display = $full;
            }

            my $href = _guess_href($display);
            if (!$href) {
                $href = _guess_href($core);
            }

            if ($href) {
                $href =~ s/\.gmi$/\.html/i;
                $out .= sprintf(
                    '<a href="%s">%s</a>%s',
                    encode_entities($href), encode_entities($display),
                    encode_entities($trail)
                );
            }
            else {
                # Not a linkable token after all
                $out .= encode_entities($match);
            }
            $pos = $end;
        }

        # Remainder
        $out .= encode_entities(substr($text, $pos));
        return $out;
    }

    # Use HTML::Entities::encode_entities imported above

    # Generate HTML wrapper
    # Sub: generate_html_page
    # - Purpose: Wrap content in a minimal HTML5 page with a title and CSS reset.
    # - Params: $title (str), $content (str) HTML fragment.
    # - Return: full HTML page string.
    sub generate_html_page {
        my ($title, $content) = @_;
        return qq{<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>$title</title>
    <style>
        /* Compact, full-width layout */
        :root {
            --pad: 8px;
        }
        html, body {
            height: 100%;
        }
        body {
            font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", "Courier New", monospace;
            line-height: 1.3;
            margin: 0;
            padding: var(--pad);
            background: #fff;
            color: #000;
        }
        /* Headings: smaller and tighter */
        h1, h2, h3 { margin: 0.5em 0 0.25em; font-weight: 600; }
        h1 { font-size: 1em; }
        h2 { font-size: 0.95em; }
        h3 { font-size: 0.9em; }
        /* Paragraphs and lists: minimal vertical rhythm */
        p { margin: 0.2em 0; }
        ul { margin: 0.3em 0; padding-left: 1.2em; }
        li { margin: 0.1em 0; }
        /* Code blocks and tables */
        pre {
            overflow-x: auto;
            white-space: pre;
            margin: 0.3em 0;
        }
        table {
            border-collapse: collapse;
            table-layout: auto; /* size columns by content */
            width: auto;        /* do not stretch to full width */
            max-width: 100%;
            margin: 0.5em 0;
            font-size: 0.95em;
            display: inline-table; /* keep as compact as content allows */
        }
        th, td {
            padding: 0.1em 0.3em;
            text-align: left;
            white-space: nowrap; /* avoid wide columns caused by wrapping */
        }
        /* Links */
        a { color: #06c; text-decoration: underline; }
        a:visited { color: #639; }
        /* Rules */
        hr { border: none; border-top: 1px solid #ccc; margin: 0.5em 0; }
    </style>
</head>
<body>
$content
</body>
</html>
};
    }

    # Sub: should_generate_daily_report
    # - Purpose: Check if a daily report should be generated based on file existence and age.
    # - Params: $date (YYYYMMDD), $report_path (str), $html_report_path (str).
    # - Return: 1 if report should be generated, 0 otherwise.
    sub should_generate_daily_report {
        my ($date, $report_path, $html_report_path) = @_;

        my ($year, $month, $day) = $date =~ /(\d{4})(\d{2})(\d{2})/;

        # Calculate age of the data based on date in filename
        my $today     = Time::Piece->new();
        my $file_date = Time::Piece->strptime($date, '%Y%m%d');
        my $age_days  = ($today - $file_date) / (24 * 60 * 60);

        if (-e $report_path && -e $html_report_path) {

            # Files exist
            if ($age_days <= 3) {

                # Data is recent (within 3 days), regenerate it
                say "Regenerating daily report for $year-$month-$day (data age: "
                    . sprintf("%.1f", $age_days)
                    . " days)";
                return 1;
            }
            else {
                # Data is old (older than 3 days), skip if files exist
                say "Skipping daily report for $year-$month-$day (files exist, data age: "
                    . sprintf("%.1f", $age_days)
                    . " days)";
                return 0;
            }
        }
        else {
            # File doesn't exist, generate it
            say "Generating new daily report for $year-$month-$day (file doesn't exist, data age: "
                . sprintf("%.1f", $age_days)
                . " days)";
            return 1;
        }
    }

    sub generate_feed_stats_section {
        my ($stats) = @_;
        my $report_content = "### Feed Statistics\n\n";
        my @feed_rows;
        push @feed_rows, [ 'Total',          $stats->{feed_ips}{'Total'}          // 0 ];
        push @feed_rows, [ 'Gemini Gemfeed', $stats->{feed_ips}{'Gemini Gemfeed'} // 0 ];
        push @feed_rows, [ 'Gemini Atom',    $stats->{feed_ips}{'Gemini Atom'}    // 0 ];
        push @feed_rows, [ 'Web Gemfeed',    $stats->{feed_ips}{'Web Gemfeed'}    // 0 ];
        push @feed_rows, [ 'Web Atom',       $stats->{feed_ips}{'Web Atom'}       // 0 ];
        $report_content .= "```\n";
        $report_content .= format_table([ 'Feed Type', 'Count' ], \@feed_rows);
        $report_content .= "\n```\n\n";
        return $report_content;
    }

    sub generate_top_n_table {
        my (%args)  = @_;
        my $title   = $args{title};
        my $data    = $args{data};
        my $headers = $args{headers};
        my $limit   = $args{limit}  // 50;
        my $is_url  = $args{is_url} // 0;

        my $report_content = "### $title\n\n";
        my @rows;
        my @sorted_keys =
            sort { ($data->{$b} // 0) <=> ($data->{$a} // 0) }
            keys %$data;
        my $truncated = @sorted_keys > $limit;
        @sorted_keys = @sorted_keys[ 0 .. $limit - 1 ] if $truncated;

        for my $key (@sorted_keys) {
            push @rows, [ $key, $data->{$key} // 0 ];
        }

        if ($is_url) {
            truncate_urls_for_table(\@rows, $headers->[1]);
        }

        $report_content .= "```\n";
        $report_content .= format_table($headers, \@rows);
        $report_content .= "\n```\n";
        if ($truncated) {
            $report_content .= "\n... and more (truncated to $limit entries).\n";
        }
        $report_content .= "\n";
        return $report_content;
    }

    sub generate_top_urls_section {
        my ($stats) = @_;
        return generate_top_n_table(
            title   => 'Top 50 URLs',
            data    => $stats->{page_ips}{urls},
            headers => [ 'URL', 'Unique Visitors' ],
            is_url  => 1,
        );
    }

    sub generate_top_hosts_section {
        my ($stats) = @_;
        return generate_top_n_table(
            title   => 'Page Statistics (by Host)',
            data    => $stats->{page_ips}{hosts},
            headers => [ 'Host', 'Unique Visitors' ],
        );
    }

    sub generate_summary_section {
        my ($stats) = @_;
        my $report_content = "### Summary\n\n";
        my $total_requests =
            ($stats->{count}{gemini} // 0) + ($stats->{count}{web} // 0);
        $report_content .= "* Total requests: $total_requests\n";
        $report_content .=
            "* Filtered requests: " . ($stats->{count}{filtered} // 0) . "\n";
        $report_content .=
            "* Gemini requests: " . ($stats->{count}{gemini} // 0) . "\n";
        $report_content .=
            "* Web requests: " . ($stats->{count}{web} // 0) . "\n";
        $report_content .=
            "* IPv4 requests: " . ($stats->{count}{IPv4} // 0) . "\n";
        $report_content .=
            "* IPv6 requests: " . ($stats->{count}{IPv6} // 0) . "\n\n";
        return $report_content;
    }

    # Sub: report
    # - Purpose: Generate daily .gmi and .html reports per date, then summaries and index.
    # - Params: $stats_dir, $output_dir, $html_output_dir, %merged (date => stats).
    # - Return: undef.
    sub report {
        my ($stats_dir, $output_dir, $html_output_dir, %merged) = @_;
        for my $date (sort { $b cmp $a } keys %merged) {
            my $stats = $merged{$date};
            next unless $stats->{count};

            my ($year, $month, $day) = $date =~ /(\d{4})(\d{2})(\d{2})/;

            my $report_path      = "$output_dir/$date.gmi";
            my $html_report_path = "$html_output_dir/$date.html";

            next unless should_generate_daily_report($date, $report_path, $html_report_path);

            reset_truncated_url_mappings();
            my $report_content = "## Stats for $year-$month-$day\n\n";
            $report_content .= generate_feed_stats_section($stats);
            $report_content .= generate_top_urls_section($stats);
            $report_content .= generate_top_hosts_section($stats);
            $report_content .= generate_summary_section($stats);

            # Add links to summary reports (only monthly)
            $report_content .= "## Related Reports\n\n";
            my $now          = localtime;
            my $current_date = $now->strftime('%Y%m%d');
            $report_content .= "=> ./30day_summary_$current_date.gmi 30-Day Summary Report\n\n";

            # Ensure output directory exists
            mkdir $output_dir unless -d $output_dir;

            # $report_path already defined above
            say "Writing report to $report_path";
            FileHelper::write($report_path, $report_content);

            # Also write HTML version
            mkdir $html_output_dir unless -d $html_output_dir;
            my $html_path    = "$html_output_dir/$date.html";
            my $html_content = gemtext_to_html($report_content);
            my $html_page    = generate_html_page("Stats for $year-$month-$day", $html_content);
            say "Writing HTML report to $html_path";
            FileHelper::write($html_path, $html_page);
            reset_truncated_url_mappings();
        }

        # Generate summary reports
        generate_summary_report(30, $stats_dir, $output_dir, $html_output_dir, %merged);

        # Generate index.gmi and index.html
        generate_index($output_dir, $html_output_dir);
    }

    # Sub: generate_summary_report
    # - Purpose: Generate N-day rolling summary in .gmi (+.html except 365-day).
    # - Params: $days (int), $stats_dir, $output_dir, $html_output_dir, %merged.
    # - Return: undef.
    sub generate_summary_report {
        my ($days, $stats_dir, $output_dir, $html_output_dir, %merged) = @_;

        # Get the last N days of dates
        my @dates     = sort { $b cmp $a } keys %merged;
        my $max_index = $days - 1;
        @dates = @dates[ 0 .. $max_index ] if @dates > $days;

        my $today       = localtime;
        my $report_date = $today->strftime('%Y%m%d');

        # Build report content
        reset_truncated_url_mappings();
        my $report_content = build_report_header($today, $days);

        # Order: feed counts -> Top URLs -> daily top 3 for last 30 days -> other tables
        $report_content .= build_feed_statistics_section(\@dates, \%merged);
        $report_content .= build_feed_statistics_daily_average_section(\@dates, \%merged);

        # Aggregate and add top lists
        my ($all_hosts, $all_urls) = aggregate_hosts_and_urls(\@dates, \%merged);
        $report_content .= build_top_urls_section($all_urls, $days);
        $report_content .= build_top3_urls_last_n_days_per_day($stats_dir, 30, \%merged);
        $report_content .= build_top_hosts_section($all_hosts, $days);
        $report_content .= build_daily_summary_section(\@dates, \%merged);

        # Add links to other summary reports
        $report_content .= build_summary_links($days, $report_date);

        # Ensure output directory exists and write the summary report
        mkdir $output_dir unless -d $output_dir;

        my $report_path = "$output_dir/${days}day_summary_$report_date.gmi";
        say "Writing $days-day summary report to $report_path";
        FileHelper::write($report_path, $report_content);

        # Also write HTML version, except for 365-day summaries (HTML suppressed)
        if ($days != 365) {
            mkdir $html_output_dir unless -d $html_output_dir;
            my $html_path    = "$html_output_dir/${days}day_summary_$report_date.html";
            my $html_content = gemtext_to_html($report_content);
            my $html_page    = generate_html_page("$days-Day Summary Report", $html_content);
            say "Writing HTML $days-day summary report to $html_path";
            FileHelper::write($html_path, $html_page);
        }
        else {
            say "Skipping HTML generation for 365-day summary (Gemtext only)";
        }

        reset_truncated_url_mappings();
    }

    sub build_feed_statistics_daily_average_section {
        my ($dates, $merged) = @_;

        my %totals;
        my $days_with_stats = 0;

        for my $date (@$dates) {
            my $stats = $merged->{$date};
            next unless $stats->{feed_ips};
            $days_with_stats++;

            for my $key (keys %{ $stats->{feed_ips} }) {
                $totals{$key} += $stats->{feed_ips}{$key};
            }
        }

        return "" unless $days_with_stats > 0;

        my @avg_rows;
        my $total_avg = 0;
        my $has_total = 0;

        # Separate 'Total' from other keys
        my @other_keys;
        for my $key (keys %totals) {
            if ($key eq 'Total') {
                $total_avg = sprintf("%.2f", $totals{$key} / $days_with_stats);
                $has_total = 1;
            }
            else {
                push @other_keys, $key;
            }
        }

        # Sort other keys and create rows
        for my $key (sort @other_keys) {
            my $avg = sprintf("%.2f", $totals{$key} / $days_with_stats);
            push @avg_rows, [ $key, $avg ];
        }

        # Add Total row at the end
        push @avg_rows, [ 'Total', $total_avg ] if $has_total;

        my $content = "### Feed Statistics Daily Average (Last 30 Days)\n\n```\n";
        $content .= format_table([ 'Feed Type', 'Daily Average' ], \@avg_rows);
        $content .= "\n```\n\n";

        return $content;
    }

    # Sub: build_report_header
    # - Purpose: Header section for summary reports.
    # - Params: $today (Time::Piece), $days (int default 30).
    # - Return: gemtext string.
    sub build_report_header {
        my ($today, $days) = @_;
        $days //= 30;    # Default to 30 days for backward compatibility

        my $content = "# $days-Day Summary Report\n\n";
        $content .= "Generated on " . $today->strftime('%Y-%m-%d') . "\n\n";
        return $content;
    }

    # Sub: build_daily_summary_section
    # - Purpose: Table of daily total counts over a period.
    # - Params: $dates (arrayref YYYYMMDD), $merged (hashref date=>stats).
    # - Return: gemtext string.
    sub build_daily_summary_section {
        my ($dates, $merged) = @_;

        my $content = "## Daily Summary Evolution (Last 30 Days)\n\n";
        $content .= "### Total Requests by Day\n\n```\n";

        my @summary_rows;
        for my $date (reverse @$dates) {
            my $stats = $merged->{$date};
            next unless $stats->{count};

            push @summary_rows, build_daily_summary_row($date, $stats);
        }

        $content .= format_table([ 'Date', 'Filtered', 'Gemini', 'Web', 'IPv4', 'IPv6', 'Total' ], \@summary_rows);
        $content .= "\n```\n\n";

        return $content;
    }

    # Sub: build_daily_summary_row
    # - Purpose: Build one table row with counts for a date.
    # - Params: $date (YYYYMMDD), $stats (hashref).
    # - Return: arrayref of cell strings.
    sub build_daily_summary_row {
        my ($date, $stats) = @_;

        my ($year, $month, $day) = $date =~ /(\d{4})(\d{2})(\d{2})/;
        my $formatted_date = "$year-$month-$day";

        my $total_requests = ($stats->{count}{gemini} // 0) + ($stats->{count}{web} // 0);
        my $filtered       = $stats->{count}{filtered} // 0;
        my $gemini         = $stats->{count}{gemini}   // 0;
        my $web            = $stats->{count}{web}      // 0;
        my $ipv4           = $stats->{count}{IPv4}     // 0;
        my $ipv6           = $stats->{count}{IPv6}     // 0;

        return [ $formatted_date, $filtered, $gemini, $web, $ipv4, $ipv6, $total_requests ];
    }

    # Sub: build_feed_statistics_section
    # - Purpose: Table of feed unique counts by day over a period.
    # - Params: $dates (arrayref), $merged (hashref).
    # - Return: gemtext string.
    sub build_feed_statistics_section {
        my ($dates, $merged) = @_;

        my $content = "### Feed Statistics Evolution\n\n```\n";

        my @feed_rows;
        for my $date (reverse @$dates) {
            my $stats = $merged->{$date};
            next unless $stats->{feed_ips};

            push @feed_rows, build_feed_statistics_row($date, $stats);
        }

        $content .= format_table([ 'Date', 'Gem Feed', 'Gem Atom', 'Web Feed', 'Web Atom', 'Total' ], \@feed_rows);
        $content .= "\n```\n\n";

        return $content;
    }

    # Sub: build_feed_statistics_row
    # - Purpose: Build one row of feed unique counts for a date.
    # - Params: $date (YYYYMMDD), $stats (hashref).
    # - Return: arrayref of cell strings.
    sub build_feed_statistics_row {
        my ($date, $stats) = @_;

        my ($year, $month, $day) = $date =~ /(\d{4})(\d{2})(\d{2})/;
        my $formatted_date = "$year-$month-$day";

        return [
            $formatted_date,
            $stats->{feed_ips}{'Gemini Gemfeed'} // 0,
            $stats->{feed_ips}{'Gemini Atom'}    // 0,
            $stats->{feed_ips}{'Web Gemfeed'}    // 0,
            $stats->{feed_ips}{'Web Atom'}       // 0,
            $stats->{feed_ips}{'Total'}          // 0
        ];
    }

    # Sub: aggregate_hosts_and_urls
    # - Purpose: Sum hosts and URLs across multiple days.
    # - Params: $dates (arrayref), $merged (hashref).
    # - Return: (\%all_hosts, \%all_urls).
    sub aggregate_hosts_and_urls {
        my ($dates, $merged) = @_;

        my %all_hosts;
        my %all_urls;

        for my $date (@$dates) {
            my $stats = $merged->{$date};
            next unless $stats->{page_ips};

            # Aggregate hosts
            while (my ($host, $count) = each %{ $stats->{page_ips}{hosts} }) {
                $all_hosts{$host} //= 0;
                $all_hosts{$host} += $count;
            }

            # Aggregate URLs
            while (my ($url, $count) = each %{ $stats->{page_ips}{urls} }) {
                $all_urls{$url} //= 0;
                $all_urls{$url} += $count;
            }
        }

        return (\%all_hosts, \%all_urls);
    }

    sub build_top_hosts_section {
        my ($all_hosts, $days) = @_;
        $days //= 30;

        return generate_top_n_table(
            title   => "Top 50 Hosts (${days}-Day Total)",
            data    => $all_hosts,
            headers => [ 'Host', 'Visitors' ],
        );
    }

    # Sub: build_top_urls_section
    # - Purpose: Build Top-50 URLs table for the aggregated period (with truncation).
    # - Params: $all_urls (hashref), $days (int default 30).
    # - Return: gemtext string.
    sub build_top_urls_section {
        my ($all_urls, $days) = @_;
        $days //= 30;

        return generate_top_n_table(
            title   => "Top 50 URLs (${days}-Day Total)",
            data    => $all_urls,
            headers => [ 'URL', 'Visitors' ],
            is_url  => 1,
        );
    }

    # Sub: build_summary_links
    # - Purpose: Links to other summary reports (30-day when not already on it).
    # - Params: $current_days (int), $report_date (YYYYMMDD).
    # - Return: gemtext string.
    sub build_summary_links {
        my ($current_days, $report_date) = @_;

        my $content = '';

        # Only add link to 30-day summary when not on the 30-day report itself
        if ($current_days != 30) {
            $content .= "## Other Summary Reports\n\n";
            $content .= "=> ./30day_summary_$report_date.gmi 30-Day Summary Report\n\n";
        }

        return $content;
    }

    # Sub: build_top3_urls_last_n_days_per_day
    # - Purpose: For each of last N days, render the top URLs table.
    # - Params: $stats_dir (str), $days (int default 30), $merged (hashref).
    # - Return: gemtext string.
    sub build_top3_urls_last_n_days_per_day {
        my ($stats_dir, $days, $merged) = @_;
        $days //= 30;
        my $content = "## Top 5 URLs Per Day (Last ${days} Days)\n\n";

        my @all   = DateHelper::last_month_dates();
        my @dates = @all;
        @dates = @all[ 0 .. $days - 1 ] if @all > $days;
        return $content . "(no data)\n\n" unless @dates;

        for my $date (@dates) {

            # Prefer in-memory merged stats if available; otherwise merge from disk
            my $stats = $merged->{$date};
            if (!$stats || !($stats->{page_ips} && $stats->{page_ips}{urls})) {
                $stats = Foostats::Merger::merge_for_date($stats_dir, $date);
            }
            next unless $stats && $stats->{page_ips} && $stats->{page_ips}{urls};

            my ($y, $m, $d) = $date =~ /(\d{4})(\d{2})(\d{2})/;
            $content .= "### $y-$m-$d\n\n";

            my $urls   = $stats->{page_ips}{urls};
            my @sorted = sort { ($urls->{$b} // 0) <=> ($urls->{$a} // 0) } keys %$urls;
            next unless @sorted;
            my $limit = @sorted < 5 ? @sorted : 5;
            @sorted = @sorted[ 0 .. $limit - 1 ];

            my @rows;
            for my $u (@sorted) {
                $u =~ s/\.gmi$/\.html/;
                push @rows, [ $u, $urls->{$u} // 0 ];
            }
            truncate_urls_for_table(\@rows, 'Visitors');
            $content .= "```\n" . format_table([ 'URL', 'Visitors' ], \@rows) . "\n```\n\n";
        }

        return $content;
    }

    # Sub: generate_index
    # - Purpose: Create index.gmi/.html using the latest 30-day summary as content.
    # - Params: $output_dir (str), $html_output_dir (str).
    # - Return: undef.
    sub generate_index {
        my ($output_dir, $html_output_dir) = @_;

        # Find latest 30-day summary
        opendir(my $dh, $output_dir) or die "Cannot open directory $output_dir: $!";
        my @gmi_files = grep { /\.gmi$/ && $_ ne 'index.gmi' } readdir($dh);
        closedir($dh);

        my @summaries_30day = sort { $b cmp $a } grep { /^30day_summary_/ } @gmi_files;
        my $latest_30       = $summaries_30day[0];

        my $index_path = "$output_dir/index.gmi";
        mkdir $html_output_dir unless -d $html_output_dir;
        my $html_path = "$html_output_dir/index.html";

        if ($latest_30) {

            # Read 30-day summary content and use it as index
            my $summary_path = "$output_dir/$latest_30";
            open my $sfh, '<', $summary_path or die "$summary_path: $!";
            local $/ = undef;
            my $content = <$sfh>;
            close $sfh;

            say "Writing index to $index_path (using $latest_30)";
            FileHelper::write($index_path, $content);

            # HTML: use existing 30-day summary HTML if present, else convert
            (my $latest_html = $latest_30) =~ s/\.gmi$/.html/;
            my $summary_html_path = "$html_output_dir/$latest_html";
            if (-e $summary_html_path) {
                open my $hh, '<', $summary_html_path or die "$summary_html_path: $!";
                local $/ = undef;
                my $html_page = <$hh>;
                close $hh;
                say "Writing HTML index to $html_path (copy of $latest_html)";
                FileHelper::write($html_path, $html_page);
            }
            else {
                my $html_content = gemtext_to_html($content);
                my $html_page    = generate_html_page("30-Day Summary Report", $html_content);
                say "Writing HTML index to $html_path (from gemtext)";
                FileHelper::write($html_path, $html_page);
            }
            return;
        }

        # Fallback: minimal index if no 30-day summary found
        my $fallback = "# Foostats Reports Index\n\n30-day summary not found.\n";
        say "Writing fallback index to $index_path";
        FileHelper::write($index_path, $fallback);

        my $html_content = gemtext_to_html($fallback);
        my $html_page    = generate_html_page("Foostats Reports Index", $html_content);
        say "Writing fallback HTML index to $html_path";
        FileHelper::write($html_path, $html_page);
    }
}

package main;

# Package: main — CLI entrypoint and orchestration
# - Purpose: Parse options and invoke parse/replicate/report flows.
use Getopt::Long;
use Sys::Hostname;

# Sub: usage
# - Purpose: Print usage and exit 0.
# - Params: none.
# - Return: never (exits).
sub usage {
    print <<~"USAGE";
        Usage: $0 [options]

        Options:
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
        USAGE
    exit 0;
}

# Sub: parse_logs
# - Purpose: Parse logs and persist aggregated stats files under $stats_dir.
# - Params: $stats_dir (str), $odds_file (str), $odds_log (str).
# - Return: undef.
sub parse_logs ($stats_dir, $odds_file, $odds_log) {
    my $out = Foostats::FileOutputter->new(stats_dir => $stats_dir);

    $out->{stats} = Foostats::Logreader::parse_logs(
        $out->last_processed_date('web'),
        $out->last_processed_date('gemini'),
        $odds_file, $odds_log
    );

    $out->write;
}

# Sub: foostats_main
# - Purpose: Option parsing and execution of requested actions.
# - Params: none (reads @ARGV).
# - Return: exit code via program termination.
sub foostats_main {
    my ($parse_logs, $replicate, $report, $all, $help, $version);

    # With default values
    my $stats_dir = '/var/www/htdocs/buetow.org/self/foostats';
    my $odds_file = $stats_dir . '/fooodds.txt';
    my $odds_log  = '/var/log/fooodds';
    my $output_dir;         # Will default to $stats_dir/gemtext if not specified
    my $html_output_dir;    # Will default to /var/www/htdocs/gemtexter/stats.foo.zone if not specified
    my $partner_node =
        hostname eq 'fishfinger.buetow.org'
        ? 'blowfish.buetow.org'
        : 'fishfinger.buetow.org';

    GetOptions
        'parse-logs!'       => \$parse_logs,
        'filter-log=s'      => \$odds_log,
        'odds-file=s'       => \$odds_file,
        'replicate!'        => \$replicate,
        'report!'           => \$report,
        'all!'              => \$all,
        'stats-dir=s'       => \$stats_dir,
        'output-dir=s'      => \$output_dir,
        'html-output-dir=s' => \$html_output_dir,
        'partner-node=s'    => \$partner_node,
        'version'           => \$version,
        'help|?'            => \$help;

    if ($version) {
        print "foostats " . VERSION . "\n";
        exit 0;
    }

    usage() if $help;

    parse_logs($stats_dir, $odds_file, $odds_log)              if $parse_logs or $all;
    Foostats::Replicator::replicate($stats_dir, $partner_node) if $replicate  or $all;

    # Set default output directories if not specified
    $output_dir      //= '/var/gemini/stats.foo.zone';
    $html_output_dir //= '/var/www/htdocs/gemtexter/stats.foo.zone';

    Foostats::Reporter::report($stats_dir, $output_dir, $html_output_dir, Foostats::Merger::merge($stats_dir))
        if $report
        or $all;
}

# Only run main flow when executed as a script, not when required (e.g., tests)
foostats_main() unless caller;
