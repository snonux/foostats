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

use constant VERSION => 'v0.1.0';

# TODO: Blog post about this script and the new Perl features used.
# TODO NEXT:
# * Write out a nice output from each merged file, also merge if multiple hosts results
# * Fix bug with .gmi.*.gmi in the log parser
# * Nicely formatted .txt output by stats by count by date
# * Print out all UAs, to add new excludes/blocked IPs

package FileHelper {
    use JSON;

    sub write ( $path, $content ) {
        open my $fh, '>', "$path.tmp"
          or die "\nCannot open file: $!";
        print $fh $content;
        close $fh;

        rename
          "$path.tmp",
          $path;
    }

    sub write_json_gz ( $path, $data ) {
        my $json = encode_json $data;

        say "Writing $path";
        open my $fd, '>:gzip', "$path.tmp"
          or die "$path.tmp: $!";
        print $fd $json;
        close $fd;

        rename "$path.tmp", $path
          or die "$path.tmp: $!";
    }

    sub read_json_gz ($path) {
        say "Reading $path";
        open my $fd, '<:gzip', $path
          or die "$path: $!";
        my $json = decode_json <$fd>;
        close $fd;
        return $json;
    }

    sub read_lines ($path) {
        my @lines;
        open( my $fh, '<', $path )
          or die "$path: $!";
        chomp( @lines = <$fh> );
        close($fh);
        return @lines;
    }
}

package DateHelper {
    use Time::Piece;

    sub last_month_dates () {
        my $today = localtime;
        my @dates;

        for my $days_ago ( 0 .. 30 ) {
            my $date = $today - ( $days_ago * 24 * 60 * 60 );
            push
              @dates,
              $date->strftime('%Y%m%d');
        }

        return @dates;
    }

    sub last_n_months_day_dates ($months) {
        my $today = localtime;
        my $start_year  = $today->year;
        my $start_month = $today->mon - $months;
        while ($start_month <= 0) { $start_month += 12; $start_year--; }

        my $start = Time::Piece->strptime(sprintf('%04d-%02d-01', $start_year, $start_month), '%Y-%m-%d');
        my @dates;
        my $t = $start;
        while ($t <= $today) {
            push @dates, $t->strftime('%Y%m%d');
            $t += 24 * 60 * 60; # one day
        }
        return @dates;
    }
}

package Foostats::Logreader {
    use Digest::SHA3 'sha3_512_base64';
    use File::stat;
    use PerlIO::gzip;
    use Time::Piece;
    use String::Util qw(contains startswith endswith);

    # Make log locations configurable (env overrides) to enable testing.
    sub gemini_logs_glob { $ENV{FOOSTATS_GEMINI_LOGS_GLOB} // '/var/log/daemon*' }
    sub web_logs_glob    { $ENV{FOOSTATS_WEB_LOGS_GLOB}    // '/var/www/logs/access.log*' }

    sub anonymize_ip ($ip) {
        my $ip_proto =
          contains( $ip, ':' )
          ? 'IPv6'
          : 'IPv4';
        my $ip_hash = sha3_512_base64 $ip;
        return ( $ip_hash, $ip_proto );
    }

    sub read_lines ( $glob, $cb ) {
        my sub year ($path) {
            localtime( ( stat $path )->mtime )->strftime('%Y');
        }

        my sub open_file ($path) {
            my $flag =
              $path =~ /\.gz$/
              ? '<:gzip'
              : '<';
            open my $fd, $flag, $path
              or die "$path: $!";
            return $fd;
        }

        my $last = false;

        say 'File path glob matches: ' . join( ' ', glob $glob );

      LAST:
        for my $path ( sort { -M $a <=> -M $b } glob $glob ) {
            say "Processing $path";

            my $file = open_file $path;
            my $year = year $file;

            while (<$file>) {
                next
                  if contains( $_, 'logfile turned over' );

                # last == true means: After this file, don't process more
                $last = true
                  unless defined $cb->( $year, split / +/ );
            }

            say "Closing $path (last:$last)";
            close $file;
            last LAST
              if $last;
        }
    }

    sub parse_web_logs ( $last_processed_date, $cb ) {
        my sub parse_date ($date) {
            my $t = Time::Piece->strptime( $date, '[%d/%b/%Y:%H:%M:%S' );
            return ( $t->strftime('%Y%m%d'), $t->strftime('%H%M%S') );
        }

        my sub parse_web_line (@line) {
            my ( $date, $time ) = parse_date $line [4];
            return undef
              if $date < $last_processed_date;

            # X-Forwarded-For?
            my $ip =
                $line[-2] eq '-'
              ? $line[1]
              : $line[-2];
            my ( $ip_hash, $ip_proto ) = anonymize_ip $ip;

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

        read_lines web_logs_glob(), sub ( $year, @line ) {
            $cb->( parse_web_line @line );
        };
    }

    sub parse_gemini_logs ( $last_processed_date, $cb ) {
        my sub parse_date ( $year, @line ) {
            my $timestr = "$line[0] $line[1]";
            return Time::Piece->strptime( $timestr, '%b %d' )
              ->strftime("$year%m%d");
        }

        my sub parse_vger_line ( $year, @line ) {
            my $full_path = $line[5];
            $full_path =~ s/"//g;
            my ( $proto, undef, $host, $uri_path ) =
              split '/',
              $full_path,
              4;
            $uri_path = ''
              unless defined $uri_path;

            return {
                proto    => 'gemini',
                host     => $host,
                uri_path => "/$uri_path",
                status   => $line[6],
                date     => int( parse_date( $year, @line ) ),
                time     => $line[2],
            };
        }

        my sub parse_relayd_line ( $year, @line ) {
            my $date = int( parse_date( $year, @line ) );

            my ( $ip_hash, $ip_proto ) = anonymize_ip $line [12];
            return {
                ip_hash  => $ip_hash,
                ip_proto => $ip_proto,
                date     => $date,
                time     => $line[2],
            };
        }

      # Expect one vger and one relayd log line per event! So collect
      # both events (one from one log line each) and then merge the result hash!
        my ( $vger, $relayd );
        read_lines gemini_logs_glob(), sub ( $year, @line ) {
            if ( $line[4] eq 'vger:' ) {
                $vger = parse_vger_line $year, @line;
            }
            elsif ( $line[5] eq 'relay'
                and startswith( $line[6], 'gemini' ) )
            {
                $relayd = parse_relayd_line $year, @line;
                return undef
                  if $relayd->{date} < $last_processed_date;
            }

            if (    defined $vger
                and defined $relayd
                and $vger->{time} eq $relayd->{time} )
            {
                $cb->( { %$vger, %$relayd } );
                $vger = $relayd = undef;
            }

            true;
        };
    }

    sub parse_logs ( $last_web_date, $last_gemini_date, $odds_file, $odds_log )
    {
        my $agg = Foostats::Aggregator->new( $odds_file, $odds_log );

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

# TODO: Write filter summary at the end of the filter log.
package Foostats::Filter {
    use String::Util qw(contains startswith endswith);

    sub new ( $class, $odds_file, $log_path ) {
        say "Logging filter to $log_path";
        my @odds = FileHelper::read_lines($odds_file);

        bless {
            odds     => \@odds,
            log_path => $log_path
          },
          $class;
    }

    sub ok ( $self, $event ) {
        state %blocked = ();
        return false
          if exists $blocked{ $event->{ip_hash} };

        if (   $self->odd($event)
            or $self->excessive($event) )
        {
            ( $blocked{ $event->{ip_hash} } //= 0 )++;
            return false;
        }
        else {
            return true;
        }
    }

    sub odd ( $self, $event ) {
        \my $uri_path = \$event->{uri_path};

        for ( $self->{odds}->@* ) {
            next if !defined $_ || $_ eq '' || /^\s*#/;
            next
              unless contains( $uri_path, $_ );

            $self->log( 'WARN', $uri_path,
                "contains $_ and is odd and will therefore be blocked!" );
            return true;
        }

        $self->log( 'OK', $uri_path, "appears fine..." );
        return false;
    }

    sub log ( $self, $severity, $subject, $message ) {
        state %dedup;

        # Don't log if path was already logged
        return
          if exists $dedup{$subject};
        $dedup{$subject} = 1;

        open( my $fh, '>>', $self->{log_path} )
          or die $self->{log_path} . ": $!";
        print $fh "$severity: $subject $message\n";
        close($fh);
    }

    sub excessive ( $self, $event ) {
        \my $time    = \$event->{time};
        \my $ip_hash = \$event->{ip_hash};

        state $last_time = $time;    # Time with second: 'HH:MM:SS'
        state %count     = ();       # IPs accessing within the same second!

        if ( $last_time ne $time ) {
            $last_time = $time;
            %count     = ();
            return false;
        }

        # IP requested site more than once within the same second!?
        if ( 1 < ++( $count{$ip_hash} //= 0 ) ) {
            $self->log( 'WARN', $ip_hash,
                "blocked due to excessive requesting..." );
            return true;
        }

        return false;
    }
}

package Foostats::Aggregator {
    use String::Util qw(contains startswith endswith);

    use constant {
        ATOM_FEED_URI => '/gemfeed/atom.xml',
        GEMFEED_URI   => '/gemfeed/index.gmi',
        GEMFEED_URI_2 => '/gemfeed/',
    };

    sub new ( $class, $odds_file, $odds_log ) {
        bless {
            filter => Foostats::Filter->new( $odds_file, $odds_log ),
            stats  => {}
          },
          $class;
    }

    sub add ( $self, $event ) {
        return undef
          unless defined $event;

        my $date     = $event->{date};
        my $date_key = $event->{proto} . "_$date";

        # Stats data model per protocol+day (key: "proto_YYYYMMDD"):
        # - count: per-proto request count, per IP version, and filtered count
        # - feed_ips: unique IPs per feed type (atom_feed, gemfeed)
        # - page_ips: unique IPs per host and per URL
        $self->{stats}{$date_key} //= {
            count => {
                filtered => 0,
            },
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
        unless ( $self->{filter}->ok($event) ) {
            $s->{count}{filtered}++;
            return $event;
        }

        $self->add_count( $s, $event );
        $self->add_page_ips( $s, $event )
          unless $self->add_feed_ips( $s, $event );

        return $event;
    }

    sub add_count ( $self, $stats, $event ) {
        \my $c = \$stats->{count};
        \my $e = \$event;

        ( $c->{ $e->{proto} }    //= 0 )++;
        ( $c->{ $e->{ip_proto} } //= 0 )++;
    }

    sub add_feed_ips ( $self, $stats, $event ) {
        \my $f = \$stats->{feed_ips};
        \my $e = \$event;

        # Atom feed (exact path match, allow optional query string)
        if ( $e->{uri_path} =~ m{^/gemfeed/atom\.xml(?:[?#].*)?$} ) {
            ( $f->{atom_feed}->{ $e->{ip_hash} } //= 0 )++;
            return 1;
        }

        # Gemfeed index: '/gemfeed/' or '/gemfeed/index.gmi' (optionally with query)
        if ( $e->{uri_path} =~ m{^/gemfeed/(?:index\.gmi)?(?:[?#].*)?$} ) {
            ( $f->{gemfeed}->{ $e->{ip_hash} } //= 0 )++;
            return 1;
        }

        return 0;
    }

    sub add_page_ips ( $self, $stats, $event ) {
        \my $e = \$event;
        \my $p = \$stats->{page_ips};

        return
          if !endswith( $e->{uri_path}, '.html' )
          && !endswith( $e->{uri_path}, '.gmi' );

        ( $p->{hosts}->{ $e->{host} }->{ $e->{ip_hash} } //= 0 )++;
        ( $p->{urls}->{ $e->{host} . $e->{uri_path} }->{ $e->{ip_hash} } //=
              0 )++;
    }
}

package Foostats::FileOutputter {
    use JSON;
    use Sys::Hostname;
    use PerlIO::gzip;

    sub new ( $class, %args ) {
        my $self = bless \%args, $class;
        mkdir $self->{stats_dir}
          or die $self->{stats_dir} . ": $!"
          unless -d $self->{stats_dir};

        return $self;
    }

    sub last_processed_date ( $self, $proto ) {
        my $hostname = hostname();
        my @processed =
          glob $self->{stats_dir} . "/${proto}_????????.$hostname.json.gz";
        my ($date) =
          @processed
          ? ( $processed[-1] =~ /_(\d{8})\.$hostname\.json.gz/ )
          : 0;

        return int($date);
    }

    sub write ($self) {
        $self->for_dates(
            sub ( $self, $date_key, $stats ) {
                my $hostname = hostname();
                my $path =
                  $self->{stats_dir} . "/${date_key}.$hostname.json.gz";
                FileHelper::write_json_gz
                  $path,
                  $stats;
            }
        );
    }

    sub for_dates ( $self, $cb ) {
        $cb->( $self, $_, $self->{stats}{$_} ) for sort
          keys $self->{stats}->%*;
    }
}

package Foostats::Replicator {
    use JSON;
    use File::Basename;
    use LWP::UserAgent;
    use String::Util qw(endswith);

    sub replicate ( $stats_dir, $partner_node ) {
        say "Replicating from $partner_node";

        for my $proto (qw(gemini web)) {
            my $count = 0;

            for my $date (DateHelper::last_month_dates) {
                my $file_base = "${proto}_${date}";
                my $dest_path = "${file_base}.$partner_node.json.gz";

                replicate_file(
                    "https://$partner_node/foostats/$dest_path",
                    "$stats_dir/$dest_path",
                    $count++
                      <
                      3
                    ,    # Always replicate the newest 3 files.
                );
            }
        }
    }

    sub replicate_file ( $remote_url, $dest_path, $force ) {

        # $dest_path already exists, not replicating it
        return
          if !$force
          && -f $dest_path;

        say "Replicating $remote_url to $dest_path (force:$force)... ";
        my $response = LWP::UserAgent->new->get($remote_url);
        unless ( $response->is_success ) {
            say "\nFailed to fetch the file: " . $response->status_line;
            return;
        }

        FileHelper::write
          $dest_path,
          $response->decoded_content;
        say 'done';
    }
}

package Foostats::Merger {
    # Removed Data::Dumper (debug-only) per review.

    sub merge ($stats_dir) {
        my %merge;
        $merge{$_} = merge_for_date( $stats_dir, $_ )
          for DateHelper::last_month_dates;
        return %merge;
    }

    sub merge_for_date ( $stats_dir, $date ) {
        printf
          "Merging for date %s\n",
          $date;

        my @stats = stats_for_date( $stats_dir, $date );
        return {
            feed_ips => feed_ips(@stats),
            count    => count(@stats),
            page_ips => page_ips(@stats),
        };
    }

    sub merge_ips ( $a, $b, $key_transform = undef ) {
        my sub merge ( $a, $b ) {
            while ( my ( $key, $val ) = each %$b ) {
                $a->{$key} //= 0;
                $a->{$key} += $val;
            }
        }

        my $is_num = qr/^\d+(\.\d+)?$/;

        while ( my ( $key, $val ) = each %$b ) {
            $key = $key_transform->($key)
              if defined $key_transform;

            if ( not exists $a->{$key} ) {
                $a->{$key} = $val;
            }
            elsif (ref( $a->{$key} ) eq 'HASH'
                && ref($val) eq 'HASH' )
            {
                merge( $a->{$key}, $val );
            }
            elsif ($a->{$key} =~ $is_num
                && $val =~ $is_num )
            {
                $a->{$key} += $val;
            }
            else {
                die
"Not merging tkey '%s' (ref:%s): '%s' (ref:%s) with '%s' (ref:%s)\n",
                  $key,
                  ref($key), $a->{$key},
                  ref( $a->{$key} ),
                  $val,
                  ref($val);
            }
        }
    }

    sub feed_ips (@stats) {
        my ( %gemini, %web );

        for my $stats (@stats) {
            my $merge =
              $stats->{proto} eq 'web'
              ? \%web
              : \%gemini;
            printf
              "Merging proto %s feed IPs\n",
              $stats->{proto};
            merge_ips( $merge, $stats->{feed_ips} );
        }

        my %total;
        merge_ips( \%total, $web{$_} )    for keys %web;
        merge_ips( \%total, $gemini{$_} ) for keys %gemini;

        my %merge = (
            'Total'          => scalar keys %total,
            'Gemini Gemfeed' => scalar keys $gemini{gemfeed}->%*,
            'Gemini Atom'    => scalar keys $gemini{atom_feed}->%*,
            'Web Gemfeed'    => scalar keys $web{gemfeed}->%*,
            'Web Atom'       => scalar keys $web{atom_feed}->%*,
        );

        return \%merge;
    }

    sub count (@stats) {
        my %merge;

        for my $stats (@stats) {
            while ( my ( $key, $val ) = each $stats->{count}->%* ) {
                $merge{$key} //= 0;
                $merge{$key} += $val;
            }
        }

        return \%merge;
    }

    sub page_ips (@stats) {
        my %merge = (
            urls  => {},
            hosts => {}
        );

        for my $key ( keys %merge ) {
            merge_ips(
                $merge{$key},
                $_->{page_ips}->{$key},
                sub ($key) {
                    $key =~ s/\.html$/.../;
                    $key =~ s/\.gmi$/.../;
                    $key;
                }
            ) for @stats;

            # Keep only uniq IP count
            $merge{$key}->{$_} = scalar keys $merge{$key}->{$_}->%*
              for keys $merge{$key}->%*;
        }

        return \%merge;
    }

    sub stats_for_date ( $stats_dir, $date ) {
        my @stats;

        for my $proto (qw(gemini web)) {
            for my $path (<$stats_dir/${proto}_${date}.*.json.gz>) {
                printf
                  "Reading %s\n",
                  $path;
                push
                  @stats,
                  FileHelper::read_json_gz($path);
                @{ $stats[-1] }{qw(proto path)} = ( $proto, $path );
            }
        }

        return @stats;
    }
}

package Foostats::Reporter {
    use Time::Piece;
    use HTML::Entities qw(encode_entities);

    sub truncate_url {
        my ( $url, $max_length ) = @_;
        $max_length //= 100;    # Default to 100 characters

        return $url if length($url) <= $max_length;

        # Calculate how many characters we need to remove
        my $ellipsis         = '...';
        my $ellipsis_length  = length($ellipsis);
        my $available_length = $max_length - $ellipsis_length;

        # Split available length between start and end, favoring the end
        my $keep_start = int( $available_length * 0.4 );     # 40% for start
        my $keep_end   = $available_length - $keep_start;    # 60% for end

        my $start = substr( $url, 0, $keep_start );
        my $end   = substr( $url, -$keep_end );

        return $start . $ellipsis . $end;
    }

    sub truncate_urls_for_table {
        my ( $url_rows, $count_column_header ) = @_;

        # Calculate the maximum width needed for the count column
        my $max_count_width = length($count_column_header);
        for my $row (@$url_rows) {
            my $count_width = length( $row->[1] );
            $max_count_width = $count_width if $count_width > $max_count_width;
        }

        # Row format: "| URL... | count |" with padding
        # Calculate: "| " (2) + URL + " | " (3) + count_with_padding + " |" (2)
        my $max_url_length = 100 - 7 - $max_count_width;
        $max_url_length = 70 if $max_url_length > 70; # Cap at reasonable length

        # Truncate URLs in place
        for my $row (@$url_rows) {
            $row->[0] = truncate_url( $row->[0], $max_url_length );
        }
    }

    sub format_table {
        my ( $headers, $rows ) = @_;

        my @widths;
        for my $col ( 0 .. $#{$headers} ) {
            my $max_width = length( $headers->[$col] );
            for my $row (@$rows) {
                my $len = length( $row->[$col] );
                $max_width = $len if $len > $max_width;
            }
            push @widths, $max_width;
        }

        my $header_line    = '|';
        my $separator_line = '|';
        for my $col ( 0 .. $#{$headers} ) {
            $header_line .=
              sprintf( " %-*s |", $widths[$col], $headers->[$col] );
            $separator_line .= '-' x ( $widths[$col] + 2 ) . '|';
        }

        my @table_lines;
        push @table_lines, $separator_line;    # Add top terminator
        push @table_lines, $header_line;
        push @table_lines, $separator_line;

        for my $row (@$rows) {
            my $row_line = '|';
            for my $col ( 0 .. $#{$row} ) {
                $row_line .= sprintf( " %-*s |", $widths[$col], $row->[$col] );
            }
            push @table_lines, $row_line;
        }

        push @table_lines, $separator_line;    # Add bottom terminator

        return join( "\n", @table_lines );
    }

    # Convert gemtext to HTML
    sub gemtext_to_html {
        my ($content) = @_;
        my $html = "";
        my $in_code_block = 0;
        my $in_list = 0;
        my @lines = split /\n/, $content;
        my @code_block_lines = ();
        
        for my $line (@lines) {
            if ($line =~ /^```/) {
                if ($in_code_block) {
                    # End code block - check if it's a table
                    if (is_ascii_table(\@code_block_lines)) {
                        $html .= convert_ascii_table_to_html(\@code_block_lines);
                    } else {
                        $html .= "<pre>\n";
                        for my $code_line (@code_block_lines) {
                            $html .= encode_entities($code_line) . "\n";
                        }
                        $html .= "</pre>\n";
                    }
                    @code_block_lines = ();
                    $in_code_block = 0;
                } else {
                    $in_code_block = 1;
                }
                next;
            }
            
            if ($in_code_block) {
                push @code_block_lines, $line;
                next;
            }
            
            # Skip 365-day summary section header in HTML output
            if ($line =~ /^## 365-Day Summary Reports\s*$/) {
                next;
            }

            # Check if we need to close a list
            if ($in_list && $line !~ /^\* /) {
                $html .= "</ul>\n";
                $in_list = 0;
            }
            
            # Headers
            if ($line =~ /^### (.*)/) {
                $html .= "<h3>" . encode_entities($1) . "</h3>\n";
            } elsif ($line =~ /^## (.*)/) {
                $html .= "<h2>" . encode_entities($1) . "</h2>\n";
            } elsif ($line =~ /^# (.*)/) {
                $html .= "<h1>" . encode_entities($1) . "</h1>\n";
            }
            # Links
            elsif ($line =~ /^=> (\S+)\s+(.*)/) {
                my ($url, $text) = ($1, $2);
                # Drop 365-day summary links from HTML output
                if ($url =~ /(?:^|[\/.])365day_summary_\d{8}\.gmi$/) {
                    next;
                }
                # Convert .gmi links to .html
                $url =~ s/\.gmi$/\.html/;
                $html .= "<p><a href=\"" . encode_entities($url) . "\">" . encode_entities($text) . "</a></p>\n";
            }
            # Bullet points
            elsif ($line =~ /^\* (.*)/) {
                if (!$in_list) {
                    $html .= "<ul>\n";
                    $in_list = 1;
                }
                $html .= "<li>" . encode_entities($1) . "</li>\n";
            }
            # Empty line - skip to avoid excessive spacing
            elsif ($line =~ /^\s*$/) {
                # Skip empty lines for more compact output
            }
            # Regular text
            else {
                $html .= "<p>" . encode_entities($line) . "</p>\n";
            }
        }
        
        # Close list if still open
        if ($in_list) {
            $html .= "</ul>\n";
        }
        
        return $html;
    }
    
    # Check if the lines form an ASCII table
    sub is_ascii_table {
        my ($lines) = @_;
        return 0 if @$lines < 3;  # Need at least header, separator, and one data row
        
        # Check for separator lines with dashes and pipes
        for my $line (@$lines) {
            return 1 if $line =~ /^\|?[\s\-]+\|/;
        }
        return 0;
    }
    
    # Convert ASCII table to HTML table
    sub convert_ascii_table_to_html {
        my ($lines) = @_;
        my $html = "<table>\n";
        my $row_count = 0;
        
        for my $line (@$lines) {
            # Skip separator lines
            next if $line =~ /^\|?[\s\-]+\|/ && $line =~ /\-/;
            
            # Parse table row
            my @cells = split /\s*\|\s*/, $line;
            @cells = grep { length($_) > 0 } @cells;  # Remove empty cells
            
            if (@cells) {
                $html .= "<tr>\n";
                # First row is header
                my $tag = ($row_count == 0) ? "th" : "td";
                for my $cell (@cells) {
                    $html .= "  <$tag>" . encode_entities(trim($cell)) . "</$tag>\n";
                }
                $html .= "</tr>\n";
                $row_count++;
            }
        }
        
        $html .= "</table>\n";
        return $html;
    }
    
    # Trim whitespace from string
    sub trim {
        my ($str) = @_;
        $str =~ s/^\s+//;
        $str =~ s/\s+$//;
        return $str;
    }
    
    # Use HTML::Entities::encode_entities imported above
    
    # Generate HTML wrapper
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

    sub report {
        my ( $stats_dir, $output_dir, $html_output_dir, %merged ) = @_;
        for my $date ( sort { $b cmp $a } keys %merged ) {
            my $stats = $merged{$date};
            next unless $stats->{count};

            my ( $year, $month, $day ) = $date =~ /(\d{4})(\d{2})(\d{2})/;

            # Check if .gmi file exists and its age based on date in filename
            my $report_path = "$output_dir/$date.gmi";
            my $html_report_path = "$output_dir/$date.html";

            # Calculate age of the data based on date in filename
            my $today     = Time::Piece->new();
            my $file_date = Time::Piece->strptime( $date, '%Y%m%d' );
            my $age_days  = ( $today - $file_date ) / ( 24 * 60 * 60 );

            if ( -e $report_path && -e $html_report_path ) {

                # Files exist
                if ( $age_days <= 3 ) {

                    # Data is recent (within 3 days), regenerate it
                    say
"Regenerating daily report for $year-$month-$day (data age: "
                      . sprintf( "%.1f", $age_days )
                      . " days)";
                }
                else {
                    # Data is old (older than 3 days), skip if files exist
                    say
"Skipping daily report for $year-$month-$day (files exist, data age: "
                      . sprintf( "%.1f", $age_days )
                      . " days)";
                    next;
                }
            }
            else {
                # File doesn't exist, generate it
                say
"Generating new daily report for $year-$month-$day (file doesn't exist, data age: "
                  . sprintf( "%.1f", $age_days )
                  . " days)";
            }

            my $report_content = "";

            $report_content .= "## Stats for $year-$month-$day\n\n";

            # Feed counts first
            $report_content .= "### Feed Statistics\n\n";
            my @feed_rows;
            push @feed_rows, [ 'Total', $stats->{feed_ips}{'Total'} // 0 ];
            push @feed_rows,
              [ 'Gemini Gemfeed', $stats->{feed_ips}{'Gemini Gemfeed'} // 0 ];
            push @feed_rows,
              [ 'Gemini Atom', $stats->{feed_ips}{'Gemini Atom'} // 0 ];
            push @feed_rows,
              [ 'Web Gemfeed', $stats->{feed_ips}{'Web Gemfeed'} // 0 ];
            push @feed_rows,
              [ 'Web Atom', $stats->{feed_ips}{'Web Atom'} // 0 ];
            $report_content .= "```\n";
            $report_content .=
              format_table( [ 'Feed Type', 'Count' ], \@feed_rows );
            $report_content .= "\n```\n\n";
            # Top 50 URLs next
            $report_content .= "### Top 50 URLs\n\n";
            my @url_rows;
            my $urls = $stats->{page_ips}{urls};
            my @sorted_urls =
              sort { ( $urls->{$b} // 0 ) <=> ( $urls->{$a} // 0 ) }
              keys %$urls;
            my $truncated   = @sorted_urls > 50;
            @sorted_urls = @sorted_urls[ 0 .. 49 ] if $truncated;

            for my $url (@sorted_urls) {
                push @url_rows, [ $url, $urls->{$url} // 0 ];
            }

            # Truncate URLs to fit within 100-character rows
            truncate_urls_for_table( \@url_rows, 'Unique Visitors' );
            $report_content .= "```\n";
            $report_content .=
              format_table( [ 'URL', 'Unique Visitors' ], \@url_rows );
            $report_content .= "\n```\n";
            if ($truncated) {
                $report_content .= "\n... and more (truncated to 50 entries).\n";
            }
            $report_content .= "\n";

            # Other tables afterwards: Hosts, then Summary
            $report_content .= "### Page Statistics (by Host)\n\n";
            my @host_rows;
            my $hosts = $stats->{page_ips}{hosts};
            my @sorted_hosts =
              sort { ( $hosts->{$b} // 0 ) <=> ( $hosts->{$a} // 0 ) }
              keys %$hosts;

            $truncated = @sorted_hosts > 50;
            @sorted_hosts = @sorted_hosts[ 0 .. 49 ] if $truncated;

            for my $host (@sorted_hosts) {
                push @host_rows, [ $host, $hosts->{$host} // 0 ];
            }
            $report_content .= "```\n";
            $report_content .=
              format_table( [ 'Host', 'Unique Visitors' ], \@host_rows );
            $report_content .= "\n```\n";
            if ($truncated) {
                $report_content .= "\n... and more (truncated to 50 entries).\n";
            }
            $report_content .= "\n";

            # Summary last
            $report_content .= "### Summary\n\n";
            my $total_requests =
              ( $stats->{count}{gemini} // 0 ) + ( $stats->{count}{web} // 0 );
            $report_content .= "* Total requests: $total_requests\n";
            $report_content .=
              "* Filtered requests: " . ( $stats->{count}{filtered} // 0 ) . "\n";
            $report_content .=
              "* Gemini requests: " . ( $stats->{count}{gemini} // 0 ) . "\n";
            $report_content .=
              "* Web requests: " . ( $stats->{count}{web} // 0 ) . "\n";
            $report_content .=
              "* IPv4 requests: " . ( $stats->{count}{IPv4} // 0 ) . "\n";
            $report_content .=
              "* IPv6 requests: " . ( $stats->{count}{IPv6} // 0 ) . "\n\n";

            # Add links to summary reports (only monthly)
            $report_content .= "## Related Reports\n\n";
            my $now           = localtime;
            my $current_date = $now->strftime('%Y%m%d');
            $report_content .= "=> ./30day_summary_$current_date.gmi 30-Day Summary Report\n\n";

            # Ensure output directory exists
            mkdir $output_dir unless -d $output_dir;

            # $report_path already defined above
            say "Writing report to $report_path";
            FileHelper::write( $report_path, $report_content );
            
            # Also write HTML version
            mkdir $html_output_dir unless -d $html_output_dir;
            my $html_path = "$html_output_dir/$date.html";
            my $html_content = gemtext_to_html($report_content);
            my $html_page = generate_html_page("Stats for $year-$month-$day", $html_content);
            say "Writing HTML report to $html_path";
            FileHelper::write( $html_path, $html_page );
        }

        # Generate summary reports
        generate_summary_report( 30, $stats_dir, $output_dir, $html_output_dir, %merged );
        
        # Generate index.gmi and index.html
        generate_index( $output_dir, $html_output_dir );
    }

    sub generate_summary_report {
        my ( $days, $stats_dir, $output_dir, $html_output_dir, %merged ) = @_;

        # Get the last N days of dates
        my @dates = sort { $b cmp $a } keys %merged;
        my $max_index = $days - 1;
        @dates = @dates[ 0 .. $max_index ] if @dates > $days;

        my $today       = localtime;
        my $report_date = $today->strftime('%Y%m%d');

        # Build report content
        my $report_content = build_report_header($today, $days);
        # Order: feed counts -> Top URLs -> daily top 3 for last 30 days -> other tables
        $report_content .= build_feed_statistics_section( \@dates, \%merged );

        # Aggregate and add top lists
        my ( $all_hosts, $all_urls ) =
          aggregate_hosts_and_urls( \@dates, \%merged );
        $report_content .= build_top_urls_section($all_urls, $days);
        $report_content .= build_top3_urls_last_n_days_per_day($stats_dir, 30, \%merged);
        $report_content .= build_top_hosts_section($all_hosts, $days);
        $report_content .= build_daily_summary_section( \@dates, \%merged );

        # Add links to other summary reports
        $report_content .= build_summary_links($days, $report_date);

        # Ensure output directory exists and write the summary report
        mkdir $output_dir unless -d $output_dir;

        my $report_path = "$output_dir/${days}day_summary_$report_date.gmi";
        say "Writing $days-day summary report to $report_path";
        FileHelper::write( $report_path, $report_content );
        
        # Also write HTML version, except for 365-day summaries (HTML suppressed)
        if ($days != 365) {
            mkdir $html_output_dir unless -d $html_output_dir;
            my $html_path = "$html_output_dir/${days}day_summary_$report_date.html";
            my $html_content = gemtext_to_html($report_content);
            my $html_page = generate_html_page("$days-Day Summary Report", $html_content);
            say "Writing HTML $days-day summary report to $html_path";
            FileHelper::write( $html_path, $html_page );
        } else {
            say "Skipping HTML generation for 365-day summary (Gemtext only)";
        }
    }

    sub build_report_header {
        my ($today, $days) = @_;
        $days //= 30;  # Default to 30 days for backward compatibility

        my $content = "# $days-Day Summary Report\n\n";
        $content .= "Generated on " . $today->strftime('%Y-%m-%d') . "\n\n";
        return $content;
    }

    sub build_daily_summary_section {
        my ( $dates, $merged ) = @_;

        my $content = "## Daily Summary Evolution (Last 30 Days)\n\n";
        $content .= "### Total Requests by Day\n\n```\n";

        my @summary_rows;
        for my $date ( reverse @$dates ) {
            my $stats = $merged->{$date};
            next unless $stats->{count};

            push @summary_rows, build_daily_summary_row( $date, $stats );
        }

        $content .= format_table(
            [ 'Date', 'Filtered', 'Gemini', 'Web', 'IPv4', 'IPv6', 'Total' ],
            \@summary_rows );
        $content .= "\n```\n\n";

        return $content;
    }

    sub build_daily_summary_row {
        my ( $date, $stats ) = @_;

        my ( $year, $month, $day ) = $date =~ /(\d{4})(\d{2})(\d{2})/;
        my $formatted_date = "$year-$month-$day";

        my $total_requests =
          ( $stats->{count}{gemini} // 0 ) + ( $stats->{count}{web} // 0 );
        my $filtered = $stats->{count}{filtered} // 0;
        my $gemini   = $stats->{count}{gemini}   // 0;
        my $web      = $stats->{count}{web}      // 0;
        my $ipv4     = $stats->{count}{IPv4}     // 0;
        my $ipv6     = $stats->{count}{IPv6}     // 0;

        return [
            $formatted_date, $filtered,
            $gemini,         $web,            $ipv4,
            $ipv6,           $total_requests
        ];
    }

    sub build_feed_statistics_section {
        my ( $dates, $merged ) = @_;

        my $content = "### Feed Statistics Evolution\n\n```\n";

        my @feed_rows;
        for my $date ( reverse @$dates ) {
            my $stats = $merged->{$date};
            next unless $stats->{feed_ips};

            push @feed_rows, build_feed_statistics_row( $date, $stats );
        }

        $content .= format_table(
            [ 'Date', 'Gem Feed', 'Gem Atom', 'Web Feed', 'Web Atom', 'Total' ],
            \@feed_rows
        );
        $content .= "\n```\n\n";

        return $content;
    }

    sub build_feed_statistics_row {
        my ( $date, $stats ) = @_;

        my ( $year, $month, $day ) = $date =~ /(\d{4})(\d{2})(\d{2})/;
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

    sub aggregate_hosts_and_urls {
        my ( $dates, $merged ) = @_;

        my %all_hosts;
        my %all_urls;

        for my $date (@$dates) {
            my $stats = $merged->{$date};
            next unless $stats->{page_ips};

            # Aggregate hosts
            while ( my ( $host, $count ) = each %{ $stats->{page_ips}{hosts} } )
            {
                $all_hosts{$host} //= 0;
                $all_hosts{$host} += $count;
            }

            # Aggregate URLs
            while ( my ( $url, $count ) = each %{ $stats->{page_ips}{urls} } ) {
                $all_urls{$url} //= 0;
                $all_urls{$url} += $count;
            }
        }

        return ( \%all_hosts, \%all_urls );
    }

    sub build_top_hosts_section {
        my ($all_hosts, $days) = @_;
        $days //= 30;

        my $content = "## Top 50 Hosts (${days}-Day Total)\n\n```\n";

        my @host_rows;
        my @sorted_hosts =
          sort { $all_hosts->{$b} <=> $all_hosts->{$a} } keys %$all_hosts;
        @sorted_hosts = @sorted_hosts[ 0 .. 49 ] if @sorted_hosts > 50;

        for my $host (@sorted_hosts) {
            push @host_rows, [ $host, $all_hosts->{$host} ];
        }

        $content .= format_table( [ 'Host', 'Visitors' ], \@host_rows );
        $content .= "\n```\n\n";

        return $content;
    }

    sub build_top_urls_section {
        my ($all_urls, $days) = @_;
        $days //= 30;

        my $content = "## Top 50 URLs (${days}-Day Total)\n\n```\n";

        my @url_rows;
        my @sorted_urls =
          sort { $all_urls->{$b} <=> $all_urls->{$a} } keys %$all_urls;
        @sorted_urls = @sorted_urls[ 0 .. 49 ] if @sorted_urls > 50;

        for my $url (@sorted_urls) {
            push @url_rows, [ $url, $all_urls->{$url} ];
        }

        # Truncate URLs to fit within 100-character rows
        truncate_urls_for_table( \@url_rows, 'Visitors' );

        $content .= format_table( [ 'URL', 'Visitors' ], \@url_rows );
        $content .= "\n```\n\n";

        return $content;
    }

    sub build_summary_links {
        my ( $current_days, $report_date ) = @_;

        my $content = '';
        # Only add link to 30-day summary when not on the 30-day report itself
        if ($current_days != 30) {
            $content .= "## Other Summary Reports\n\n";
            $content .= "=> ./30day_summary_$report_date.gmi 30-Day Summary Report\n\n";
        }

        return $content;
    }

sub build_top3_urls_last_n_days_per_day {
    my ($stats_dir, $days, $merged) = @_;
    $days //= 30;
    my $content = "## Top 5 URLs Per Day (Last ${days} Days)\n\n";

    my @all = DateHelper::last_month_dates();
    my @dates = @all;
    @dates = @all[0 .. $days-1] if @all > $days;
    return $content . "(no data)\n\n" unless @dates;

        for my $date (@dates) {
            # Prefer in-memory merged stats if available; otherwise merge from disk
            my $stats = $merged->{$date};
            if (!$stats || !($stats->{page_ips} && $stats->{page_ips}{urls})) {
                $stats = Foostats::Merger::merge_for_date($stats_dir, $date);
            }
            next unless $stats && $stats->{page_ips} && $stats->{page_ips}{urls};

            my ($y,$m,$d) = $date =~ /(\d{4})(\d{2})(\d{2})/;
            $content .= "### $y-$m-$d\n\n";

            my $urls = $stats->{page_ips}{urls};
            my @sorted = sort { ($urls->{$b}//0) <=> ($urls->{$a}//0) } keys %$urls;
            next unless @sorted;
            my $limit = @sorted < 5 ? @sorted : 5;
            @sorted = @sorted[0..$limit-1];

            my @rows;
            for my $u (@sorted) { push @rows, [ $u, $urls->{$u} // 0 ]; }
            truncate_urls_for_table( \@rows, 'Visitors' );
            $content .= "```\n" . format_table([ 'URL', 'Visitors' ], \@rows) . "\n```\n\n";
    }

    return $content;
}
    
    sub generate_index {
        my ($output_dir, $html_output_dir) = @_;

        # Find latest 30-day summary
        opendir(my $dh, $output_dir) or die "Cannot open directory $output_dir: $!";
        my @gmi_files = grep { /\.gmi$/ && $_ ne 'index.gmi' } readdir($dh);
        closedir($dh);

        my @summaries_30day = sort { $b cmp $a } grep { /^30day_summary_/ } @gmi_files;
        my $latest_30 = $summaries_30day[0];

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
            } else {
                my $html_content = gemtext_to_html($content);
                my $html_page = generate_html_page("30-Day Summary Report", $html_content);
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
        my $html_page = generate_html_page("Foostats Reports Index", $html_content);
        say "Writing fallback HTML index to $html_path";
        FileHelper::write($html_path, $html_page);
    }
}

package main;
    use Getopt::Long;
    use Sys::Hostname;

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

    sub parse_logs ( $stats_dir, $odds_file, $odds_log ) {
        my $out = Foostats::FileOutputter->new( stats_dir => $stats_dir );

        $out->{stats} = Foostats::Logreader::parse_logs(
            $out->last_processed_date('web'),
            $out->last_processed_date('gemini'),
            $odds_file, $odds_log
        );

        $out->write;
    }

    sub foostats_main {
        my ( $parse_logs, $replicate, $report, $all, $help, $version );

        # With default values
        my $stats_dir = '/var/www/htdocs/buetow.org/self/foostats';
        my $odds_file = $stats_dir . '/fooodds.txt';
        my $odds_log  = '/var/log/fooodds';
        my $output_dir;       # Will default to $stats_dir/gemtext if not specified
        my $html_output_dir;  # Will default to /var/www/htdocs/gemtexter/stats.foo.zone if not specified
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

        parse_logs( $stats_dir, $odds_file, $odds_log )
          if $parse_logs
          or $all;

        Foostats::Replicator::replicate( $stats_dir, $partner_node )
          if $replicate
          or $all;

        # Set default output directories if not specified
        $output_dir //= '/var/gemini/stats.foo.zone';
        $html_output_dir //= '/var/www/htdocs/gemtexter/stats.foo.zone';

        Foostats::Reporter::report( $stats_dir, $output_dir, $html_output_dir,
            Foostats::Merger::merge($stats_dir) )
          if $report
          or $all;
    }

    # Only run main flow when executed as a script, not when required (e.g., tests)
    foostats_main() unless caller;
