#!/usr/bin/perl

use v5.38;

# Those are enabled automatically now w/ this version of Perl
# use strict;
# use warnings;

use builtin      qw(true false);
use experimental qw(builtin);

use feature qw(refaliasing);
no warnings qw(experimental::refaliasing);

# TODO: UNDO
use diagnostics;

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
}

package Foostats::Logreader {
    use Digest::SHA3 'sha3_512_base64';
    use File::stat;
    use PerlIO::gzip;
    use Time::Piece;
    use String::Util qw(contains startswith endswith);

    use constant {
        GEMINI_LOGS_GLOB => '/var/log/daemon*',
        WEB_LOGS_GLOB    => '/var/www/logs/access.log*',
    };

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

        read_lines WEB_LOGS_GLOB, sub ( $year, @line ) {
            $cb->( parse_web_line @line );
        };
    }

    sub parse_gemini_logs ( $last_processed_date, $cb ) {
        my sub parse_date ( $year, @line ) {
            my $timestr = "$line[0] $line[1]";
            return Time::Piece->strptime( $timestr, '%b %d' )->strftime("$year%m%d");
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
        read_lines GEMINI_LOGS_GLOB, sub ( $year, @line ) {
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

    sub parse_logs ( $last_web_date, $last_gemini_date, $odds_file, $odds_log ) {
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
            next
              unless contains( $uri_path, $_ );

            $self->log( 'WARN', $uri_path, "contains $_ and is odd and will therefore be blocked!" );
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
            $self->log( 'WARN', $ip_hash, "blocked due to excessive requesting..." );
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

        $self->{stats}{$date_key} //= {
            count => {
                filtered => 0
            },
            feed_ips => {
                atom_feed => {},
                gemfeed   => {}
            },
            page_ips => {
                hosts => {},
                urls  => {}
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

        if ( endswith( $e->{uri_path}, ATOM_FEED_URI ) ) {
            ( $f->{atom_feed}->{ $e->{ip_hash} } //= 0 )++;
        }
        elsif ( contains( $e->{uri_path}, GEMFEED_URI ) ) {
            ( $f->{gemfeed}->{ $e->{ip_hash} } //= 0 )++;
        }
        elsif ( endswith( $e->{uri_path}, GEMFEED_URI_2 ) ) {
            ( $f->{gemfeed}->{ $e->{ip_hash} } //= 0 )++;
        }
        else {
            0;
        }
    }

    sub add_page_ips ( $self, $stats, $event ) {
        \my $e = \$event;
        \my $p = \$stats->{page_ips};

        return
          if !endswith( $e->{uri_path}, '.html' )
          && !endswith( $e->{uri_path}, '.gmi' );

        ( $p->{hosts}->{ $e->{host} }->{ $e->{ip_hash} } //= 0 )++;
        ( $p->{urls}->{ $e->{host} . $e->{uri_path} }->{ $e->{ip_hash} } //= 0 )++;
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
        my $hostname  = hostname();
        my @processed = glob $self->{stats_dir} . "/${proto}_????????.$hostname.json.gz";
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
                my $path     = $self->{stats_dir} . "/${date_key}.$hostname.json.gz";
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
    use Data::Dumper;    # TODO: UNDO

    sub merge ($stats_dir) {
        my %merge;
        $merge{$_} = merge_for_date( $stats_dir, $_ ) for DateHelper::last_month_dates;
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
            $merge{$key}->{$_} = scalar keys $merge{$key}->{$_}->%* for keys $merge{$key}->%*;
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
    use Data::Dumper;

    sub report (%merged) {
        print Dumper %merged;
    }
}

package main {
    use Getopt::Long;
    use Sys::Hostname;

    sub parse_logs ( $stats_dir, $odds_file, $odds_log ) {
        my $out = Foostats::FileOutputter->new( stats_dir => $stats_dir );

        $out->{stats} = Foostats::Logreader::parse_logs(
            $out->last_processed_date('web'),
            $out->last_processed_date('gemini'),
            $odds_file, $odds_log
        );

        $out->write;
    }

    my ( $parse_logs, $replicate, $report, $all );

    # With default values
    my $stats_dir = '/var/www/htdocs/buetow.org/self/foostats';
    my $odds_file = $stats_dir . '/fooodds.txt';
    my $odds_log  = '/var/log/fooodds';
    my $partner_node =
      hostname eq 'fishfinger.buetow.org'
      ? 'blowfish.buetow.org'
      : 'fishfinger.buetow.org';

    # TODO: Add help output
    GetOptions
      'parse-logs!'    => \$parse_logs,
      'filter-log=s'   => \$odds_log,
      'odds-file=s'    => \$odds_file,
      'replicate!'     => \$replicate,
      'report!'        => \$report,
      'all!'           => \$all,
      'stats-dir=s'    => \$stats_dir,
      'partner-node=s' => \$partner_node;

    parse_logs( $stats_dir, $odds_file, $odds_log )
      if $parse_logs
      or $all;

    Foostats::Replicator::replicate( $stats_dir, $partner_node )
      if $replicate
      or $all;

    Foostats::Reporter::report( Foostats::Merger::merge($stats_dir) )
      if $report
      or $all;
}
