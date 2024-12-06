#!/usr/bin/perl

use v5.38;

# Those are enabled automatically now w/ this version of Perl
# use strict;
# use warnings;

use builtin qw(true false);
use experimental qw(builtin);

use feature qw(refaliasing);
no warnings qw(experimental::refaliasing);

# use diagnostics; 
# use Data::Dumper;

# TODO: Blog post about this script and the new Perl features used.

package Foostats::Logreader {
  use Digest::SHA3 'sha3_512_base64';
  use File::stat;
  use PerlIO::gzip;
  use Time::Piece;
  use String::Util qw(contains startswith endswith);

  use constant {
    GEMINI_LOGS_GLOB => '/var/log/daemon*',
    WEB_LOGS_GLOB => '/var/www/logs/access.log*',
  };

  sub anonymize_ip ($ip) {
    my $ip_proto = contains($ip, ':') ? 'IPv6' : 'IPv4';
    my $ip_hash = sha3_512_base64 $ip;
    return ($ip_hash, $ip_proto);
  }

  sub read_lines ($glob, $cb) {
    my sub year ($path) { localtime( (stat $path)->mtime )->strftime('%Y') }

    my sub open_file ($path) {
      my $flag = $path =~ /\.gz$/ ? '<:gzip' : '<';
      open my $fd, $flag, $path or die "$path: $!";
      return $fd;
    }

    my $last = false;

  LAST:
    for my $path (glob $glob) {
      say "Processing $path";

      my $file = open_file $path;
      my $year = year $file;

      while (<$file>) {
        next if contains($_, 'logfile turned over');
        # last == true means: After this file, don't process more
        $last = true unless defined $cb->($year, split / +/);
      }

      say "Closing $path";
      close $file;
      last LAST if $last;
    }
  }

  sub parse_web_logs ($last_processed_date, $cb) {
    my sub parse_date ($date) {
      my $t = Time::Piece->strptime($date, '[%d/%b/%Y:%H:%M:%S');
      return ($t->strftime('%Y%m%d'), $t->strftime('%H%M%S'));
    }

    my sub parse_web_line (@line) {
      my ($date, $time) = parse_date $line[4];
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

    read_lines WEB_LOGS_GLOB, sub ($year, @line) { $cb->(parse_web_line @line) };
  }

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
      return undef if $date < $last_processed_date;

      my ($ip_hash, $ip_proto) = anonymize_ip $line[12];
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
    read_lines GEMINI_LOGS_GLOB, sub ($year, @line) {
      if ($line[4] eq 'vger:') {
        $vger = parse_vger_line $year, @line;
      } elsif ($line[5] eq 'relay' and startswith($line[6], 'gemini')) {
        $relayd = parse_relayd_line $year, @line;
      }

      if (defined $vger and defined $relayd and $vger->{time} eq $relayd->{time}) {
        $cb->({ %$vger, %$relayd });
        $vger = $relayd = undef;
      }
    };
  }

  sub parse_logs ($last_web_date, $last_gemini_date) {
    my $agg = Foostats::Aggregator->new;

    parse_web_logs $last_web_date, sub ($event) { $agg->add($event) };
    parse_gemini_logs $last_gemini_date, sub ($event) { $agg->add($event) };

    return $agg->{stats};
  }
}

package Foostats::Filter {
  use String::Util qw(contains startswith endswith);
  use constant WARN_ODD => false;

  sub new ($class) {
    bless {
      odds => [qw(
        .php wordpress /wp .asp .. robots.txt .env + % HNAP1 /admin
        .git microsoft.exchange .lua /owa/ 
      )]
    }, $class;
  }

  sub ok ($self, $event) {
    state %blocked = ();
    return false if exists $blocked{$event->{ip_hash}};

    if ($self->odd($event) or $self->excessive($event)) {
      ($blocked{$event->{ip_hash}} //= 0)++;
      return false;
    } else {
      return true;
    }
  }

  sub odd ($self, $event) {
    \my $uri_path = \$event->{uri_path};

    for ($self->{odds}->@*) {
      if (contains($uri_path, $_)) {
        say STDERR "Warn: $uri_path contains $_ and is odd and will therefore be blocked!" if WARN_ODD;
        return true;
      }
    }

    return false;
  }

  sub excessive ($self, $event) {
    \my $time = \$event->{time};
    \my $ip_hash = \$event->{ip_hash};

    state $last_time = $time; # Time with second: 'HH:MM:SS'
    state %count = (); # IPs accessing within the same second!

    if ($last_time ne $time) {
      $last_time = $time;
      %count = ();
      return false;
    }

    # IP requested site more than once within the same second!?
    if (1 < ++($count{$ip_hash} //= 0)) {
      say STDERR "Warn: $ip_hash blocked due to excessive requesting..." if WARN_ODD;
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

  sub new ($class) { bless { filter => Foostats::Filter->new, stats => {} }, $class }

  sub add ($self, $event) {
    return undef unless defined $event;
    
    my $date = $event->{date};
    my $date_key = $event->{proto} . "_$date";

    $self->{stats}{$date_key} //= {
      count    => { filtered  => 0 },
      feed_ips => { atom_feed => {}, gemfeed => {} },
      page_ips => { hosts     => {}, urls    => {} },
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

  sub add_count ($self, $stats, $event) {
    \my $c = \$stats->{count};
    \my $e = \$event;

    ($c->{$e->{proto}} //= 0)++;
    ($c->{$e->{ip_proto}} //= 0)++;
  }

  sub add_feed_ips ($self, $stats, $event) {
    \my $f = \$stats->{feed_ips};
    \my $e = \$event;

    if (endswith($e->{uri_path}, ATOM_FEED_URI)) {
      ($f->{atom_feed}->{$e->{ip_hash}} //= 0)++;
    } elsif (contains($e->{uri_path}, GEMFEED_URI)) {
      ($f->{gemfeed}->{$e->{ip_hash}} //= 0)++;
    } elsif (endswith($e->{uri_path}, GEMFEED_URI_2)) {
      ($f->{gemfeed}->{$e->{ip_hash}} //= 0)++;
    } else {
      0
    }
  }

  sub add_page_ips ($self, $stats, $event) {
    \my $e = \$event;
    \my $p = \$stats->{page_ips};

    return if !endswith($e->{uri_path}, '.html') 
           && !endswith($e->{uri_path}, '.gmi');

    ($p->{hosts}->{$e->{host}}->{$e->{ip_hash}} //= 0)++;
    ($p->{urls}->{$e->{host}.$e->{uri_path}}->{$e->{ip_hash}} //= 0)++;
  }
}

package Foostats::Outputter {
  use JSON;
  use Sys::Hostname;
  
  sub new ($class, %args) {
    my $self = bless \%args, $class;
    mkdir $self->{stats_dir} or die $self->{stats_dir} . ": $!" unless -d $self->{stats_dir};
    return $self;
  }

  sub last_processed_date ($self, $proto) {
    my $hostname = hostname();
    my @processed = glob $self->{stats_dir} . "/${proto}_????????.$hostname.json";
    my ($date) = @processed ? ($processed[-1] =~ /_(\d{8})\.$hostname\.json/) : 0;
    return int($date);
  }

  sub write ($self) { $self->for_dates(\&write_json) }
  sub for_dates ($self, $cb) { $cb->($self, $_, $self->{stats}{$_}) for sort keys $self->{stats}->%* }

  sub write_json ($self, $date_key, $stats) {
    my $hostname = hostname();
    my $path = $self->{stats_dir} . "/${date_key}.$hostname.json";
    my $json = encode_json $stats;

    say "Writing $path";
    open my $fd, '>', "$path.tmp" or die "$path.tmp: $!";
    print $fd $json;
    close $fd;

    rename "$path.tmp", $path or die "$path.tmp: $!";
  } 
}

package Foostats::Replicator {
  sub new ($class, %args) { bless \%args, $class }

  sub replicate ($self, $partner_node) {
    die 'Replicate is not yet implemented';
  }
}

package main {
  use Getopt::Long;
  use Sys::Hostname;

  sub parse_logs ($stats_dir) {
    my $out = Foostats::Outputter->new(stats_dir => $stats_dir);

    $out->{stats} = Foostats::Logreader::parse_logs(
      $out->last_processed_date('web'),
      $out->last_processed_date('gemini'),
    );

    $out->write;
  }

  sub replicate ($stats_dir, $partner_node) {
    die 'Partner node not specified' unless defined $partner_node;
    Foostats::Replicator->new(stats_dir => $stats_dir)->replicate($partner_node);
  }

  sub pretty_print () { say 'pretty_print not yet implemented' }

  my ($parse_logs, $replicate, $pretty_print, $partner_node);
  my $stats_dir = '/var/www/htdocs/buetow.org/self/foostats';

  GetOptions 'parse-logs'   => \$parse_logs,
             'replicate'    => \$replicate,
             'pretty-print' => \$pretty_print,
             'stats-dir'    => \$stats_dir,
             'partner-node' => \$partner_node;

  parse_logs $stats_dir if $parse_logs;
  replicate $stats_dir, $partner_node if $replicate;
  pretty_print $stats_dir if $pretty_print;
}

# TODO NEXT:
# 1) Implement replicator
# 2) Also merge the results
# 3) Write out a nice output from each merged file
