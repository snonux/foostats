#!/usr/bin/perl

use v5.38;
use strict;
use warnings;

use feature qw(refaliasing);
no warnings qw(experimental::refaliasing);

# use diagnostics; 
# use Data::Dumper;

# TODO: Blog post about this script and the new Perl features used.
package Str {
  sub contains ($x, $y) { -1 != index $x, $y }
  sub starts_with ($x, $y) { 0 == index $x, $y }
  sub ends_with ($x, $y) { length($x) - length($y) == index($x, $y) }
}

package Foostats::Logreader {
  use Digest::SHA3 'sha3_512_base64';
  use File::stat;
  use PerlIO::gzip;
  use Time::Piece;

  use constant {
    GEMINI_LOGS_GLOB => '/var/log/daemon*',
    WEB_LOGS_GLOB => '/var/www/logs/access.log*',
  };

  sub anonymize_ip ($ip) {
    my $ip_proto = (Str::contains $ip, ':') ? 'IPv6' : 'IPv4';
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

    my $last = 0;

  LAST:
    for my $path (glob $glob) {
      say "Processing $path";

      my $file = open_file $path;
      my $year = year $file;
      my $last = 0;

      while (<$file>) {
        next if Str::contains $_, 'logfile turned over';
        # last == 1 means: After this file, don't process more
        $last = 1 unless defined $cb->($year, split / +/);
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
        proto => 'web',
        host => $line[0],
        ip_hash => $ip_hash,
        ip_proto => $ip_proto,
        date => $date,
        time => $time,
        uri_path => $line[7],
        status => $line[9],
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
        proto => 'gemini',
        host => $host,
        uri_path => "/$uri_path",
        status => $line[6],
        date => int(parse_date($year, @line)),
        time => $line[2],
      };
    }

    my sub parse_relayd_line ($year, @line) {
      my $date = int(parse_date($year, @line));
      return undef if $date < $last_processed_date;
      my ($ip_hash, $ip_proto) = anonymize_ip $line[12];

      return {
        ip_hash => $ip_hash,
        ip_proto => $ip_proto,
        date => $date,
        time => $line[2],
      };
    }

    # Expect one vger and one relayd log line per event! So collect
    # both events (one from one log line each) and then merge the result hash!
    my ($vger, $relayd);
    read_lines GEMINI_LOGS_GLOB, sub ($year, @line) {
      if ($line[4] eq 'vger:') {
        $vger = parse_vger_line $year, @line;
      } elsif ($line[5] eq 'relay' and Str::starts_with $line[6], 'gemini') {
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
  use constant WARN_ODD => 0;

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
    return 0 if exists $blocked{$event->{ip_hash}};

    if ($self->odd($event) or $self->excessive($event)) {
      ($blocked{$event->{ip_hash}} //= 0)++;
      return 0;
    } else {
      return 1;
    }
  }

  sub odd ($self, $event) {
    \my $uri_path = \$event->{uri_path};

    for ($self->{odds}->@*) {
      if (Str::contains $uri_path, $_) {
        say STDERR "Warn: $uri_path contains $_ and is odd and will therefore be blocked!" if WARN_ODD;
        return 1;
      }
    }
    return 0;
  }

  sub excessive ($self, $event) {
    \my $time = \$event->{time};
    \my $ip_hash = \$event->{ip_hash};

    state $last_time = $time; # Time with second: 'HH:MM:SS'
    state %count = (); # IPs accessing within the same second!

    if ($last_time ne $time) {
      $last_time = $time;
      %count = ();
      return 0;
    }

    # IP requested site more than once within the same second!?
    if (1 < ++($count{$ip_hash} //= 0)) {
      say STDERR "Warn: $ip_hash blocked due to excessive requesting..." if WARN_ODD;
      return 1;
    }
    return 0;
  }
}

package Foostats::Aggregator {
  use constant {
    ATOM_FEED_URI => '/gemfeed/atom.xml',
    GEMFEED_URI => '/gemfeed/index.gmi',
    GEMFEED_URI_2 => '/gemfeed/',
  };

  sub new ($class) { bless { filter => Foostats::Filter->new, stats => {} }, $class }

  sub add ($self, $event) {
    return undef unless defined $event;
    
    my $date = $event->{date};
    my $date_key = $event->{proto} . "_$date";

    $self->{stats}{$date_key} //= {
      count => { filtered => 0 },
      feed_ips => { atom_feed => {}, gemfeed => {} },
      page_ips => { hosts => {}, urls => {} },
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

  sub add_count($self, $stats, $event) {
    \my $c = \$stats->{count};
    \my $e = \$event;

    ($c->{$e->{proto}} //= 0)++;
    ($c->{$e->{ip_proto}} //= 0)++;
  }

  sub add_feed_ips($self, $stats, $event) {
    \my $f = \$stats->{feed_ips};
    \my $e = \$event;

    if (Str::ends_with $e->{uri_path}, ATOM_FEED_URI) {
      ($f->{atom_feed}->{$e->{ip_hash}} //= 0)++;
    } elsif (Str::contains $e->{uri_path}, GEMFEED_URI) {
      ($f->{gemfeed}->{$e->{ip_hash}} //= 0)++;
    } elsif (Str::ends_with $e->{uri_path}, GEMFEED_URI_2) {
      ($f->{gemfeed}->{$e->{ip_hash}} //= 0)++;
    } else {
      0
    }
  }

  sub add_page_ips($self, $stats, $event) {
    \my $e = \$event;
    \my $p = \$stats->{page_ips};

    return if !Str::ends_with($e->{uri_path}, '.html') 
           && !Str::ends_with($e->{uri_path}, '.gmi');

    ($p->{hosts}->{$e->{host}}->{$e->{ip_hash}} //= 0)++;
    ($p->{urls}->{$e->{host}.$e->{uri_path}}->{$e->{ip_hash}} //= 0)++;
  }
}

package Foostats::Outputter {
  use JSON;
  
  sub new ($class, %args) {
    my $self = bless \%args, $class;
    mkdir $self->{outdir} or die $self->{outdir} . ": $!" unless -d $self->{outdir};
    return $self;
  }

  sub last_processed_date ($self, $proto) {
    my @processed = glob $self->{outdir} . "/${proto}_????????.json";
    my ($date) = @processed ? ($processed[-1] =~ /_(\d{8})\.json/) : 0;
    return int($date);
  }

  sub write ($self) { say $self->for_dates(\&_dump_json) }

  sub for_dates ($self, $cb) {
    say "$_: " . $cb->($self, $_, $self->{stats}{$_}) for sort keys $self->{stats}->%*;
  }

  sub _dump_json ($self, $date_key, $stats) {
    my $path = $self->{outdir} . "/$date_key.json";

    say "Dumping $path";
    open my $fd, '>', "$path.tmp" or die "$path.tmp: $!";
    print $fd encode_json($stats) . "\n";
    close $fd;

    rename "$path.tmp", $path or die "$path.tmp: $!";
  } 
}

package main {
  use Getopt::Long;

  sub parse_logs () {
    my $out = Foostats::Outputter->new(outdir => '/var/foostats');

    $out->{stats} = Foostats::Logreader::parse_logs(
      $out->last_processed_date('web'),
      $out->last_processed_date('gemini'),
    );

    $out->write;
  }

  sub replicate () {
    say 'replicate not yet implemented';
  }

  sub pretty_print () {
    say 'pretty_print not yet implemented';
  }

  my ($parse_logs, $replicate, $pretty_print);
  GetOptions 'parse-logs'   => \$parse_logs,
             'replicate'    => \$replicate,
             'pretty-print' => \$pretty_print;

  parse_logs if $parse_logs;
  replicate if $replicate;
  pretty_print if $pretty_print;
}
