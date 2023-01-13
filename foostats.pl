#!/usr/bin/perl

use v5.32;
use strict;
use warnings;
#use diagnostics;
use feature qw(signatures refaliasing);
no warnings qw(experimental::signatures);

package Str {
  sub contains ($x, $y) { -1 != index $x, $y }
  sub starts_with ($x, $y) { 0 == index $x, $y }
}

package Foostats::Filter {
  use Data::Dumper;

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
        say "$uri_path contains $_ and is odd and will therefore be blocked!";
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
      say "$ip_hash blocked due to excessive requesting...";
      return 1;
    }
    return 0;
  }
}

package Foostats::Aggregator {
  use Data::Dumper;

  use constant {
    FEED_URI => '/gemfeed/atom.xml',
  };

  sub new ($class) {
    bless { filter => Foostats::Filter->new }, $class;
  }

  sub add ($self, $event) {
    my $date = $event->{date};
    $self->add_count($event, $date);
    $self->dump;
  }

  sub add_count ($self, $event, $date) {
    $self->{$date} //= { count => { filtered => 0 }, feed_ips => {} };
    \my $e = \$event;

    unless ($self->{filter}->ok($event)) {
      $self->{$date}{count}{filtered}++;
      return;
    }

    \my $c = \$self->{$date}{count};
    \my $f = \$self->{$date}{feed_ips};

    ($c->{$e->{proto}} //= 0)++;
    ($c->{$e->{ip_proto}} //= 0)++;
    ($c->{$e->{proto}.' '.$e->{ip_proto}} //= 0)++;

    if (Str::contains $e->{uri_path}, FEED_URI) {
      ($c->{feed} //= 0)++;
      ($f->{$e->{ip_hash}} //= 0)++;
      $c->{feed_uniq} = scalar keys %$f;
    }
  }

  sub dump ($self) {
    say Dumper $self
  }
}

package Foostats::Logreader {
  use Data::Dumper;
  use Digest::SHA3 'sha3_512_base64';
  use File::stat;
  use PerlIO::gzip;
  use Time::Piece;

  use constant {
    GEMINI_LOGS_GLOB => '/var/log/daemon*',
    WWW_LOGS_GLOB => '/var/www/logs/access.log*',
  };

  sub anonymize_ip ($ip) {
    my $ip_proto = (Str::contains $ip, ':') ? 'IPv6' : 'IPv4';
    my $ip_hash = sha3_512_base64 $ip;
    return ($ip_hash, $ip_proto);
  }

  sub read_lines ($glob, $callback) {
    my sub year ($path) {
      localtime( (stat $path)->mtime )->strftime('%Y')
    }

    my sub open_file ($path) {
      my $flag = $path =~ /\.gz$/ ? '<:gzip' : '<';
      open my $file, $flag, $path or die $!;
      return $file;
    }

    for my $path (glob $glob) {
      my $file = open_file $path;
      my $year = year $file;
      while (<$file>) {
        $callback->($year, split / +/) unless Str::contains $_, 'logfile turned over';
      }
      close $file;
    }
  }

  sub parse_www_logs ($callback) {
    my sub parse_date ($date) {
      my $t = Time::Piece->strptime($date, '[%d/%b/%Y:%H:%M:%S');
      ($t->strftime('%Y-%m-%d'), $t->strftime('%H:%M:%S'));
    }

    my sub parse_line (@line) {
      my ($ip_hash, $ip_proto) = anonymize_ip $line[1];
      my ($date, $time) = parse_date $line[4];
      {
        proto => 'http/s',
        host => $line[0],
        ip_hash => $ip_hash,
        ip_proto => $ip_proto,
        date => $date,
        time => $time,
        uri_path => $line[7],
        status => $line[9],
      }
    }

    read_lines WWW_LOGS_GLOB, sub ($year, @line) {
      $callback->(parse_line @line);
    };
  }

  sub parse_gemini_logs ($callback) {
    my sub parse_date ($year, @line) {
      my $timestr = "$line[0] $line[1]";
      Time::Piece->strptime($timestr, '%b %d')->strftime("$year-%m-%d");
    }

    my sub parse_vger_line ($year, @line) {
      my $full_path = $line[5];
      $full_path =~ s/"//g;
      my ($proto, undef, $host, $uri_path) = split '/', $full_path, 4;
      $uri_path = '' unless defined $uri_path;
      {
        proto => 'gemini',
        host => $host,
        uri_path => "/$uri_path",
        status => $line[6],
        date => parse_date($year, @line),
        time => $line[2],
      }
    }

    my sub parse_relayd_line ($year, @line) {
      my ($ip_hash, $ip_proto) = anonymize_ip $line[12];
      {
        ip_hash => $ip_hash,
        ip_proto => $ip_proto,
        date => parse_date($year, @line),
        time => $line[2],
      }
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
        $callback->({ %$vger, %$relayd });
        $vger = $relayd = undef;
      }
    };
  }

  sub parse_logs {
    my $agg = Foostats::Aggregator->new;

    my sub foo ($event) { $agg->add($event); }

    parse_www_logs \&foo;
    parse_gemini_logs \&foo;

    say Dumper $agg;
  }

  parse_logs;
}
