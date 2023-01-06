#!/usr/bin/perl

use v5.32;
use strict;
use warnings;
use feature 'signatures';
no warnings 'experimental::signatures';

package Foostats::Tokenizer {
  use constant {
    GEMINI_LOGS_GLOB => '/var/log/daemon*',
    WWW_LOGS_GLOB => '/var/www/logs/access.log*',
  };

  use Data::Dumper;
  use Digest::SHA3 'sha3_512_base64';
  use File::stat;
  use PerlIO::gzip;
  use Time::Piece;

  sub anonymize_ip ($ip) {
    my $ip_proto = (index $ip, ':') == -1 ? 'ipv4' : 'ipv6';
    my $ip_hash = sha3_512_base64 $ip;
    return ($ip_hash, $ip_proto);
  }

  sub read_lines ($glob, $callback, $skip_first_line = 1) {
    my sub year ($path) {
      localtime( stat($path)->mtime )->strftime('%Y')
    }

    my sub open_file ($path) {
      my $flag = $path =~ /\.gz$/ ? '<:gzip' : '<';
      open my $file, $flag, $path or die $!;
      return $file;
    }

    for my $path (glob $glob) {
      my $file = open_file $path;
      my $year = year $file;
      <$file> if $skip_first_line; # Contains 'logfile turned over' newsyslog message.
      $callback->($year, split / +/) while <$file>;
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
        uripath => $line[7],
        status => $line[9],
      }
    }

    read_lines WWW_LOGS_GLOB, sub ($year, @line) {
      $callback->(parse_line @line);
    };
  }

  sub parse_gemini_logs ($callback) {
    my sub parse_date ($year, @line) {
      my $timestr = "$year $line[0] $line[1]";
      Time::Piece->strptime($timestr, '%Y %b %d')->strftime('%Y-%m-%d');
    }

    my sub parse_vger_line ($year, @line) {
      my $full_path = $line[5];
      $full_path =~ s/"//g;
      my ($proto, undef, $host, $uripath) = split '/', $full_path, 4;
      $uripath = '' unless defined $uripath;
      {
        proto => 'gemini',
        host => $host,
        uripath => "/$uripath",
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
      } elsif ($line[5] eq 'relay' and index($line[6], 'gemini') == 0) {
        $relayd = parse_relayd_line $year, @line;
      }

      if (defined $vger and defined $relayd and $vger->{time} eq $relayd->{time}) {
        $callback->({ %$vger, %$relayd });
        $vger = $relayd = undef;
      }
    };
  }

  sub parse_logs {
    my sub foo { say Dumper @_ };
    parse_www_logs \&foo;
    parse_gemini_logs \&foo;
  }

  parse_logs;
}
