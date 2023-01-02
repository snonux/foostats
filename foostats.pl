#!/usr/bin/perl

use v5.32;
use strict;
use warnings;
use feature 'signatures';
no warnings 'experimental::signatures';

use constant {
  WWW_LOGS_GLOB => '/var/www/logs/access.log*',
};

use Data::Dumper;
use Time::Piece;
use Digest::SHA3 'sha3_512_base64';
use PerlIO::gzip;

sub anonymize_ip ($ip) {
  my $ip_proto = (index $ip, ':') == -1 ? 'ipv4' : 'ipv6';
  my $ip_hash = sha3_512_base64 $ip;
  return ($ip_hash, $ip_proto);
}

sub process_lines ($glob, $cb) {
  my sub open_file ($path) {
    my $flag = $path =~ /\.gz$/ ? '<:gzip' : '<';
    open my $file, $flag, $path or die $!;
    return $file;
  }

  for my $path (glob $glob) {
    my $file = open_file $path;
    $cb->(split / +/) while <$file>;
    close $file;
  }
}

sub process_www_logs ($cb) {
  my sub parse_date ($date) {
    eval {
      Time::Piece->strptime($date, '[%d/%b/%Y:%H:%M:%S')->strftime('%Y-%m-%d')
    }
  }

  my sub parse_line (@line) {
    my ($ip_hash, $ip_proto) = anonymize_ip $line[1];
    {
      host => $line[0],
      ip_hash => $ip_hash,
      ip_proto => $ip_proto,
      date => parse_date($line[4]),
      uripath => $line[7],
      status => $line[9],
      #line => \@line,
    }
  }

  process_lines WWW_LOGS_GLOB, sub (@line) {
    $cb->(parse_line @line);
  };
}

process_www_logs sub {
  say Dumper @_;
};

