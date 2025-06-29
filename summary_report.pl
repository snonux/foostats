#!/usr/bin/perl

use v5.38;
use strict;
use warnings;
use JSON;
use File::Slurp qw(read_file);

my $stats_dir = '/var/www/htdocs/buetow.org/self/foostats';

my @report_files = glob "$stats_dir/*.gmi";
my %summary_stats;
my %feed_stats;
my %host_stats;
my %url_stats;

for my $file (sort @report_files) {
    my ($date) = $file =~ /(\d{8})\.gmi/;
    next unless $date;

    my $content = read_file($file);

    # Extract Summary
    if ($content =~ /### Summary\n\n(.*?)\n\n###/s) {
        my $summary_text = $1;
        my @lines = split /\n/, $summary_text;
        for my $line (@lines) {
            if ($line =~ /\* (.*?): (\d+)/) {
                $summary_stats{$date}{$1} = $2;
            }
        }
    }

    # Extract Feed Statistics
    if ($content =~ /### Feed Statistics\n\n```\n(.*?)\n```/s) {
        my $feed_text = $1;
        my @lines = split /\n/, $feed_text;
        for my $line (@lines) {
            if ($line =~ /\| (.*?) \| (.*?) \|/) {
                my ($key, $val) = (trim($1), trim($2));
                next if $key eq 'Feed Type';
                $feed_stats{$date}{$key} = $val;
            }
        }
    }

    # Extract Host Statistics
    if ($content =~ /### Page Statistics \(by Host\)\n\n```\n(.*?)\n```/s) {
        my $host_text = $1;
        my @lines = split /\n/, $host_text;
        for my $line (@lines) {
            if ($line =~ /\| (.*?) \| (.*?) \|/) {
                my ($key, $val) = (trim($1), trim($2));
                next if $key eq 'Host';
                $host_stats{$key} += $val;
            }
        }
    }

    # Extract URL Statistics
    if ($content =~ /### Page Statistics \(by URL\)\n\n```\n(.*?)\n```/s) {
        my $url_text = $1;
        my @lines = split /\n/, $url_text;
        for my $line (@lines) {
            if ($line =~ /\| (.*?) \| (.*?) \|/) {
                my ($key, $val) = (trim($1), trim($2));
                next if $key eq 'URL';
                $url_stats{$key} += $val;
            }
        }
    }
}

# Generate Summary Report

print "# 30-Day Summary Report\n\n";

print "## Daily Summary Evolution\n\n";
my @dates = sort keys %summary_stats;
my @summary_headers = sort keys %{ $summary_stats{ $dates[0] } };
print "| Date       | " . join(" | ", @summary_headers) . "|\n";
print "|------------|" . join("", map { '-' x (length($_) + 2) . '|' } @summary_headers) . "\n";
for my $date (@dates) {
    print "| $date | ";
    for my $header (@summary_headers) {
        print "$summary_stats{$date}{$header} | ";
    }
    print "\n";
}

print "\n## Daily Feed Statistics Evolution\n\n";
my @feed_headers = sort keys %{ $feed_stats{ $dates[0] } };
print "| Date       | " . join(" | ", @feed_headers) . "|\n";
print "|------------|" . join("", map { '-' x (length($_) + 2) . '|' } @feed_headers) . "\n";
for my $date (@dates) {
    print "| $date | ";
    for my $header (@feed_headers) {
        print "$feed_stats{$date}{$header} | ";
    }
    print "\n";
}

print "\n## Top 50 Hosts\n\n";
my @sorted_hosts = sort { $host_stats{$b} <=> $host_stats{$a} } keys %host_stats;
@sorted_hosts = @sorted_hosts[0..49] if @sorted_hosts > 50;
print "| Host | Total Visitors |\n";
print "|------|----------------|\n";
for my $host (@sorted_hosts) {
    print "| $host | $host_stats{$host} |\n";
}

print "\n## Top 50 URLs\n\n";
my @sorted_urls = sort { $url_stats{$b} <=> $url_stats{$a} } keys %url_stats;
@sorted_urls = @sorted_urls[0..49] if @sorted_urls > 50;
print "| URL | Total Visitors |\n";
print "|-----|----------------|\n";
for my $url (@sorted_urls) {
    print "| $url | $url_stats{$url} |\n";
}

print "\n## Daily Reports\n\n";
for my $file (sort @report_files) {
    my ($date) = $file =~ /(\d{8})\.gmi/;
    next unless $date;
    print "=> ./$date.gmi $date Report\n";
}

sub trim {
    my $s = shift;
    $s =~ s/^\s+|\s+$//g;
    return $s;
}
