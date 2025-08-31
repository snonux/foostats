use strict;
use warnings;
use Test::More;

ok( do './foostats.pl', 'loaded foostats.pl' );

# Ensure odds file exists before creating filter/aggregator
open my $odd, '>', 't/tmp_odds.txt' or die $!;
print $odd "\n"; close $odd;

my $agg = Foostats::Aggregator->new('t/tmp_odds.txt', 't/tmp_filter_log');

my $date = 20250101;

my $events = [
  { proto => 'web',    host => 'example.org', ip_hash => 'ip1', ip_proto => 'IPv4', date => $date, time => '120000', uri_path => '/gemfeed/atom.xml', status => 200 },
  { proto => 'gemini', host => 'example.org', ip_hash => 'ip2', ip_proto => 'IPv6', date => $date, time => '120100', uri_path => '/gemfeed/',           status => 20  },
  { proto => 'web',    host => 'example.org', ip_hash => 'ip3', ip_proto => 'IPv4', date => $date, time => '120200', uri_path => '/gemfeed/index.gmi',  status => 200 },
  { proto => 'web',    host => 'example.org', ip_hash => 'ip4', ip_proto => 'IPv4', date => $date, time => '120300', uri_path => '/index.html',         status => 200 },
];

$agg->add($_) for @$events;

my $stats = $agg->{stats}{"web_" . $date};
ok($stats, 'have web stats for date');
use Test::More; diag("web stats: ", join(',', sort keys %{$stats->{feed_ips}{atom_feed}}));
is( scalar(keys %{$stats->{feed_ips}{atom_feed}}), 1, 'one atom feed IP');
is( scalar(keys %{$stats->{feed_ips}{gemfeed}}),   1, 'one gemfeed IP (from web)');

my $gstats = $agg->{stats}{"gemini_" . $date};
ok($gstats, 'have gemini stats for date');
diag("gemini feed keys: ", join(',', sort keys %{$gstats->{feed_ips}{gemfeed}}));
is( scalar(keys %{$gstats->{feed_ips}{gemfeed}}),  1, 'one gemfeed IP (from gemini)');

done_testing;
