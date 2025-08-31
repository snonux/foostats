use strict;
use warnings;
use Test::More;

ok( do './foostats.pl', 'loaded foostats.pl' );

# Ensure odds file exists
open my $odd, '>', 't/tmp_odds.txt' or die $!;
print $odd "\n"; close $odd;

my $agg = Foostats::Aggregator->new('t/tmp_odds.txt', 't/tmp_filter_log');

my $date = 20250102;

my $e1 = { proto => 'web', host => 'example.org', ip_hash => 'same', ip_proto => 'IPv4', date => $date, time => '121212', uri_path => '/index.html', status => 200 };
my $e2 = { %$e1 }; # same ip and same second triggers excessive filter

$agg->add($e1);
$agg->add($e2);

my $stats = $agg->{stats}{"web_" . $date};
is( $stats->{count}{filtered} // 0, 1, 'one filtered request due to excessive rate');

done_testing;
