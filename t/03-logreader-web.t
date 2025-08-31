use strict;
use warnings;
use Test::More;

ok( do './foostats.pl', 'loaded foostats.pl' );

# Create a minimal access log line approximating combined/forwarded format
my $dir = 't/data';
mkdir $dir unless -d $dir;
my $log = "$dir/access.log";
open my $fh, '>', $log or die $!;
print $fh qq{example.org 192.0.2.1 - - [10/Oct/2023:13:55:36 +0000] "GET /gemfeed/index.gmi HTTP/1.1" 200 123 "-" "ua" -\n};
close $fh;

$ENV{FOOSTATS_WEB_LOGS_GLOB} = $log;

my @events;
Foostats::Logreader::parse_web_logs(0, sub { my ($ev) = @_; push @events, $ev if $ev });

ok(@events == 1, 'parsed one web log event');
is($events[0]{proto}, 'web', 'proto parsed');
is($events[0]{host}, 'example.org', 'host parsed');
like($events[0]{uri_path}, qr{^/gemfeed/index\.gmi$}, 'URI parsed');
like($events[0]{date}, qr/^\d{8}$/ , 'date normalized');
like($events[0]{time}, qr/^\d{6}$/, 'time normalized');
ok($events[0]{ip_hash}, 'ip hashed');

done_testing;
