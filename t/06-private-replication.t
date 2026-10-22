use strict;
use warnings;
use Test::More;
use File::Temp qw(tempdir);
use File::Copy qw(copy);
use File::Basename qw(basename);
use IO::Socket::INET;
use POSIX qw(setsid);
use Sys::Hostname qw(hostname);

require './foostats.pl';
my $dir = tempdir(CLEANUP => 1);
my $key_hex = 'a1' x 32;
open my $kf, '>', "$dir/key" or die $!;
print $kf $key_hex;
close $kf;
chmod 0600, "$dir/key";
Foostats::Privacy::load_key("$dir/key");
my $tag = Foostats::Privacy::digest('192.0.2.1');
my $date = (DateHelper::last_month_dates())[0];
my $older = (DateHelper::last_month_dates())[1];

open my $odds, '>', "$dir/odds" or die $!;
close $odds;
my $agg = Foostats::Aggregator->new("$dir/odds", "$dir/filter.log");
$agg->add({proto => 'web', host => 'example.test', ip_hash => $tag,
           ip_proto => 'IPv4', date => $date, time => '120000',
           uri_path => '/index.html', status => 200});
my $out = Foostats::FileOutputter->new(stats_dir => "$dir/private");
$out->{stats} = $agg->{stats};
$out->write();
my $local = "$dir/private/web_$date." . hostname() . '.json.gz';
ok(-f $local, 'actual producer writes a private counter archive');
is((stat($local))[2] & 0777, 0640, 'counter mode allows only owner and replication group');
is((stat("$dir/private"))[2] & 0777, 0700, 'standalone default creates a private directory');
my $data = FileHelper::read_json_gz($local);
is_deeply($data->{privacy}, Foostats::Privacy::metadata(), 'producer attaches scheme/key identity');

mkdir "$dir/export" or die $!;
my $peer_file = "web_$date.peer.example.json.gz";
copy($local, "$dir/export/$peer_file") or die $!;
my $socket = IO::Socket::INET->new(LocalAddr => '127.0.0.1', LocalPort => 0,
                                 Listen => 1, Proto => 'tcp') or die $!;
my $port = $socket->sockport;
close $socket;
open my $config, '>', "$dir/rsyncd.conf" or die $!;
print $config <<"CONFIG";
use chroot = no
reverse lookup = no
lock file = $dir/lock
log file = $dir/daemon.log
[foostats-private]
path = $dir/export
read only = yes
list = no
hosts allow = 127.0.0.1
hosts deny = *
CONFIG
close $config;
my $pid = fork();
defined $pid or die $!;
if (!$pid) {
    setsid() >= 0 or die $!;
    open STDIN, '<', '/dev/null' or die $!;
    open STDOUT, '>', '/dev/null' or die $!;
    open STDERR, '>', "$dir/daemon.stderr" or die $!;
    exec 'rsync', '--daemon', '--no-detach', '--address=127.0.0.1',
         "--port=$port", "--config=$dir/rsyncd.conf";
    die "Cannot start fixture rsync";
}
END {
    if ($pid) {
        kill 'TERM', -$pid;
        waitpid $pid, 0;
    }
}
my $listening = 0;
for (1 .. 100) {
    my $probe = IO::Socket::INET->new(PeerAddr => '127.0.0.1', PeerPort => $port,
                                    Proto => 'tcp', Timeout => 0.1);
    if ($probe) { close $probe; $listening = 1; last; }
    select undef, undef, undef, 0.02;
}
ok($listening, 'owned loopback rsync daemon is ready');
BAIL_OUT('fixture daemon unavailable') unless $listening;
my $remote = "rsync://127.0.0.1:$port/foostats-private/$peer_file";
my $received = "$dir/private/$peer_file";
Foostats::Replicator::replicate_file($remote, $received, 1);
ok(-f $received, 'native rsync replicates an archive without public HTTP');
is((stat($received))[2] & 0777, 0640, 'replica retains private file mode');
my $merged = Foostats::Merger::merge_for_date("$dir/private", $date);
is($merged->{count}{web}, 2, 'both nodes contribute their requests');
is($merged->{page_ips}{hosts}{'example.test'}, 1, 'same visitor on both nodes is counted once');

open my $before_fh, '<', $received or die $!;
my $before = do { local $/; <$before_fh> };
close $before_fh;
my $bad = FileHelper::read_json_gz("$dir/export/$peer_file");
$bad->{privacy}{key_id} = '0' x 64;
FileHelper::write_json_gz("$dir/export/$peer_file", $bad);
ok(!eval { Foostats::Replicator::replicate_file($remote, $received, 1); 1 },
   'different-key peer is rejected before replacing good replica');
open my $after_fh, '<', $received or die $!;
my $after = do { local $/; <$after_fh> };
close $after_fh;
is($after, $before, 'good previous replica survives incompatible peer');
my @temporary = glob "$dir/private/.replica-*";
is(scalar @temporary, 0, 'failed validation leaves no partial files');
ok(!eval { Foostats::Replicator::replicate("$dir/private", '../invalid'); 1 },
   'unsafe partner filename is refused');
ok(!eval { Foostats::Replicator::replicate("$dir/private", 'custom.example'); 1 },
   'custom peer cannot silently fall back to public transport');

mkdir "$dir/public-gmi" or die $!;
mkdir "$dir/public-html" or die $!;
open my $historic, '>', "$dir/public-gmi/$older.gmi" or die $!;
print $historic "Existing aggregate history\n";
close $historic;
Foostats::Reporter::report("$dir/private", "$dir/public-gmi", "$dir/public-html",
                          $date => $merged, $older => {count => {}});
open my $saved, '<', "$dir/public-gmi/$older.gmi" or die $!;
is(do { local $/; <$saved> }, "Existing aggregate history\n", 'missing raw history does not overwrite old aggregate page');
close $saved;
my @public = (glob("$dir/public-gmi/*"), glob("$dir/public-html/*"));
ok(@public > 2, 'actual aggregate reporter generates public artifacts');
for my $file (@public) {
    open my $fh, '<', $file or die $!;
    my $body = do { local $/; <$fh> };
    close $fh;
    unlike($body, qr/\Q$tag\E|\Q$key_hex\E|192\.0\.2\.1|key_id|hmac-sha3/,
           'public report contains neither visitor identity nor private metadata');
}

done_testing;
