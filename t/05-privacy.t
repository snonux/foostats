use strict;
use warnings;
use Test::More;
use File::Temp qw(tempdir);
use MIME::Base64 qw(decode_base64);
use Digest::HMAC qw(hmac_hex);
use Digest::SHA3 qw(sha3_512 sha3_512_base64);

require './foostats.pl';
my $dir = tempdir(CLEANUP => 1);
my $path = "$dir/key";
sub key_file {
    my ($hex, $mode) = @_;
    open my $fh, '>', $path or die $!;
    print $fh $hex;
    close $fh or die $!;
    chmod($mode // 0600, $path) or die $!;
}

# NIST HMAC_SHA3-512.pdf, samples 1–3; SHA3-512 block length is 72 bytes.
my @vectors = (
    [64, 'Sample message for keylen<blocklen',
     '4efd629d6c71bf86162658f29943b1c308ce27cdfa6db0d9c3ce81763f9cbce5f7ebe9868031db1a8f8eb7b6b95e5c5e3f657a8996c86a2f6527e307f0213196'],
    [72, 'Sample message for keylen=blocklen',
     '544e257ea2a3e5ea19a590e6a24b724ce6327757723fe2751b75bf007d80f6b360744bf1b7a88ea585f9765b47911976d3191cf83c039f5ffab0d29cc9d9b6da'],
    [136, 'Sample message for keylen>blocklen',
     '5f464f5e5b7848e3885e49b2c385f0694985d0e38966242dc4a5fe3fea4b37d46b65ceced5dcf59438dd840bab22269f0ba7febdb9fcf74602a35666b2a32915'],
);
for my $v (@vectors) {
    my ($length, $message, $expected) = @$v;
    my $key = pack('C*', 0 .. $length - 1);
    key_file(unpack('H*', $key));
    Foostats::Privacy::load_key($path);
    is(unpack('H*', decode_base64(Foostats::Privacy::digest($message))), $expected,
       "NIST HMAC-SHA3-512 vector, $length-byte key");
    isnt(hmac_hex($message, $key, \&sha3_512, 64), $expected,
         'negative control catches the incorrect default HMAC block size');
}

key_file('ab' x 32);
Foostats::Privacy::load_key($path);
my ($first, $proto) = Foostats::Logreader::anonymize_ip('192.0.2.1');
is($proto, 'IPv4', 'IPv4 classification retained');
is((Foostats::Logreader::anonymize_ip('2001:db8::1'))[1], 'IPv6', 'IPv6 classification retained');
isnt($first, sha3_512_base64('192.0.2.1'), 'no unsalted hash fallback');
my $metadata = Foostats::Privacy::metadata();
Foostats::Privacy::load_key($path);
is((Foostats::Logreader::anonymize_ip('192.0.2.1'))[0], $first, 'same key has stable pseudonyms');
ok(eval { Foostats::Privacy::validate_stats({privacy => $metadata}); 1 }, 'matching dataset accepted');
key_file('ac' x 32);
Foostats::Privacy::load_key($path);
isnt((Foostats::Logreader::anonymize_ip('192.0.2.1'))[0], $first, 'different key changes pseudonym');
ok(!eval { Foostats::Privacy::validate_stats({privacy => $metadata}); 1 }, 'different-key dataset refused');
ok(!eval { Foostats::Privacy::validate_stats({count => {}}); 1 }, 'legacy dataset refused');

for my $bad ('', 'ab' x 8, 'not hex', ('ab' x 32) . "\n\n") {
    key_file($bad);
    ok(!eval { Foostats::Privacy::load_key($path); 1 }, 'invalid key refused');
    ok(!eval { Foostats::Privacy::digest('192.0.2.1'); 1 }, 'failed reload leaves no usable old key');
}
key_file('ab' x 32, 0644);
ok(!eval { Foostats::Privacy::load_key($path); 1 }, 'publicly readable key refused');
unlink $path or die $!;
ok(!eval { Foostats::Privacy::load_key($path); 1 }, 'missing key refused');
key_file('ab' x 32);
symlink $path, "$dir/link" or die $!;
ok(!eval { Foostats::Privacy::load_key("$dir/link"); 1 }, 'symlink key refused');
key_file(('ab' x 2048) . "\n");
ok(eval { Foostats::Privacy::load_key($path); 1 }, 'maximum supported hex key accepts final newline');
key_file('ab' x 2049);
ok(!eval { Foostats::Privacy::load_key($path); 1 }, 'oversized key refused');

mkdir "$dir/public", 0755 or die $!;
ok(!eval { Foostats::FileOutputter->new(stats_dir => "$dir/public"); 1 }, 'world-accessible counter directory refused');
chmod 0770, "$dir/public";
ok(!eval { Foostats::FileOutputter->new(stats_dir => "$dir/public"); 1 }, 'group-writable counter directory refused');
chmod 0700, "$dir/public";
symlink "$dir/public", "$dir/stats-link" or die $!;
ok(!eval { Foostats::FileOutputter->new(stats_dir => "$dir/stats-link"); 1 }, 'symlink counter directory refused');

done_testing;
