use strict;
use warnings;
use Test::More;

# Ensure the main script can be loaded
require 'foostats.pl';
ok(1, 'loaded foostats.pl');

# Test truncate_url
subtest 'truncate_url' => sub {
    is(Foostats::Reporter::truncate_url('http://example.com', 20), 'http://example.com', 'URL shorter than max length');
    is(Foostats::Reporter::truncate_url('http://example.com/a/very/long/path', 20), 'http:/...y/long/path', 'URL longer than max length');
    is(Foostats::Reporter::truncate_url('12345678901234567890', 20), '12345678901234567890', 'URL equal to max length');
    is(Foostats::Reporter::truncate_url('http://example.com/a/very/long/path', 30), 'http://exa.../a/very/long/path', 'URL with custom max length');
};

subtest 'format_table' => sub {
    my $headers = ['Name', 'Value'];
    my $rows = [
        ['foo', '123'],
        ['bar', '45'],
    ];
    my $expected = <<'TABLE';
|------|-------|
| Name | Value |
|------|-------|
| foo  | 123   |
| bar  | 45    |
|------|-------|
TABLE
    chomp $expected;
    my $got = Foostats::Reporter::format_table($headers, $rows);
    is($got, $expected, 'format_table output is correct');
};

subtest 'gemtext_to_html headings' => sub {
    my $gemtext = "# Title\n## Subtitle\n### Sub-subtitle";
    my $expected = "<h1>Title</h1>\n<h2>Subtitle</h2>\n<h3>Sub-subtitle</h3>\n";
    my $html = Foostats::Reporter::gemtext_to_html($gemtext);
    is($html, $expected, 'Headings are converted correctly');
};

subtest 'gemtext_to_html links' => sub {
    my $gemtext = "=> http://example.com Example";
    my $expected = "<p><a href=\"http://example.com\">Example</a></p>\n";
    my $html = Foostats::Reporter::gemtext_to_html($gemtext);
    is($html, $expected, 'Links are converted correctly');
};

subtest 'gemtext_to_html lists' => sub {
    my $gemtext = "* one\n* two";
    my $expected = "<ul>\n<li>one</li>\n<li>two</li>\n</ul>\n";
    my $html = Foostats::Reporter::gemtext_to_html($gemtext);
    is($html, $expected, 'Lists are converted correctly');
};

subtest 'gemtext_to_html code blocks' => sub {
    my $gemtext = "```\nmy \$code = 1;\n```";
    my $expected = "<pre>\nmy \$code = 1;\n</pre>\n";
    my $html = Foostats::Reporter::gemtext_to_html($gemtext);
    is($html, $expected, 'Code blocks are converted correctly');
};

subtest 'gemtext_to_html ascii tables' => sub {
    my $gemtext = "```\n| a | b |\n|---|---|\n| 1 | 2 |\n```";
    my $expected = "<table>\n<tr>\n  <th>a</th>\n  <th>b</th>\n</tr>\n<tr>\n  <td>1</td>\n  <td>2</td>\n</tr>\n</table>\n";
    my $html = Foostats::Reporter::gemtext_to_html($gemtext);
    is($html, $expected, 'ASCII tables are converted correctly');
};

done_testing();
