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

subtest 'gemtext_to_html expands truncated URLs' => sub {
    Foostats::Reporter::reset_truncated_url_mappings();
    my $original_url = 'https://example.com/a/really/long/path/that/should/get/truncated/because/it/exceeds/the/limit.html';
    my $rows         = [ [ $original_url, '12' ] ];
    Foostats::Reporter::truncate_urls_for_table($rows, 'Visitors');
    my $table   = Foostats::Reporter::format_table([ 'URL', 'Visitors' ], $rows);
    my $gemtext = "```\n$table\n```";
    my $html    = Foostats::Reporter::gemtext_to_html($gemtext);
    like($html,
        qr{<a href=\"https://example.com/a/really/long/path/that/should/get/truncated/because/it/exceeds/the/limit\.html\">https://example.com/a/really/long/path/that/should/get/truncated/because/it/exceeds/the/limit\.html</a>},
        'HTML renders full URL without ellipsis');
    Foostats::Reporter::reset_truncated_url_mappings();
};

subtest 'build_top_urls_section limits to top 10' => sub {
    Foostats::Reporter::reset_truncated_url_mappings();
    my %urls = map { ("https://example.com/page$_" => 100 - $_) } 1 .. 25;
    my $section = Foostats::Reporter::build_top_urls_section(\%urls, 30);
    like($section, qr/Top 10 URLs \(30-Day Total\)/, 'title is Top 10');
    like($section, qr/truncated to 10 entries/,         'notes truncation to 10');
    my @data_rows = grep { /^\| https:\/\// } split /\n/, $section;
    is(scalar @data_rows, 10, 'renders exactly 10 URL rows');
    unlike($section, qr/Top 50 URLs/, 'does not say Top 50');
    for my $n (1 .. 10) {
        like($section, qr/page$n\b/, "includes ranked URL page$n");
    }
    for my $n (11 .. 25) {
        unlike($section, qr/page$n\b/, "excludes ranked URL page$n");
    }
    my @visitors;
    for my $row (@data_rows) {
        if ($row =~ /\|\s*(\d+)\s*\|/) {
            push @visitors, 0 + $1;
        }
    }
    is(scalar @visitors, 10, 'parsed visitor count for every row');
    is_deeply(\@visitors, [ 99, 98, 97, 96, 95, 94, 93, 92, 91, 90 ],
        'visitor counts are the top 10 descending values');

    # Boundary: exactly 10 URLs must not claim truncation
    my %exact = map { ("https://example.com/exact$_" => 50 - $_) } 1 .. 10;
    my $exact_section = Foostats::Reporter::build_top_urls_section(\%exact, 30);
    unlike($exact_section, qr/truncated to 10 entries/, 'no truncation note at exact limit');
    my @exact_rows = grep { /^\| https:\/\// } split /\n/, $exact_section;
    is(scalar @exact_rows, 10, 'renders all 10 URLs at exact limit');

    # Negative: fewer than 10 URLs must not claim truncation
    my %few = map { ("https://example.com/few$_" => $_) } 1 .. 3;
    my $few_section = Foostats::Reporter::build_top_urls_section(\%few, 30);
    unlike($few_section, qr/truncated to 10 entries/, 'no truncation note when under limit');
    my @few_rows = grep { /^\| https:\/\// } split /\n/, $few_section;
    is(scalar @few_rows, 3, 'renders all URLs when under limit');
    Foostats::Reporter::reset_truncated_url_mappings();
};

done_testing();
