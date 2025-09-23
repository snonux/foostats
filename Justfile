set shell := ["bash", "-cu"]

# Format Perl code using perltidy (uses .perltidyrc)
format:
    perltidy foostats.pl

# Run tests via prove if available, otherwise fallback to perl runner
test:
    if command -v prove >/dev/null 2>&1; then \
      prove -lr t; \
    else \
      for f in t/*.t; do echo "== $f =="; PERL5LIB=. perl "$f" || exit 1; done; \
    fi

# Syntax check
check:
    perl -c foostats.pl

clean:
    find . -type f \( -name "*.bak" -o -name "*~" -o -name ".#*" \) -print0 | xargs -0r rm -f

# Generate Gemtext and HTML reports into local directories from local stats
reports:
    mkdir -p out_gmi out_html
    perl foostats.pl --report --stats-dir stats --output-dir out_gmi --html-output-dir out_html
    echo "Generated Gemtext in out_gmi and HTML in out_html"

gather-fooodds:
    @echo Gathering to fooodds.log
    ( \
      ssh rex@fishfinger.buetow.org '(doas cat /var/log/fooodds; doas zcat /var/log/fooodds.*) | sort -u'; \
      ssh rex@blowfish.buetow.org '( doas cat /var/log/fooodds; doas zcat /var/log/fooodds.0*) | sort -u'; \
    ) \
    | grep -F -v 'logfile turned over' \
    | sort -u > fooodds.log
    wc -l fooodds.log
    @echo Now check fooodds.log manually and update fooodds.txt accordingly. Any new paths to block?
    @echo You could use an LLM to add more suspicious enrtries from the fooodds.log to the fooodds.txt file!
