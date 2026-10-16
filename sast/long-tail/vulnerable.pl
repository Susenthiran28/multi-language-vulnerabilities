#!/usr/bin/perl
# File:    vulnerable.pl
# Purpose: SAST fixture (Perl). Command execution, string eval, unsafe thaw,
#          weak hash, unvalidated outbound request.
# Author:  Vigilnz Security Engineering
# Date:    2026-10-16
# Expected rules: perl-system, perl-eval-string, perl-storable-thaw, perl-md5,
#   perl-lwp

use strict;
use warnings;
use Digest::MD5;
use LWP::UserAgent;
use Storable;

my $host = $ARGV[0];

# CWE-78: command injection
system("ping -c 1 $host");
exec("nslookup $host") if $ENV{DO_EXEC};

# CWE-95: string eval on untrusted source
my $code = $ARGV[1];
eval "$code";

# CWE-502: thawing attacker-controlled bytes
sub load_state {
    my ($blob) = @_;
    return Storable::thaw($blob);
}

# CWE-327: broken hash
sub hash_password {
    my ($password) = @_;
    return Digest::MD5::md5_hex($password);
}

# CWE-918: SSRF
sub proxy {
    my ($url) = @_;
    my $ua = LWP::UserAgent->new(ssl_opts => { verify_hostname => 0 });
    return $ua->get($url)->content;
}

1;
