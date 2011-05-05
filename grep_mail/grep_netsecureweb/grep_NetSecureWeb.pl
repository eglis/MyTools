#!/usr/bin/perl

use strict;
use warnings;
use Geo::IP;
my $gi = Geo::IP->new(GEOIP_STANDARD);

my $mail_path = "/home/charles/.kde/share/apps/kmail/mail/NetSecureWeb/cur";
chdir $mail_path;
my $o = `grep 'Source IP' *`;

my %ips;
foreach (split /\n/, $o) {
    my ($ip) = $_  =~  m/\"(.+?)\"/;
    if (not exists $ips{$ip}) {
        $ips{$ip} = 1;
    } else {
        $ips{$ip}++;
    }
}

map { 
    my $c = $gi->country_name_by_addr($_);
    my $bl = &check_rbl($_);
    print $_ . "\t" . $ips{$_} . "\t" . $c . "\t" . $bl . "\n" 
} 
sort { $ips{$a} <=> $ips{$b} } keys %ips; 


#$country = $gi->country_code_by_addr('24.24.24.24');
sub check_rbl {
        #rblcheck 218.29.115.152 |grep -v "not listed"
    my $o = '';
    my $ip = shift;
    my $out = `/usr/bin/rblcheck $ip |grep -v "not listed"`;
    if ($out !~ m/^\s*$/) {
        my @o = split /\n/, $out;
        map { s/.+\s([a-zA-Z0-9.]+)$/$1/; } @o;
        $o = join " ", @o;
    }
    return $o;
}

