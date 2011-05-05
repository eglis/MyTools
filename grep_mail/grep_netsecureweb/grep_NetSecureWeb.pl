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
    print $_ . "\t" . $ips{$_} . "\t" . $c . "\n" 
} 
sort { $ips{$a} <=> $ips{$b} } keys %ips; 


#$country = $gi->country_code_by_addr('24.24.24.24');


