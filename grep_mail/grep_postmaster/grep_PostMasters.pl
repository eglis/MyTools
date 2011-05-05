#!/usr/bin/perl

use strict;
use warnings;
#use Geo::IP;
#my $gi = Geo::IP->new(GEOIP_STANDARD);

my $mail_path = "/home/charles/.kde/share/apps/kmail/mail/Postmaster/cur";
chdir $mail_path;
my $o = `grep -A1 'The following addresses had permanent fatal errors' *`;

my %mails;
foreach (split /\n/, $o) {
    next if m/^\>/;
    next if m/-----/;
    my ($mail) = $_  =~  m/\<(.+?)\>/;
    next if $mail =~ m/^\s*$/;
    if (not exists $mails{$mail}) {
        $mails{$mail} = 1;
    } else {
        $mails{$mail}++;
    }
}

map { 
    #my $c = $gi->country_name_by_addr($_);
    print $_ . "\t" . $mails{$_} . "\n";
    # . $c . "\n" 
} 
sort { $mails{$a} <=> $mails{$b} } keys %mails; 


#$country = $gi->country_code_by_addr('24.24.24.24');


