#!/usr/bin/perl

use strict;
use warnings;
use Geo::IP;
my $gi = Geo::IP->new(GEOIP_STANDARD);

my $mail_path = "/home/charles/.kde/share/apps/kmail/mail/BlockHost/cur";
chdir $mail_path;
#my $o = `grep -A1 'The following addresses had permanent fatal errors' *`;

opendir(MAIL, ".");
my @mailfile = readdir(MAIL);
closedir(MAIL);

my %blocked;
my %watched;
foreach (@mailfile) {           # on ouvre chauqe fichiers un par un...
    open MAILFILE, $_;
    my @maillines = <MAILFILE>;
    close MAILFILE;
     
    my $bw = ''; 
    foreach (@maillines) {      
        # on regarde pour trouver les Blocked et Watched
        $bw = 'block'  if m/Blocking hosts:/; 
        $bw = 'watch'  if m/Watching hosts:/; 
        $bw = 'expire' if m/Notice: removing expired host:/;

        if ($bw eq 'block') {
            if (m/((?:\d{1,3}\.){3}\d{1,3})/) {
                if (not exists $blocked{$1}) {
                    $blocked{$1} = 1;
                } else {
                    $blocked{$1}++;
                }
            }
        }
       	elsif ($bw eq 'watch') {
            if (m/((?:\d{1,3}\.){3}\d{1,3})/) {
                if (not exists $watched{$1}) {
                    $watched{$1} = 1;
                } else {
                    $watched{$1}++;
                }
            }
        }
###	} elsif ($bw eq 'expire') {
###	
###	} else { 
###	    # junk.
###	}

    }
} 

# épuration blocked dans watched et ajouter au compteur;
#
map { $blocked{$_} += $watched{$_} } keys %blocked;
map { delete $watched{$_} } keys %blocked;

print "Watched: \n";
map { 
   my $c = $gi->country_name_by_addr($_);
   my $bl = &check_rbl($_);
   print $_ . "\t" . $watched{$_} . "\t" . $c . "\t" . $bl . "\n" 
} 
sort { $watched{$a} <=> $watched{$b} } keys %watched; 

# print blocked
print "Blocked: \n";
map { 
   my $c = $gi->country_name_by_addr($_);
   my $bl = &check_rbl($_);
   print $_ . "\t" . $blocked{$_} . "\t" . $c . "\t" . $bl . "\n" 
} 
sort { $blocked{$a} <=> $blocked{$b} } keys %blocked; 


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

