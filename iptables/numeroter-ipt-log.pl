#!/usr/bin/perl

#
# Charles Lacroix
#
# Petit script pour numéroter le /etc/sysconfig/iptables 
# afin de savoir quel règle nous bloque. 
# 
# Un search & replace bête et stupide. 
#
# Le script pourrait être améliorer facilement pour attrapper le
# ...  --log-prefix "(.+?)" et y concaténer un Id unique.
# 
# Il pourrait aussi jourer directement sur le bon fichier
# mais je préfère travailler sur une copie.
#

use strict;
use warnings;

open IPT, "iptables";
my @ipt = <IPT>;
close IPT;
open IPTO, ">iptables-2";

my $c = 1;
foreach (@ipt) {
    chomp;
    if (m/NP-LOG/) {
        s/NP-LOG/NP-LOG-$c/;
        $c++;
    }
    print IPTO $_ . "\n";
}
close IPTO;


