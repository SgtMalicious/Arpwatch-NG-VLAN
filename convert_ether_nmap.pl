#!/usr/bin/perl
#
# convert the ethercodes from nmap to arpwatch format
# (C) by Freek/2005
#
#
while(<>) {
	chomp;
	($mac, @info)= split(/ /);
	$x=substr $mac, 0,2;
	$y=substr $mac, 2,2;
	$z=substr $mac, 4, 2;
	print "$x:$y:$z\t@info\n"
}
