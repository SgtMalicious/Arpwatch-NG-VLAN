#!/bin/sh
#
# Just a little helper script for online-updating the ethercodes from IEEE.
# Thanks to Tom Crane.
#
# Note that arpwatch now usually uses the ethercodes supplied by nmap which
# I consider of better quality because they also contain officially unknowns.

wget -O- http://standards.ieee.org/regauth/oui/oui.txt | ./massagevendor > new_ethercodes.dat
