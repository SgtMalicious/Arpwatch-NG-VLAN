# Add -old suffix to ethers file, as required. Assumed sorted input

{
	if (!seen[$2]) {
		seen[$2] = 1
		print
		next
	}
	h = $2 "-old"
	s = h
	for (n = 1; seen[h]; ++n)
		h = s n
	seen[h] = 1
	print $1 "\t" h
	next
}
