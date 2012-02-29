# DECnet hacking

BEGIN {
	n = 0
	sdecnet = "aa:0:4:"
	ldecnet = length(sdecnet)
}

{
	++n
	e[n] = $1
	h[n] = $2
	if (sdecnet == substr($1, 1, ldecnet))
		decnet[$2] = 1
}

END {
	for (i = 1; i <= n; ++i) {
		if (decnet[h[i]] && sdecnet != substr(e[i], 1, ldecnet))
			h[i] = h[i] "-ip"
		print e[i] "\t" h[i]
	}
}
