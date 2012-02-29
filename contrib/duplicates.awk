# combine company info for duplciate vendor codes

BEGIN {
	str = ""
	lastv = ""
}

{
	v = $1
	if (v == lastv) {
		i = index($0, "	")
		# XXX probably can't happen
		if (i <= 0)
			i = 0
		str = str " *also* " substr($0, i + 1)
	} else {
		if (str != "")
			print str
		str = $0
	}
	lastv = v

}

END {
	if (str != "")
		print str
}
