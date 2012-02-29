# Only print the first ethernet address seen

{
	e = $1
	if (seen[e])
		next
	seen[e] = 1
	print
}
