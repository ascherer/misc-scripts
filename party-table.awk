#!/usr/bin/awk -f
# This AWK programme expects its input in the format created by
# $ gpg --fingerprint --keyring pubring.gpg | sed -e '1,2d'

BEGIN {
	# The individual IDs are treated as multi-line records that are
	# separated by empty lines.
	FS = "\n"; RS = ""

	print "<!DOCTYPE html>" \
		"<html lang=\"en\">" \
		"<head>" \
		"	<meta charset=\"utf-8\"/>" \
		"	<title>List of Public Keys</title>" \
		"	<style type=\"text/css\">" \
		"	.keytype { text-align: center; }" \
		"	.fingerprint, .email { font-size: small; }" \
		"	.expired { background-color: red; color: yellow; }" \
		"	th { padding: 1ex 0.5em; }" \
		"	td { padding: 0.5ex 0.5em; }" \
		"	table, th, td { border: 1px solid gray; }" \
		"	</style>" \
		"</head>" \
		"<body>" \
		"" \
		"<table>" \
		"" \
		"<thead>" \
		"<tr>" \
		"<th>Key ID</th>" \
		"<th>User ID(s)</th>" \
		"<th>Fingerprint</th>" \
		"<th>Keytype</th>" \
		"<th>Key Matches?</th>" \
		"<th>Owner Matches?</th>" \
		"</tr>" \
		"</thead>" \
		"" \
		"<tbody>"
}

{ # Treat a single record in this block
	sub(/pub[ ]+/, "", $1) # The first line of each entry is the "pub" line
	numelem = split($1, publine, "[ /]")
	keytype = publine[1] # e.g., 1024D for 1024-bit DSA
	keyid = publine[2]
	expired = match(publine[4], /verfallen/) # Change to "expired" if necc.
	typeid = match(keytype,/[A-Z]/) # separate key-length and encryption
	keylength = substr(keytype, 0, typeid)
	encryption = substr(keytype, typeid)
	if (encryption=="D") encryption="DSA"
	if (encryption=="R") encryption="RSA"
	if (encryption=="G") encryption="El Gamal"

	if (expired) print "<tr class=\"expired\">"
	else print "<tr>"
	printf("<td><code>%s</code></td>\n", keyid)

	# The second line of each entry is the "fingerprint"
	split($2, fingerline, " = ")
	fingerprint = fingerline[2]

	# The third and following lines are the "uid" lines
	printf("<td><b>")
	if ($NF ~ /sub/) --NF # The (optional) final "sub"-line is discarded
	for(i=3; i<=NF; ++i)
	{
		sub(/uid[ ]+/, "", $i) # Remove the "uid" part of the data line
		sub(/>/, "\\&gt;</code>", $i)
		has_email = sub(/ </, "</b> <code class=\"email\">\\&lt;", $i)

		printf("%s", $i)
		if (0 == has_email) print "</b>"
		if (i<NF) printf("<br/>\n<b>") # User has multiple IDs
	}
	print "</td>"

	sub("  ", "<br/>", fingerprint)
	printf("<td class=\"fingerprint\"><code>%s</code></td>\n", fingerprint)

	printf("<td class=\"keytype\">%s<br/>%s</td>\n", keylength, encryption)
	if (expired) print "<td><b>Expired!</b></td>"
	else print "<td></td>"
	print "<td></td>" \
		"</tr>"
}

END {
	print "</tbody>" \
		"" \
		"</table>" \
		"" \
		"</body>" \
		"</html>"
}
