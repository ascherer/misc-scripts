#!/usr/bin/awk -f
# This AWK programme expects its input in the format created by
# $ gpg --fingerprint --keyring pubring.gpg | sed -e '1,2d'
# It prints its output to stdout.

BEGIN {
	# The individual IDs are treated as multi-line records that are
	# separated by empty lines.
	FS = "\n"; RS = ""

	print "<!DOCTYPE html>\n" \
		"<html lang=\"en\">\n" \
		"<head>\n" \
		"	<meta charset=\"utf-8\"/>\n" \
		"	<title>List of Public Keys</title>\n" \
		"	<style type=\"text/css\">\n" \
		"	.keytype { text-align: center; }\n" \
		"	.fingerprint, .email { font-size: small; }\n" \
		"	.expired { background-color: red; color: yellow; }\n" \
		"	th { padding: 1ex 0.5em; }\n" \
		"	td { padding: 0.5ex 0.5em; }\n" \
		"	table, th, td { border: 1px solid gray; }\n" \
		"	</style>\n" \
		"</head>\n" \
		"<body>\n\n" \
		"<table>\n\n" \
		"<thead>\n" \
		"<tr>\n" \
		"<th>Key ID</th>\n" \
		"<th>User ID(s)</th>\n" \
		"<th>Fingerprint</th>\n" \
		"<th>Keytype</th>\n" \
		"<th>Key Matches?</th>\n" \
		"<th>Owner Matches?</th>\n" \
		"</tr>\n" \
		"</thead>\n\n" \
		"<tbody>"
}

{ # Treat a single record in this block
	sub(/pub[ ]+/, "", $1) # The first line of each entry is the "pub" line
	numelem = split($1, publine, "[ /]")
	keytype = publine[1] # e.g., 1024D for 1024-bit DSA
	keyid = publine[2]
	expired = match(publine[4], /verfallen/) # Change to "expired" if necc.
	typeid = match(keytype,/[A-Z]/) # separate key-length and encryption
	keylength = substr(keytype, 0, typeid-1)
	encryption = substr(keytype, typeid)
	sub(/D/, "DSA", encryption)
	sub(/R/, "RSA", encryption)
	sub(/G/, "El Gamal", encryption)

	print expired ? "<tr class=\"expired\">" : "<tr>"
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
		if (0 == has_email) printf("</b>")
		if (i<NF) printf("<br/>\n<b>") # User has multiple IDs
	}
	print "</td>"

	sub("  ", "<br/>", fingerprint)
	printf("<td class=\"fingerprint\"><code>%s</code></td>\n", fingerprint)

	printf("<td class=\"keytype\">%s<br/>%s</td>\n", keylength, encryption)
	print expired ? "<td><b>Expired!</b></td>" : "<td></td>"
	print "<td></td>\n</tr>"
}

END {
	print "</tbody>\n\n" \
		"</table>\n\n" \
		"</body>\n" \
		"</html>"
}
