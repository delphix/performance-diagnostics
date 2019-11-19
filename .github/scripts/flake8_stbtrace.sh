#/bin/bash
#
# Copyright (c) 2020 by Delphix. All rights reserved.
#
# SPDX-License-Identifier: GPL-2.0-or-later
#

#
# This provides flake8 linting for the various stbtrace templates. It uses
# stbtrace with the '--bcc' flag to produce and print Python code, and then
# runs flake8 against that.
#

set -o pipefail

function die() {
        echo "$(basename "$0"): $*" >&2
        exit 1
}

prgms=$(find ./bpf/stbtrace -name '*.st' | xargs basename --suffix='.st') ||
	die "Failed to generate list of stbtrace programs"

for prgm in $prgms; do
	echo "Checking stbtrace program $prgm..."
	./cmd/stbtrace.py $prgm --bcc >/tmp/$prgm.py ||
		die "Failed to generate python source"
	flake8 /tmp/$prgm.py --show-source || die "flake8 errors found in" \
		"'bpf/stbtrace/$prgm.st'. Line numbers in error messages" \
		"correspond to the output of './cmd/stbtrace.py $prgm --bcc'"
done

exit 0
