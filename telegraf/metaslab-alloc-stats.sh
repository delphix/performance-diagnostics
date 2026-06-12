#!/bin/sh
#
# Wrapper around "estat metaslab-alloc -jm 10" that filters out metrics whose
# "name" tag contains garbage characters (DLPX-88427). A kernel bug causes
# estat to occasionally emit stat names containing raw memory bytes or C macro
# strings. Only names consisting of printable ASCII letters, digits, spaces,
# and common punctuation are passed through.
#
estat metaslab-alloc -jm 10 | grep -E '"name":"[A-Za-z0-9 ,_()/.-]+"'
