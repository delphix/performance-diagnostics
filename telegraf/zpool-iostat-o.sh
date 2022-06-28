#!/bin/bash 
zpool iostat -opy domain0 10 | egrep --line-buffered -v "object|put|\-"

