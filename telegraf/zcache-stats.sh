#!/bin/bash
zcache stats -ap 10 | egrep --line-buffered -v "\-"

