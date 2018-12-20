#!/usr/bin/env bash

make

rm -rf test/out/

./showmaps -i test/queue -o test/out -q -- ./test/mjs-afl @@