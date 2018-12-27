#!/usr/bin/env bash

make

rm -rf test/out/
rm -rf test/out-simple/

./showmaps -i test/queue -o test/out -q -- ./test/mjs-afl @@

./showmaps -i test/queue -o test/out-simple -q -s -- ./test/mjs-afl @@