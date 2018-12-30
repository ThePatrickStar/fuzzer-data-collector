#!/usr/bin/env bash

make

rm -rf test/out/
rm -rf test/out-simple/
rm -rf test/out-entry/

./showmaps -i test/queue -o test/out -q -- ./test/mjs-afl @@

./showmaps -i test/queue -o test/out-simple -q -s -- ./test/mjs-afl @@

./showmaps -i test/queue -o test/out-entry -E