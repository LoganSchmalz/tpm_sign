#!/bin/sh
./gen_policies.sh
rm -f key.*
./gen_keys.sh
rm -f /tmp/*.ctx
cargo run
