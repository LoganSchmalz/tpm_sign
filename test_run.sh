#!/bin/sh
./gen_policies.sh
rm key.*
rm /tmp/*.ctx
cargo run provision
cargo run
