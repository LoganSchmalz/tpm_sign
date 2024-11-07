#!/bin/sh
./gen_policies.sh
rm key.*
cargo run provision
cargo run
