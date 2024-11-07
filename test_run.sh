#!/bin/sh
./gen_policies.sh
cargo run provision
cargo run
