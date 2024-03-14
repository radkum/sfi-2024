# SFI 19 - example of basic detection technics

TODO Description

### How to run:
##### HELP
###### cargo build
###### cargo run -- help
###### cargo run -- signature --help
###### cargo run -- signature compile --help
###### cargo run -- signature compile-raw --help
###### cargo run -- signature unpack --help
###### cargo run -- evaluate --help

##### OTHER
###### cargo run -- signature compile -d signatures -o malset.sset
###### cargo run -- signature unpack -s malset.sset -o unpacked_sigs
###### cargo run -- signature compile-raw -d maldir -o raw.sset

###### cargo run -- evaluate -s malset.sset maldir
