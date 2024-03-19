# SFI 19 - example of basic detection technics

TODO Description

### How to run:
##### HELP
###### cargo build
###### cargo run -- help
###### cargo run -- signature --help
###### cargo run -- signature compile --help
###### cargo run -- evaluate --help

##### OTHER
###### cargo run -- signature compile -s --dir signatures\sha -o malset.sset
###### cargo run -- signature compile -i --dir signatures\heur -o malset.hset
###### cargo run -- signature unpack -s malset.sset -o unpacked_sigs

###### cargo run -- evaluate -s malset.sset maldir
###### cargo run -- evaluate -i malset.hset maldir
###### cargo run -- evaluate -s malset.sset -i malset.hset maldir