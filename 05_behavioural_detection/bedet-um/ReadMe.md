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
###### cargo run -- signature compile -i --dir signatures\bedet -o malset.bset
###### cargo run -- signature unpack -s malset.sset -o unpacked_sigs

###### cargo run -- detection -b malset.bset maldir
###### cli.exe start-detection -b .\malset.bset