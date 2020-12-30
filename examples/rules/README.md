To generate rules from Coreruleset

* run genrules.sh - `./genrules.sh`
* Point ISA rules location to this folder when starting: `docker run -p 12345:9000 -v $PWD/examples/rules/conf:/rules/ isa:lala --modsec-rules=/rules/modsecurity.conf` 
