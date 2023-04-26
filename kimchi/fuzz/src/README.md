## Run the fuzzer in main

To run the fuzzer:
* Step on the fuzz folder placed in kimchi folder.
* set the manifest path var with the command `export CARGO_MANIFEST_DIR=/root/kimchi-fuzz/srs`.
* Use the command `HFUZZ_RUN_ARGS="-t=3600" cargo hfuzz run kimchi-fuzz` to run the fuzzer.