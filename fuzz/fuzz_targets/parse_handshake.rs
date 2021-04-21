#![no_main]
use libfuzzer_sys::fuzz_target;

extern crate minecraft_parser;
use minecraft_parser::parse_handshake;

fuzz_target!(|data: &[u8]| {
    // fuzzed code goes here
    let mut data = data.clone();
    parse_handshake(&mut data);
});
