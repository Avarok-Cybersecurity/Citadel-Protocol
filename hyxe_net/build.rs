use std::fs::File;
use std::io::{Read, Write};
use std::str::FromStr;

fn main() {
    let mut buf = String::new();
    let mut file = File::open("../meta.txt").unwrap();
    file.read_to_string(&mut buf).unwrap();
    std::mem::drop(file);
    let mut output = std::io::BufWriter::new(File::create("../meta.txt").unwrap());

    buf.lines().for_each(|line| {
        if line.contains("pub const BUILD_VERSION") {
            let vers = usize::from_str(
                line.split('=').collect::<Vec<&str>>()[1]
                    .replace(";", "")
                    .trim(),
            )
            .unwrap();
            let next_version = vers + 1;
            let replaced_line = format!("pub const BUILD_VERSION: usize = {};", next_version);
            output.write_all(replaced_line.as_bytes()).unwrap();
        } else {
            output.write_all(line.as_bytes()).unwrap();
        }

        output.write_all(b"\n").unwrap();
    });

    output.flush().unwrap();
}
