#![forbid(unsafe_code)]

#[cfg(unix)]
fn main() {
    use std::io;

    use out_node::cli::{parse_node_arguments, read_operator_key, NODE_USAGE};
    use out_node::process::run_local_node_process;

    let arguments: Vec<String> = std::env::args().skip(1).collect();
    if arguments.as_slice() == ["--help"] {
        println!("{NODE_USAGE}");
        println!("Read one 64-character lowercase operator-key hex line from standard input.");
        return;
    }
    let config = match parse_node_arguments(arguments) {
        Ok(config) => config,
        Err(error) => {
            eprintln!("invalid arguments: {error:?}");
            eprintln!("{NODE_USAGE}");
            std::process::exit(2);
        }
    };
    let key = match read_operator_key(io::stdin().lock()) {
        Ok(key) => key,
        Err(error) => {
            eprintln!("invalid operator key from standard input: {error:?}");
            std::process::exit(2);
        }
    };
    if let Err(error) = run_local_node_process(config, key) {
        eprintln!("local node stopped with an error: {error:?}");
        std::process::exit(1);
    }
}

#[cfg(not(unix))]
fn main() {
    eprintln!("out-node-local requires Unix-domain sockets");
    std::process::exit(2);
}
