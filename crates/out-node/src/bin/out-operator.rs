#![forbid(unsafe_code)]

#[cfg(unix)]
fn main() {
    use std::io;

    use out_node::cli::{
        parse_operator_arguments, read_operator_key, run_operator_client, OPERATOR_USAGE,
    };
    use out_node::operator::OperatorReply;

    let arguments: Vec<String> = std::env::args().skip(1).collect();
    if arguments.as_slice() == ["--help"] {
        println!("{OPERATOR_USAGE}");
        println!("account fields: <recipient-hex>");
        println!("submit-tx fields: <canonical-signed-transaction-hex>");
        println!("start/refresh fields: <timestamp> <local-now> <recipient-hex> <reward-extra-hex|-> <first-nonce>");
        println!("Read one 64-character lowercase operator-key hex line from standard input.");
        return;
    }
    let config = match parse_operator_arguments(arguments) {
        Ok(config) => config,
        Err(error) => {
            eprintln!("invalid arguments: {error:?}");
            eprintln!("{OPERATOR_USAGE}");
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
    match run_operator_client(&config, &key) {
        Ok(response) => {
            println!(
                "sequence={} command={} reply={:?}",
                response.sequence, response.command_tag, response.reply
            );
            if matches!(response.reply, OperatorReply::Rejected(_)) {
                std::process::exit(3);
            }
        }
        Err(error) => {
            eprintln!("operator request failed: {error:?}");
            std::process::exit(1);
        }
    }
}

#[cfg(not(unix))]
fn main() {
    eprintln!("out-operator requires Unix-domain sockets");
    std::process::exit(2);
}
