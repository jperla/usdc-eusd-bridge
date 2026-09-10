//! JSON stdin/stdout adapter for the auditor-to-Escrow component integration.
use std::io::{self, Read};

fn main() {
    let result = (|| {
        const LIMIT: u64 = 1_048_576;
        let mut input = String::new();
        io::stdin()
            .take(LIMIT + 1)
            .read_to_string(&mut input)
            .map_err(|e| e.to_string())?;
        if input.len() as u64 > LIMIT {
            return Err("audit input exceeds 1 MiB".to_owned());
        }
        e2e::evaluate_json(&input)
    })();
    match result {
        Ok(json) => println!("{json}"),
        Err(error) => {
            eprintln!("auditor-decision: {error}");
            std::process::exit(2);
        }
    }
}
