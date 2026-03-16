mod environ;

const VERSION: &str = env!("CARGO_PKG_VERSION");

fn main() {
    let args: Vec<String> = std::env::args().collect();

    if args.len() == 2 && args[1] == "-v" {
        println!("envps {VERSION}");
        return;
    }

    if args.len() != 2 {
        eprintln!("Usage: envps [-v] <pid>");
        std::process::exit(1);
    }

    let pid: i32 = match args[1].parse() {
        Ok(p) => p,
        Err(_) => {
            eprintln!("Illegal PID: {}", args[1]);
            std::process::exit(1);
        }
    };

    if pid < 0 {
        eprintln!("Illegal PID: {pid}");
        return;
    }

    let env_vars = environ::from_pid(pid);
    for var in &env_vars {
        println!("{var}");
    }
}
