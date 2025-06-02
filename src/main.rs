use chrono::{DateTime, Utc};
use clap::{App, Arg, SubCommand};
use serde::{Deserialize, Serialize};
use std::{
    fs,
    io::{self, Write},
    path::PathBuf,
    process::Command,
};

const SUPERUSER: &str = "admin";
const DEFAULT_DURATION_MINUTES: i64 = 30;

#[derive(Debug, Serialize, Deserialize)]
struct Access {
    ip_address: String,
    server_id: String,
    has_sudo: bool,
    valid_until: Option<DateTime<Utc>>,
}

#[derive(Debug, Serialize, Deserialize)]
struct LoginLog {
    ip_address: String,
    server_id: String,
    timestamp: DateTime<Utc>,
}

#[derive(Debug, Serialize, Deserialize)]
struct AccessLog {
    ip_address: String,
    server_id: String,
    command: String,
    entry_time: DateTime<Utc>,
    exit_time: Option<DateTime<Utc>>,
}

fn main() {
    let matches = App::new("Password Manager CLI")
        .version("0.1")
        .author("Your Name")
        .about("Secure access orchestration")
        .subcommand(
            SubCommand::with_name("login")
                .arg(Arg::with_name("ip").index(1).required(true))
                .arg(Arg::with_name("server").index(2).required(true)),
        )
        .subcommand(
            SubCommand::with_name("grant-access")
                .arg(Arg::with_name("superuser").required(true))
                .arg(Arg::with_name("ip").required(true))
                .arg(Arg::with_name("server").required(true))
                .arg(Arg::with_name("sudo").long("sudo"))
                .arg(
                    Arg::with_name("duration")
                        .long("duration")
                        .takes_value(true),
                ),
        )
        .subcommand(
            SubCommand::with_name("view-access").arg(Arg::with_name("superuser").required(true)),
        )
        .subcommand(
            SubCommand::with_name("revoke-access")
                .arg(Arg::with_name("superuser").required(true))
                .arg(Arg::with_name("ip").required(true))
                .arg(Arg::with_name("server").required(true)),
        )
        .subcommand(
            SubCommand::with_name("view-logs")
                .arg(Arg::with_name("superuser").required(true))
                .arg(
                    Arg::with_name("ip")
                        .long("ip")
                        .takes_value(true)
                        .required(false),
                )
                .arg(
                    Arg::with_name("server")
                        .long("server")
                        .takes_value(true)
                        .required(false),
                ),
        )
        .subcommand(
            SubCommand::with_name("extend-access")
                .arg(Arg::with_name("superuser").required(true))
                .arg(Arg::with_name("ip").required(true))
                .arg(Arg::with_name("server").required(true))
                .arg(Arg::with_name("duration").required(true)),
        )
        .subcommand(
            SubCommand::with_name("shell")
                .arg(Arg::with_name("ip").required(true))
                .arg(Arg::with_name("server").required(true)),
        )
        .get_matches();

    if let Some(matches) = matches.subcommand_matches("login") {
        let ip = matches.value_of("ip").unwrap();
        let server = matches.value_of("server").unwrap();
        handle_login(ip, server);
        auto_grant_access_if_needed(ip, server);
    } else if let Some(matches) = matches.subcommand_matches("grant-access") {
        let superuser = matches.value_of("superuser").unwrap();
        if superuser != SUPERUSER {
            eprintln!("Only superuser can grant access.");
            return;
        }
        let ip = matches.value_of("ip").unwrap();
        let server = matches.value_of("server").unwrap();
        let has_sudo = matches.is_present("sudo");
        let duration = matches
            .value_of("duration")
            .map(|d| Utc::now() + chrono::Duration::minutes(d.parse::<i64>().unwrap()));
        handle_grant_access(ip, server, has_sudo, duration);
    } else if let Some(matches) = matches.subcommand_matches("view-access") {
        let superuser = matches.value_of("superuser").unwrap();
        if superuser != SUPERUSER {
            eprintln!("Only superuser can view access.");
            return;
        }
        view_access();
    } else if let Some(matches) = matches.subcommand_matches("revoke-access") {
        let superuser = matches.value_of("superuser").unwrap();
        if superuser != SUPERUSER {
            eprintln!("Only superuser can revoke access.");
            return;
        }
        let ip = matches.value_of("ip").unwrap();
        let server = matches.value_of("server").unwrap();
        revoke_access(ip, server);
    } else if let Some(matches) = matches.subcommand_matches("view-logs") {
        let superuser = matches.value_of("superuser").unwrap();
        if superuser != SUPERUSER {
            eprintln!("Only superuser can view logs.");
            return;
        }
        let ip = matches.value_of("ip");
        let server = matches.value_of("server");
        view_logs(ip, server);
    }else if let Some(matches) = matches.subcommand_matches("extend-access") {
        let superuser = matches.value_of("superuser").unwrap();
        if superuser != SUPERUSER {
            eprintln!("Only superuser can extend access.");
            return;
        }
        let ip = matches.value_of("ip").unwrap();
        let server = matches.value_of("server").unwrap();
        let duration = matches.value_of("duration").unwrap().parse::<i64>().unwrap_or(0);
        extend_access(ip, server, duration);
    }else if let Some(matches) = matches.subcommand_matches("shell") {
        let ip = matches.value_of("ip").unwrap();
        let server = matches.value_of("server").unwrap();
        launch_monitored_shell(ip, server);
    }
}

fn handle_login(ip: &str, server: &str) {
    let log = LoginLog {
        ip_address: ip.to_string(),
        server_id: server.to_string(),
        timestamp: Utc::now(),
    };
    let log_path = PathBuf::from("login_logs.jsonl");
    let mut file = fs::OpenOptions::new()
        .append(true)
        .create(true)
        .open(&log_path)
        .expect("Unable to open login log file");
    let serialized = serde_json::to_string(&log).unwrap();
    writeln!(file, "{}", serialized).unwrap();
}

fn handle_grant_access(ip: &str, server: &str, has_sudo: bool, valid_until: Option<DateTime<Utc>>) {
    let access = Access {
        ip_address: ip.to_string(),
        server_id: server.to_string(),
        has_sudo,
        valid_until,
    };
    let path = PathBuf::from("access_control.json");
    let mut data: Vec<Access> = if path.exists() {
        let content = fs::read_to_string(&path).unwrap();
        serde_json::from_str(&content).unwrap_or_default()
    } else {
        Vec::new()
    };
    data.push(access);
    fs::write(path, serde_json::to_string_pretty(&data).unwrap()).unwrap();
    println!("Access granted to IP {} on server {}", ip, server);
}

fn view_access() {
    let path = PathBuf::from("access_control.json");
    if !path.exists() {
        println!("No access records found.");
        return;
    }
    let content = fs::read_to_string(&path).unwrap();
    let data: Vec<Access> = serde_json::from_str(&content).unwrap_or_default();
    for access in data {
        println!(
            "IP: {}, Server: {}, Sudo: {}, Valid Until: {:?}",
            access.ip_address, access.server_id, access.has_sudo, access.valid_until
        );
    }
}

fn revoke_access(ip: &str, server: &str) {
    let path = PathBuf::from("access_control.json");

    if !path.exists() {
        println!("Access control file not found.");
        return;
    }

    let content = fs::read_to_string(&path).unwrap();
    let mut access_list: Vec<Access> = serde_json::from_str(&content).unwrap_or_default();

    let original_len = access_list.len();
    access_list.retain(|entry| !(entry.ip_address == ip && entry.server_id == server));

    if access_list.len() == original_len {
        println!(
            "No matching access found for IP {} on server {}",
            ip, server
        );
    } else {
        fs::write(&path, serde_json::to_string_pretty(&access_list).unwrap()).unwrap();
        println!("Access revoked for IP {} on server {}", ip, server);
    }
}

fn extend_access(ip: &str, server: &str, duration: i64) {
    let path = PathBuf::from("access_control.json");
    if !path.exists() {
        eprintln!("Access control file not found.");
        return;
    }
    let content = fs::read_to_string(&path).unwrap();
    let mut data: Vec<Access> = serde_json::from_str(&content).unwrap_or_default();
    let now = Utc::now();

    let mut found = false;
    for entry in &mut data {
        if entry.ip_address == ip && entry.server_id == server {
            entry.valid_until = Some(now + chrono::Duration::minutes(duration));
            println!("Access for {} on {} extended by {} minutes.", ip, server, duration);
            found = true;
        }
    }
    if !found {
        println!("No access record found for IP {} on server {}", ip, server);
    } else {
        fs::write(&path, serde_json::to_string_pretty(&data).unwrap()).unwrap();
    }
}

fn view_logs(ip_filter: Option<&str>, server_filter: Option<&str>) {
    let path = PathBuf::from("all_commands.jsonl");
    if !path.exists() {
        println!("No command logs found.");
        return;
    }

    let content = fs::read_to_string(&path).unwrap();
    for line in content.lines() {
        let log: AccessLog = serde_json::from_str(line).unwrap();
        if ip_filter.map_or(true, |ip| ip == log.ip_address)
            && server_filter.map_or(true, |server| server == log.server_id)
        {
            println!(
                "[{}] {}@{} ran: {}",
                log.entry_time, log.ip_address, log.server_id, log.command
            );
        }
    }
}

fn auto_grant_access_if_needed(ip: &str, server: &str) {
    let path = PathBuf::from("access_control.json");
    let mut data: Vec<Access> = if path.exists() {
        let content = fs::read_to_string(&path).unwrap();
        serde_json::from_str(&content).unwrap_or_default()
    } else {
        Vec::new()
    };

    let exists = data.iter().any(|a| {
        a.ip_address == ip
            && a.server_id == server
            && a.valid_until.map(|v| v > Utc::now()).unwrap_or(false)
    });

    if !exists {
        let new_access = Access {
            ip_address: ip.to_string(),
            server_id: server.to_string(),
            has_sudo: false,
            valid_until: Some(Utc::now() + chrono::Duration::minutes(DEFAULT_DURATION_MINUTES)),
        };
        data.push(new_access);
        fs::write(&path, serde_json::to_string_pretty(&data).unwrap()).unwrap();
        println!(
            "Automatically granted temporary access to IP {} for server {}",
            ip, server
        );
    }
}

fn launch_monitored_shell(ip: &str, server: &str) {
    println!(
        "Launching monitored shell for IP '{}' on server '{}'...",
        ip, server
    );

    loop {
        print!("{}@{}$ ", ip, server);
        io::stdout().flush().unwrap();
        let mut input = String::new();
        if io::stdin().read_line(&mut input).is_err() {
            break;
        }
        let command = input.trim();
        if command == "exit" {
            println!("Exiting monitored shell.");
            break;
        }
        let entry_time = Utc::now();
        let output = Command::new("sh").arg("-c").arg(command).output();
        let exit_time = Utc::now();

        match output {
            Ok(output) => {
                io::stdout().write_all(&output.stdout).unwrap();
                io::stderr().write_all(&output.stderr).unwrap();
            }
            Err(e) => {
                eprintln!("Failed to execute command: {}", e);
            }
        }

        let log = AccessLog {
            ip_address: ip.to_string(),
            server_id: server.to_string(),
            command: command.to_string(),
            entry_time,
            exit_time: Some(exit_time),
        };
        let mut file = fs::OpenOptions::new()
            .append(true)
            .create(true)
            .open("all_commands.jsonl")
            .expect("Failed to open command log");
        let serialized = serde_json::to_string(&log).unwrap();
        writeln!(file, "{}", serialized).unwrap();

        let session_file = format!(
            "user_logs/{}_{}.jsonl",
            ip.replace(".", "_"),
            entry_time.format("%Y%m%dT%H%M%S")
        );
        fs::create_dir_all("user_logs").unwrap();
        let mut user_file = fs::OpenOptions::new()
            .append(true)
            .create(true)
            .open(session_file)
            .expect("Failed to open user session log");
        writeln!(user_file, "{}", serialized).unwrap();
    }
}
