extern crate colored;

use std::fs;
use std::process::{Command, exit};

use colored::Colorize;
use chrono::{Local, Datelike};

use {Error, Config, Criticity, Result, print_error, print_vulnerability, print_warning};
use results::{Results, Vulnerability};

fn parse_month(month_str: &str) -> u32 {
    let month_number = match month_str {
        "Jan" => 1,
        "Feb" => 2,
        "Mar" => 3,
        "Apr" => 4,
        "May" => 5,
        "Jun" => 6,
        "Jul" => 7,
        "Aug" => 8,
        "Sep" => 9,
        "Oct" => 10,
        "Nov" => 11,
        "Dec" => 12,
        _ => 0,
    };

    month_number
}

pub fn certificate_analysis(config: &Config, results: &mut Results) -> Result<()> {
    if config.is_verbose() {
        println!("Reading and analyzing the certificates...")
    }

    let path = format!("{}/{}/original/META-INF/",
                       config.get_dist_folder(),
                       config.get_app_id());
    let dir_iter = try!(fs::read_dir(&path));

    for f in dir_iter {
        let f = match f {
            Ok(f) => f,
            Err(e) => {
                print_warning(format!("An error occurred when reading the \
                                       {}/{}/original/META-INF/ dir searching certificates. \
                                       Certificate analysis will be skipped. More info: {}",
                                      config.get_dist_folder(),
                                      config.get_app_id(),
                                      e),
                              config.is_verbose());
                break;
            }
        };

        let path_file = match f.path().file_name() {
            Some(n) => n.to_os_string().into_string().unwrap(),
            None => String::new(),
        };

        let mut is_cert = false;
        match f.path().extension() {
            None => {}
            Some(e) => {
                if e.to_string_lossy() == "RSA" || e.to_string_lossy() == "DSA" {
                    is_cert = true;
                }
            }
        }

        if is_cert {
            let output = Command::new("openssl")
                .arg("pkcs7")
                .arg("-inform")
                .arg("DER")
                .arg("-in")
                .arg(f.path().to_str().unwrap())
                .arg("-noout")
                .arg("-print_certs")
                .arg("-text")
                .output();

            if output.is_err() {
                print_error(format!("There was an error when executing the openssl command to \
                                     check the certificate: {}",
                                    output.err().unwrap()),
                            config.is_verbose());
                exit(Error::Unknown.into());
            }

            let output = output.unwrap();
            if !output.status.success() {
                print_error(format!("The openssl command returned an error. More info: {}",
                                    String::from_utf8_lossy(&output.stderr[..])),
                            config.is_verbose());
                exit(Error::Unknown.into());
            };

            let cmd = output.stdout;
            if config.is_verbose() {
                println!("The application is signed with the following certificate: {}",
                         path_file.bold());

                println!("{}", String::from_utf8_lossy(&cmd));
            }

            let mut issuer = String::new();
            let mut subject = String::new();
            let mut after = String::new();
            for line in String::from_utf8_lossy(&cmd).lines() {
                if line.contains("Issuer:") {
                    issuer = String::from(line.clone());
                }
                if line.contains("Subject:") {
                    subject = String::from(line.clone());
                }
                if line.contains("Not After :") {
                    after = String::from(line.clone());
                }
            }

            let mut issuer = issuer.split(": ");
            let mut subject = subject.split(": ");
            let mut after = after.split(": ");

            if issuer.nth(1).unwrap().contains("Android Debug") {
                let criticity = Criticity::Critical;
                let description = "The application is signed with the Android Debug Certificate. \
                                   This certificate should never be used for publishing an app.";

                let vuln = Vulnerability::new(criticity,
                                              "Android Debug Certificate",
                                              description,
                                              None as Option<&str>,
                                              None,
                                              None,
                                              None);
                results.add_vulnerability(vuln);

                if config.is_verbose() {
                    print_vulnerability(description, criticity);
                }
            }
            if issuer.nth(1) == subject.nth(1) {
                // TODO: This means it is self signed. Should we do something?
            }

            let now = Local::now();
            let year = now.year();
            let month = now.month();
            let day = now.day();

            let after = after.nth(1).unwrap();
            let cert_year = after[16..20].parse::<i32>().unwrap();
            let cert_month = parse_month(&after[0..3]);
            let cert_day = match after[4..6].parse::<u32>() { //if day<10 parse 1 number
                Ok(n) => n,
                Err(_) => after[5..6].parse::<u32>().unwrap(),
            };

            if year > cert_year || (year == cert_year && month > cert_month) ||
               (year == cert_year && month == cert_month && day > cert_day) {
                let criticity = Criticity::High;
                let description = "The certificate of the application has expired. You should not \
                                   use applications with expired certificates since the app is \
                                   not secure anymore.";

                let vuln = Vulnerability::new(criticity,
                                              "Expired certificate",
                                              description,
                                              None as Option<&str>,
                                              None,
                                              None,
                                              None);
                results.add_vulnerability(vuln);

                if config.is_verbose() {
                    print_vulnerability(description, criticity);
                }
            }
        }
    }

    if config.is_verbose() {
        println!("");
        println!("{}", "The certificates were analyzed correctly!".green());
        println!("");
    } else if !config.is_quiet() {
        println!("Certificates analyzed.");
    }
    Ok(())
}
