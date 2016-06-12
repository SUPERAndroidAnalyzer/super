extern crate colored;

use std::fs;
use std::process::{Command, exit};
use std::io::prelude::*;
use std::str::FromStr;

use colored::Colorize;
use chrono::{Local, Datelike};

use {Error, Config, Criticity, print_error, print_vulnerability};
use results::{Results, Vulnerability};

pub fn certificate_analysis(config: &Config, results: &mut Results) {
    if config.is_verbose() {
        println!("Reading and analyzing the certificates...")
    }

    let path = format!("{}/{}/original/META-INF/",
                       config.get_dist_folder(),
                       config.get_app_id());

    //    Why cant I do this???
    //
    //    for entry in fs::read_dir(&certs_dir).unwrap() {
    //        let dir = entry.unwrap();
    //        let dir = dir.path().to_str().unwrap();
    //        if dir.ends_with(".RSA") || dir.ends_with(".DSA"){
    //              ...
    //        }
    //    }

    for entry in fs::read_dir(&path).unwrap() {
        let dir = entry.unwrap();

        if dir.path().to_str().unwrap().ends_with(".RSA") ||
           dir.path().to_str().unwrap().ends_with(".DSA") {

            let output = Command::new("openssl")
                .arg("pkcs7")
                .arg("-inform")
                .arg("DER")
                .arg("-in")
                .arg(dir.path().to_str().unwrap())
                .arg("-noout")
                .arg("-print_certs")
                .arg("-text")
                .output();

            if output.is_err() {
                print_error(format!("There was an error when executing the openssl \
                             command to check the certificate: {}",
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
                         dir.path().file_name().unwrap().to_str().unwrap());

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
                                   This certificate should never use for publishing an app.";

                let vuln = Vulnerability::new(criticity,
                                              "Android Debug Certificate",
                                              description,
                                              dir.path().file_name().unwrap().to_str().unwrap(),
                                              None,
                                              None,
                                              None);
                results.add_vulnerability(vuln);

                if config.is_verbose() {
                    print_vulnerability(description, criticity);
                }
            }
            if issuer.nth(1) == subject.nth(1) {
                // This means it is self signed. Should we do something?
            }

            let now = Local::now();
            let year = now.year();

            if year > FromStr::from_str(&after.nth(1).unwrap()[16..20]).unwrap() {
                // TODO: Also check if the certificate expired months or days ago, not only years
                // need to find a better way to parse the date output of the command
                let criticity = Criticity::High;
                let description = "The certificate of the application has expired. You should not \
                                   use applications with expired certificates since the app is \
                                   not secure anymore.";

                let vuln = Vulnerability::new(criticity,
                                              "Expired certificate",
                                              description,
                                              dir.path().file_name().unwrap().to_str().unwrap(),
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
        println!("Certificates analyzed");
    }
}
