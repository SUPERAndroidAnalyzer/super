//! Tests for the code analysis.
#![allow(clippy::trivial_regex)]

use super::{load_rules, Rule};
use crate::config::Config;
use anyhow::Error;
use regex::Regex;

/// Prints information about the given error.
fn print_error(e: &Error) {
    eprintln!("Error: {}", e);

    let mut source = e.source();
    while let Some(e) = source {
        eprintln!("\tCaused by: {}", e);
        source = e.source();
    }
}

fn check_match<S: AsRef<str>>(text: S, rule: &Rule) -> bool {
    if rule.regex().is_match(text.as_ref()) {
        for white in rule.whitelist() {
            if white.is_match(text.as_ref()) {
                let m = white.find(text.as_ref()).unwrap();
                println!(
                    "Whitelist '{}' matches the text '{}' in '{}'",
                    white.as_str(),
                    text.as_ref(),
                    &text.as_ref()[m.start()..m.end()]
                );
                return false;
            }
        }
        match rule.forward_check() {
            None => {
                let m = rule.regex().find(text.as_ref()).unwrap();
                println!(
                    "The regular expression '{}' matches the text '{}' in '{}'",
                    rule.regex(),
                    text.as_ref(),
                    &text.as_ref()[m.start()..m.end()]
                );
                true
            }
            Some(check) => {
                let caps = rule.regex().captures(text.as_ref()).unwrap();

                let forward_check1 = caps.name("fc1");
                let forward_check2 = caps.name("fc2");
                let mut r = check.clone();

                if let Some(fc1) = forward_check1 {
                    r = r.replace("{fc1}", fc1.as_str());
                }

                if let Some(fc2) = forward_check2 {
                    r = r.replace("{fc2}", fc2.as_str());
                }

                let regex = Regex::new(r.as_str()).unwrap();
                if regex.is_match(text.as_ref()) {
                    let m = regex.find(text.as_ref()).unwrap();
                    println!(
                        "The forward check '{}'  matches the text '{}' in '{}'",
                        regex.as_str(),
                        text.as_ref(),
                        &text.as_ref()[m.start()..m.end()]
                    );
                    true
                } else {
                    println!(
                        "The forward check '{}' does not match the text '{}'",
                        regex.as_str(),
                        text.as_ref()
                    );
                    false
                }
            }
        }
    } else {
        println!(
            "The regular expression '{}' does not match the text '{}'",
            rule.regex(),
            text.as_ref()
        );
        false
    }
}

#[test]
fn it_url_regex() {
    let config = Config::default();
    let rules = match load_rules(&config) {
        Ok(r) => r,
        Err(e) => {
            print_error(&e);
            panic!()
        }
    };
    let rule = &rules[0];

    let should_match = &[
        "\"http://www.razican.com\"",
        "\"https://razican.com\"",
        "\"http://www.razican.com/hello\"",
        "\"//www.razican.com/hello\"",
        "\"ftp://ftp.razican.com/hello\"",
    ];
    let should_not_match = &[
        "\"android.intent.extra.EMAIL\"",
        "\"hello\"",
        "\"http://schemas.android.com/apk/res/android\"",
        "\"http://www.w3.org/2005/Atom\"",
    ];

    for m in should_match {
        assert!(check_match(m, rule));
    }

    for m in should_not_match {
        assert!(!check_match(m, rule));
    }
}

#[test]
fn it_catch_exception() {
    let config = Config::default();
    let rules = match load_rules(&config) {
        Ok(r) => r,
        Err(e) => {
            print_error(&e);
            panic!()
        }
    };
    let rule = &rules[1];

    let should_match = &[
        "catch (Exception e) {",
        "catch (Exception hello) {",
        "catch( Exception e ){",
        "catch (IOException|Exception e) {",
        "catch (Exception|IOException e) {",
        "catch (IOException | Exception e) {",
        "catch (IOException|Exception|MyTestException e) {",
        "catch (SystemException|ApplicationException|MyTestException e) {",
        "catch (IOException|Exception | MyTestException e) {",
    ];
    let should_not_match = &[
        "catch (IOException e) {",
        "catch (IOException|MyTestException e) {",
    ];

    for m in should_match {
        assert!(check_match(m, rule));
    }

    for m in should_not_match {
        assert!(!check_match(m, rule));
    }
}

#[test]
fn it_throws_exception() {
    let config = Config::default();
    let rules = match load_rules(&config) {
        Ok(r) => r,
        Err(e) => {
            print_error(&e);
            panic!()
        }
    };
    let rule = &rules[2];

    let should_match = &[
        "throws Exception {",
        "throws Exception, IOException {",
        "throws IOException, Exception {",
        "throws Exception,IOException{",
        "throws IOException,Exception{",
        "throws SystemException,Exception{",
        "throws ApplicationException,Exception{",
        "throws SomeException, Exception, IOException {",
    ];
    let should_not_match = &[
        "throws IOException {",
        "throws SomeException, IOException {",
    ];

    for m in should_match {
        assert!(check_match(m, rule));
    }

    for m in should_not_match {
        assert!(!check_match(m, rule));
    }
}

#[test]
fn it_hidden_fields() {
    let config = Config::default();
    let rules = match load_rules(&config) {
        Ok(r) => r,
        Err(e) => {
            print_error(&e);
            panic!()
        }
    };
    let rule = &rules[3];

    let should_match = &[
        "setVisible(View.INVISIBLE)",
        "setVisible ( View.invisible )",
        "android:visibility = \"invisible\"",
        "android:background = \"NULL\"",
        "android:background=\"null\"",
        "android:background = \"@null\"",
    ];
    let should_not_match = &["android:background = \"@color/red\""];

    for m in should_match {
        assert!(check_match(m, rule));
    }

    for m in should_not_match {
        assert!(!check_match(m, rule));
    }
}

#[test]
fn it_ipv4_disclosure() {
    let config = Config::default();
    let rules = match load_rules(&config) {
        Ok(r) => r,
        Err(e) => {
            print_error(&e);
            panic!()
        }
    };
    let rule = &rules[4];

    let should_match = &[
        " 192.168.1.1",
        " 0.0.0.0",
        " 255.255.255.255",
        " 13.0.130.23.52",
    ];
    let should_not_match = &[
        "0000.000.000.000",
        "256.140.123.154",
        "135.260.120.0",
        "50.75.300.35",
        "60.35.59.300",
        ".5.6.7",
        "115..35.5",
        "155.232..576",
        "123.132.123.",
        "123.124.123",
    ];

    for m in should_match {
        assert!(check_match(m, rule));
    }

    for m in should_not_match {
        assert!(!check_match(m, rule));
    }
}

#[test]
fn it_math_random() {
    let config = Config::default();
    let rules = match load_rules(&config) {
        Ok(r) => r,
        Err(e) => {
            print_error(&e);
            panic!()
        }
    };
    let rule = &rules[5];

    let should_match = &["Math.random()", "Random()", "Math . random ()"];
    let should_not_match = &[
        "math.random()",
        "MATH.random()",
        "Math.Randomize()",
        "Mathrandom()",
        "Math.random",
    ];

    for m in should_match {
        assert!(check_match(m, rule));
    }

    for m in should_not_match {
        assert!(!check_match(m, rule));
    }
}

#[test]
fn it_log() {
    let config = Config::default();
    let rules = match load_rules(&config) {
        Ok(r) => r,
        Err(e) => {
            print_error(&e);
            panic!()
        }
    };
    let rule = &rules[6];

    let should_match = &[
        "Log.d(\"Diva-sqli\", \"Error occurred while searching in database: \
             \" + messageToShow);",
        " Log.d(\"Diva-sqli\", \"Error occurred while searching in \
             database: \" + messageToShow + msg1 +  msg2 + msg3);",
        " Log.d(\"Diva-sqli\", \"Error occurred while searching in \
             database: \" + messageToShow + msg1 +  msg2 + msg3);",
        " Log.d(\"Diva-sqli\", \"Error occurred while searching in \
             database: \" + messageToShow + msg1 +  msg2 + msg3);",
    ];

    let should_not_match = &[
        "Log.e(\"Hello!\")",
        "Log.e(\"Hello: \" + var)",
        "Log.e(\"Hello: \" +var)",
        "Log.wtf(\"Hello: \"+var)",
        "Log.i(var)",
        "Log.println(\"Hello: \" + var + \" goodbye\")",
    ];

    for m in should_match {
        assert!(check_match(m, rule));
    }

    for m in should_not_match {
        assert!(!check_match(m, rule));
    }
}

#[test]
fn it_file_separator() {
    let config = Config::default();
    let rules = match load_rules(&config) {
        Ok(r) => r,
        Err(e) => {
            print_error(&e);
            panic!()
        }
    };
    let rule = &rules[7];

    let should_match = &[
        "C:\\",
        "C:\\Programs\\password.txt",
        "D:\\",
        "H:\\P\\o\\password.txt",
    ];

    let should_not_match = &["ome\\password.txt", "at:\\", "\\\\home\\sharedfile", "\\n"];

    for m in should_match {
        assert!(check_match(m, rule));
    }

    for m in should_not_match {
        assert!(!check_match(m, rule));
    }
}

#[test]
fn it_weak_algorithms() {
    let config = Config::default();
    let rules = match load_rules(&config) {
        Ok(r) => r,
        Err(e) => {
            print_error(&e);
            panic!()
        }
    };
    let rule = &rules[8];

    let should_match = &[
        "DESKeySpec",
        "getInstance(MD5)",
        "getInstance(\"MD5\")",
        "getInstance(SHA-1)",
        "getInstance(\"SHA-1\")",
        "getInstance(\"MD4\")",
        "getInstance(\"RC2\")",
        "getInstance(\"md4\")",
        "getInstance(\"rc2\")",
        "getInstance(\"rc4\")",
        "getInstance(\"RC4\")",
        "getInstance(\"AES/ECB\")",
        "getInstance(\"RSA/ECB/nopadding\")",
        "getInstance(\"rsa/ECB/nopadding\")",
    ];

    let should_not_match = &["", "", "", ""];

    for m in should_match {
        assert!(check_match(m, rule));
    }

    for m in should_not_match {
        assert!(!check_match(m, rule));
    }
}

#[test]
fn it_sleep_method() {
    let config = Config::default();
    let rules = match load_rules(&config) {
        Ok(r) => r,
        Err(e) => {
            print_error(&e);
            panic!()
        }
    };
    let rule = &rules[9];

    let should_match = &[
        "Thread.sleep(Usertime+Variable+Variable);",
        "Thread.sleep(Usertime+13+123+1+24);",
        "Thread . sleep (200+var1+var2 );",
        "Thread . sleep (200+var1+var2+30 );",
        "Thread.sleep(10 + 10 + 10241 + Usertime);",
        "SystemClock.sleep(Usertime);",
    ];

    let should_not_match = &[
        "Thread.sleep(2000);",
        "Thread.sleep(\"1000\" + Usertime);",
        "Thread.sleep();",
        "SystemClock.sleep(1000);",
    ];

    for m in should_match {
        assert!(check_match(m, rule));
    }

    for m in should_not_match {
        assert!(!check_match(m, rule));
    }
}

#[test]
fn it_world_readable_permissions() {
    let config = Config::default();
    let rules = match load_rules(&config) {
        Ok(r) => r,
        Err(e) => {
            print_error(&e);
            panic!()
        }
    };
    let rule = &rules[10];

    let should_match = &[
        "MODE_WORLD_READABLE",
        "openFileOutput(\"file.txt  \", 1) ",
        "openFileOutput(\"filename\", 1) ",
        "openFileOutput(filepath, 1) ",
        "openFileOutput(path_to_file, 1) ",
    ];

    let should_not_match = &[
        "openFileOutput(\"file.txt\", 0) ",
        "openFileOutput(, 1) ",
        "openFileOutput() ",
        "",
    ];

    for m in should_match {
        assert!(check_match(m, rule));
    }

    for m in should_not_match {
        assert!(!check_match(m, rule));
    }
}

#[test]
fn it_world_writable_permissions() {
    let config = Config::default();
    let rules = match load_rules(&config) {
        Ok(r) => r,
        Err(e) => {
            print_error(&e);
            panic!()
        }
    };
    let rule = &rules[11];

    let should_match = &[
        "MODE_WORLD_WRITABLE",
        "openFileOutput(\"file.txt  \", 2) ",
        "openFileOutput(\"filename\", 2) ",
        "openFileOutput(filepath, 2) ",
        "openFileOutput(path_to_file, 2) ",
    ];

    let should_not_match = &[
        "openFileOutput(\"file.txt\", 0) ",
        "openFileOutput(, 2) ",
        "openFileOutput() ",
        "",
    ];

    for m in should_match {
        assert!(check_match(m, rule));
    }

    for m in should_not_match {
        assert!(!check_match(m, rule));
    }
}

#[test]
fn it_external_storage_write_read() {
    let config = Config::default();
    let rules = match load_rules(&config) {
        Ok(r) => r,
        Err(e) => {
            print_error(&e);
            panic!()
        }
    };
    let rule = &rules[12];

    let should_match = &[".getExternalStorage", ".getExternalFilesDir()"];

    let should_not_match = &["", "", "", ""];

    for m in should_match {
        assert!(check_match(m, rule));
    }

    for m in should_not_match {
        assert!(!check_match(m, rule));
    }
}

#[test]
fn it_temp_file() {
    let config = Config::default();
    let rules = match load_rules(&config) {
        Ok(r) => r,
        Err(e) => {
            print_error(&e);
            panic!()
        }
    };
    let rule = &rules[13];

    let should_match = &[".createTempFile()", ".createTempFile()"];

    let should_not_match = &["", "", "", ""];

    for m in should_match {
        assert!(check_match(m, rule));
    }

    for m in should_not_match {
        assert!(!check_match(m, rule));
    }
}

#[test]
fn it_web_view_xss() {
    let config = Config::default();
    let rules = match load_rules(&config) {
        Ok(r) => r,
        Err(e) => {
            print_error(&e);
            panic!()
        }
    };
    let rule = &rules[14];

    let should_match = &["setJavaScriptEnabled(true)    .addJavascriptInterface()"];

    let should_not_match = &["", "", "", ""];

    for m in should_match {
        assert!(check_match(m, rule));
    }

    for m in should_not_match {
        assert!(!check_match(m, rule));
    }
}

#[test]
fn it_web_view_ssl_errors() {
    let config = Config::default();
    let rules = match load_rules(&config) {
        Ok(r) => r,
        Err(e) => {
            print_error(&e);
            panic!()
        }
    };
    let rule = &rules[15];

    let should_match = &[
        "onReceivedSslError(WebView view, SslErrorHandler handler, SslError \
             error)             .proceed();",
    ];

    let should_not_match = &["", "", "", ""];

    for m in should_match {
        assert!(check_match(m, rule));
    }

    for m in should_not_match {
        assert!(!check_match(m, rule));
    }
}

#[test]
fn it_sql_injection() {
    let config = Config::default();
    let rules = match load_rules(&config) {
        Ok(r) => r,
        Err(e) => {
            print_error(&e);
            panic!()
        }
    };
    let rule = &rules[16];

    let should_match = &[
        "android.database.sqlite   .execSQL(\"INSERT INTO myuser VALUES \
             ('\" + paramView.getText().toString() + \"', '\" + \
             localEditText.getText().toString() + \"');\");",
        "android.database.sqlite   .rawQuery(\"INSERT INTO myuser VALUES \
             ('\" + paramView.getText().toString() + \"', '\" + \
             localEditText.getText().toString() + \"');\");",
    ];

    let should_not_match = &[
        ".execSQL(\"INSERT INTO myuser VALUES\"';\");",
        "rawQuery(\"INSERT INTO myuser VALUES\";\");",
        "",
        "",
    ];

    for m in should_match {
        assert!(check_match(m, rule));
    }

    for m in should_not_match {
        assert!(!check_match(m, rule));
    }
}

#[test]
fn it_ssl_accepting_all_certificates() {
    let config = Config::default();
    let rules = match load_rules(&config) {
        Ok(r) => r,
        Err(e) => {
            print_error(&e);
            panic!()
        }
    };
    let rule = &rules[17];

    let should_match = &[
        "javax.net.ssl   TrustAllSSLSocket-Factory",
        "javax.net.ssl   AllTrustSSLSocketFactory",
        "javax.net.ssl   NonValidatingSSLSocketFactory",
        "javax.net.ssl   ALLOW_ALL_HOSTNAME_VERIFIER",
        "javax.net.ssl   .setDefaultHostnameVerifier()",
        "javax.net.ssl   NullHostnameVerifier(')",
    ];

    let should_not_match = &[
        "NullHostnameVerifier(')",
        "javax.net.ssl",
        "AllTrustSSLSocketFactory",
        "",
    ];

    for m in should_match {
        assert!(check_match(m, rule));
    }

    for m in should_not_match {
        assert!(!check_match(m, rule));
    }
}

#[test]
fn it_sms_mms_sending() {
    let config = Config::default();
    let rules = match load_rules(&config) {
        Ok(r) => r,
        Err(e) => {
            print_error(&e);
            panic!()
        }
    };
    let rule = &rules[18];

    let should_match = &[
        "telephony.SmsManager  sendMultipartTextMessage(String \
             destinationAddress, String scAddress, ArrayList<String> parts, \
             ArrayList<PendingIntent> sentIntents, ArrayList<PendingIntent> \
             deliveryIntents)",
        "telephony.SmsManager  sendTextMessage(String destinationAddress, \
             String scAddress, String text, PendingIntent sentIntent, \
             PendingIntent deliveryIntent)",
        "telephony.SmsManager  vnd.android-dir/mms-sms",
        "telephony.SmsManager  vnd.android-dir/mms-sms",
    ];

    let should_not_match = &[
        "vnd.android-dir/mms-sms",
        "sendTextMessage(String destinationAddress, String scAddress, \
             String text, PendingIntent sentIntent, PendingIntent \
             deliveryIntent)",
        " sendMultipartTextMessage(String destinationAddress, String \
             scAddress, ArrayList<String> parts, ArrayList<PendingIntent> \
             sentIntents, ArrayList<PendingIntent> deliveryIntents)",
        "telephony.SmsManager ",
    ];

    for m in should_match {
        assert!(check_match(m, rule));
    }

    for m in should_not_match {
        assert!(!check_match(m, rule));
    }
}

#[test]
fn it_superuser_privileges() {
    let config = Config::default();
    let rules = match load_rules(&config) {
        Ok(r) => r,
        Err(e) => {
            print_error(&e);
            panic!()
        }
    };
    let rule = &rules[19];

    let should_match = &[
        "com.noshufou.android.su",
        "com.thirdparty.superuser",
        "eu.chainfire.supersu",
        "com.koushikdutta.superuser",
        "eu.chainfire.",
    ];

    let should_not_match = &["", "", "", ""];

    for m in should_match {
        assert!(check_match(m, rule));
    }

    for m in should_not_match {
        assert!(!check_match(m, rule));
    }
}

#[test]
fn it_superuser_device_detection() {
    let config = Config::default();
    let rules = match load_rules(&config) {
        Ok(r) => r,
        Err(e) => {
            print_error(&e);
            panic!()
        }
    };
    let rule = &rules[20];

    let should_match = &[
        ".contains(\"test-keys\")",
        "/system/app/Superuser.apk",
        "isDeviceRooted()",
        "/system/bin/failsafe/su",
        "/system/sd/xbin/su",
        "RootTools.isAccessGiven()",
        "RootTools.isAccessGiven()",
    ];

    let should_not_match = &["", "", "", ""];

    for m in should_match {
        assert!(check_match(m, rule));
    }

    for m in should_not_match {
        assert!(!check_match(m, rule));
    }
}

#[test]
fn it_base_station_location() {
    let config = Config::default();
    let rules = match load_rules(&config) {
        Ok(r) => r,
        Err(e) => {
            print_error(&e);
            panic!()
        }
    };
    let rule = &rules[21];

    let should_match = &["telephony.TelephonyManager    getCellLocation"];

    let should_not_match = &["telephony.TelephonyManager ", " getCellLocation", "", ""];

    for m in should_match {
        assert!(check_match(m, rule));
    }

    for m in should_not_match {
        assert!(!check_match(m, rule));
    }
}

#[test]
fn it_get_device_id() {
    let config = Config::default();
    let rules = match load_rules(&config) {
        Ok(r) => r,
        Err(e) => {
            print_error(&e);
            panic!()
        }
    };
    let rule = &rules[22];

    let should_match = &["telephony.TelephonyManager      getDeviceId()"];

    let should_not_match = &["getDeviceId()", "telephony.TelephonyManager", "", ""];

    for m in should_match {
        assert!(check_match(m, rule));
    }

    for m in should_not_match {
        assert!(!check_match(m, rule));
    }
}

#[test]
fn it_get_sim_serial() {
    let config = Config::default();
    let rules = match load_rules(&config) {
        Ok(r) => r,
        Err(e) => {
            print_error(&e);
            panic!()
        }
    };
    let rule = &rules[23];

    let should_match = &["telephony.TelephonyManager      getSimSerialNumber()"];

    let should_not_match = &["getSimSerialNumber()", "telephony.TelephonyManager"];

    for m in should_match {
        assert!(check_match(m, rule));
    }

    for m in should_not_match {
        assert!(!check_match(m, rule));
    }
}

#[test]
fn it_gps_location() {
    let config = Config::default();
    let rules = match load_rules(&config) {
        Ok(r) => r,
        Err(e) => {
            print_error(&e);
            panic!()
        }
    };
    let rule = &rules[24];

    let should_match = &[
        "android.location   getLastKnownLocation()",
        "android.location   requestLocationUpdates()",
        "android.location   getLatitude()",
        "android.location   getLongitude()",
    ];

    let should_not_match = &[
        "getLastKnownLocation()",
        "requestLocationUpdates()",
        "getLatitude()",
        "getLongitude()",
        "android.location",
    ];

    for m in should_match {
        assert!(check_match(m, rule));
    }

    for m in should_not_match {
        assert!(!check_match(m, rule));
    }
}

#[test]
fn it_base64_encode() {
    let config = Config::default();
    let rules = match load_rules(&config) {
        Ok(r) => r,
        Err(e) => {
            print_error(&e);
            panic!()
        }
    };
    let rule = &rules[25];

    let should_match = &[
        "android.util.Base64 .encodeToString()",
        "android.util.Base64    .encode()",
    ];

    let should_not_match = &[".encodeToString()", ".encode()", "android.util.Base64"];

    for m in should_match {
        assert!(check_match(m, rule));
    }

    for m in should_not_match {
        assert!(!check_match(m, rule));
    }
}

#[test]
fn it_base64_decoding() {
    let config = Config::default();
    let rules = match load_rules(&config) {
        Ok(r) => r,
        Err(e) => {
            print_error(&e);
            panic!()
        }
    };
    let rule = &rules[26];

    let should_match = &["android.util.Base64   .decode()"];

    let should_not_match = &["android.util.Base64", ".decode()"];

    for m in should_match {
        assert!(check_match(m, rule));
    }

    for m in should_not_match {
        assert!(!check_match(m, rule));
    }
}

#[test]
fn it_infinite_loop() {
    let config = Config::default();
    let rules = match load_rules(&config) {
        Ok(r) => r,
        Err(e) => {
            print_error(&e);
            panic!()
        }
    };
    let rule = &rules[27];

    let should_match = &["while(true)"];

    let should_not_match = &["while(i<10)"];

    for m in should_match {
        assert!(check_match(m, rule));
    }

    for m in should_not_match {
        assert!(!check_match(m, rule));
    }
}

#[test]
fn it_email_disclosure() {
    let config = Config::default();
    let rules = match load_rules(&config) {
        Ok(r) => r,
        Err(e) => {
            print_error(&e);
            panic!()
        }
    };
    let rule = &rules[28];

    let should_match = &[
        "super@super.es",
        "android_analyzer@dem.co.uk",
        "foo@webpage.com",
        "android-rust69@tux.rox",
    ];

    let should_not_match = &["@", "@strings/", "@id/user.id", "android:id=\"@id/userid\""];

    for m in should_match {
        assert!(check_match(m, rule));
    }

    for m in should_not_match {
        assert!(!check_match(m, rule));
    }
}

#[test]
fn it_hardcoded_certificate() {
    let config = Config::default();
    let rules = match load_rules(&config) {
        Ok(r) => r,
        Err(e) => {
            print_error(&e);
            panic!()
        }
    };
    let rule = &rules[29];

    let should_match = &[
        "\"key.key              ",
        "\"cert.cert\"",
        "\"    key.pub    ",
        "\"    cert.pub   ",
        "     throw new IllegalArgumentException(\"translateAPI.key is not \
             specified\");",
    ];

    let should_not_match = &[
        "Iterator localIterator = paramBundle.keySet().iterator();",
        "import java.security.cert.X509Certificate;",
        "",
        "",
    ];

    for m in should_match {
        assert!(check_match(m, rule));
    }

    for m in should_not_match {
        assert!(!check_match(m, rule));
    }
}

#[test]
fn it_get_sim_operator() {
    let config = Config::default();
    let rules = match load_rules(&config) {
        Ok(r) => r,
        Err(e) => {
            print_error(&e);
            panic!()
        }
    };
    let rule = &rules[30];

    let should_match = &["telephony.TelephonyManager      getSimOperator()"];

    let should_not_match = &["getSimOperator()", "telephony.TelephonyManager"];

    for m in should_match {
        assert!(check_match(m, rule));
    }

    for m in should_not_match {
        assert!(!check_match(m, rule));
    }
}

#[test]
fn it_get_sim_operator_name() {
    let config = Config::default();
    let rules = match load_rules(&config) {
        Ok(r) => r,
        Err(e) => {
            print_error(&e);
            panic!()
        }
    };
    let rule = &rules[31];

    let should_match = &["telephony.TelephonyManager      getSimOperatorName()"];

    let should_not_match = &["getSimOperatorName()", "telephony.TelephonyManager"];

    for m in should_match {
        assert!(check_match(m, rule));
    }

    for m in should_not_match {
        assert!(!check_match(m, rule));
    }
}

#[test]
fn it_obfuscation() {
    let config = Config::default();
    let rules = match load_rules(&config) {
        Ok(r) => r,
        Err(e) => {
            print_error(&e);
            panic!()
        }
    };
    let rule = &rules[32];

    let should_match = &[
        "android.utils.AESObfuscator getObfuscator();",
        "android.utils.AESObfuscator   obfuscation.getObfuscator();",
        "utils.AESObfuscator getObfuscator();",
        "utils.AESObfuscator   obfuscation.getObfuscator();",
    ];

    let should_not_match = &[
        "AESObfuscator  getObfuscator();",
        "android.utils.AESObfuscator   obfuscation",
        "getObfuscator();",
        "android.utils.AESObfuscator",
    ];

    for m in should_match {
        assert!(check_match(m, rule));
    }

    for m in should_not_match {
        assert!(!check_match(m, rule));
    }
}

#[test]
fn it_command_exec() {
    let config = Config::default();
    let rules = match load_rules(&config) {
        Ok(r) => r,
        Err(e) => {
            print_error(&e);
            panic!()
        }
    };
    let rule = &rules[33];

    let should_match = &[
        "Runtime.getRuntime().exec(\"command\", options);",
        "getRuntime().exec(\"ls -la\", options);",
        "Runtime.getRuntime().exec(\"ls -la\", options);",
        "getRuntime().exec(\"ps -l\", options);",
    ];

    let should_not_match = &[
        "Runtime.getRuntime()(\"\", options);",
        "getRuntime()(\"\", options);",
        "Runtime.getRuntime()(\"\", options);",
        "getRuntime()(\"\", options);",
    ];

    for m in should_match {
        assert!(check_match(m, rule));
    }

    for m in should_not_match {
        assert!(!check_match(m, rule));
    }
}

#[test]
fn it_ssl_get_insecure_method() {
    let config = Config::default();
    let rules = match load_rules(&config) {
        Ok(r) => r,
        Err(e) => {
            print_error(&e);
            panic!()
        }
    };
    let rule = &rules[34];

    let should_match = &[" javax.net.ssl.SSLSocketFactory                 \
                              SSLSocketFactory.getInsecure()"];

    let should_not_match = &[
        "getInsecure()",
        "javax.net.ssl.SSL  getInsecure();",
        "javax.net.ssl.SSLSocketFactory",
        "net.ssl.SSL getSecure();",
    ];

    for m in should_match {
        assert!(check_match(m, rule));
    }

    for m in should_not_match {
        assert!(!check_match(m, rule));
    }
}

#[test]
fn it_finally_with_return() {
    let config = Config::default();
    let rules = match load_rules(&config) {
        Ok(r) => r,
        Err(e) => {
            print_error(&e);
            panic!()
        }
    };
    let rule = &rules[35];

    let should_match = &[
        "finally {                      return;",
        "finally {                      return;}",
    ];

    let should_not_match = &[
        "finally{}",
        "finally{ var;}",
        "finally { Printf (\"Hello\"); return true; }",
    ];

    for m in should_match {
        assert!(check_match(m, rule));
    }

    for m in should_not_match {
        assert!(!check_match(m, rule));
    }
}

#[test]
fn it_sleep_method_not_validated() {
    let config = Config::default();
    let rules = match load_rules(&config) {
        Ok(r) => r,
        Err(e) => {
            print_error(&e);
            panic!()
        }
    };
    let rule = &rules[36];

    let should_match = &[
        "int var = EditText.getText  Thread.sleep(100 + var);",
        "var = .getText  Thread.sleep(100 + var);",
    ];

    let should_not_match = &[
        "int var4 = EditText.getText  Thread.sleep(100 + var);",
        "var = .getText  Thread.sleep(100 + hello);",
        "",
        "",
    ];

    for m in should_match {
        assert!(check_match(m, rule));
    }

    for m in should_not_match {
        assert!(!check_match(m, rule));
    }
}
