use Result;
use std::path::Path;
use std::str::from_utf8;
use std::fs;
use elf;
use std::path::PathBuf;
use results::Results;
use std::ffi::OsString;
use code::Rule;
use results::utils::Vulnerability;
use Criticality;

pub struct BinaryAnalyzer;

impl BinaryAnalyzer {
    pub fn analyze_path(path: &PathBuf, rules: &Vec<Rule>, results: &mut Results) -> Result<()> {
        let libs_path = path.join("lib");

        for architecture in fs::read_dir(&libs_path)? {
            let entry = architecture?;

            if fs::metadata(entry.path())?.is_dir() {

                for file in fs::read_dir(entry.path())? {
                    let file = file?;

                    let meta = fs::metadata(file.path())?;

                    if !meta.is_dir() && file.path().extension().unwrap_or(&OsString::new()) == "so" {
                        Self::analyze_lib(&file.path(), rules, results).unwrap();
                    }
                }
            }
        }

        Ok(())
    }

    fn analyze_lib(path: &Path, rules: &Vec<Rule>, results: &mut Results) -> Result<()> {
        let efile = elf::File::open_path(&path).unwrap();
        let text_scn = efile.get_section(".rodata").unwrap();

        let st = StringTable::new(&text_scn.data);
        let str_path = path.file_name().unwrap().to_str().unwrap();
        let mut working_rules = rules.clone();
        working_rules.retain(|ref r| r.has_to_check(str_path));

        let mut i = 0;
        for s in &st.strings {
            if s != "" {
                for rule in &working_rules {
                    let r = rule.get_regex();

                    for _ in r.find_iter(&s) {
                        let path_buf = PathBuf::from(path);
                        let code_str = Self::generate_code(&st.strings, i);

                        let v: Vulnerability = Vulnerability::new::<String, String, PathBuf, String>(
                            Criticality::Warning,
                            rule.get_label().to_string(),
                            rule.get_description().to_string(),
                            Some(path_buf),
                            Some(4),
                            Some(4),
                            Some(code_str),
                        );

                        results.add_vulnerability(v);
                    }
                }
            }

            i += 1
        }

        Ok(())
    }

    fn generate_code(string_table: &Vec<String>, position: usize) -> String {
        let mut code = String::new();

        for i in -4..5 {
            let current_position = position as i32 + i;

            if current_position >= 0 {
                match string_table.get(current_position as usize) {
                    Some(str) => {
                        code.push_str(str);
                    },
                    None => (),
                }
            }

            code.push('\n');
        }

        code
    }
}

pub struct StringTable {
    pub strings: Vec<String>,
}

impl StringTable {
    pub fn new(data: &Vec<u8>) -> Self {
        let strings = Self::build_string_table(data);

        StringTable {
            strings: strings,
        }
    }

    fn build_string_table(data: &Vec<u8>) -> Vec<String> {
        let mut last_start = 0;
        let mut string_table = Vec::new();

        for (current_index, ch) in data.iter().enumerate() {
            match ch {
                &0 => {
                    let su8 = from_utf8(&data[last_start..current_index]);
                    last_start = current_index + 1;

                    match su8 {
                        Ok(refsu8) => {
                            string_table.push(refsu8.to_string());
                        },
                        Err(_) => {
                            string_table.push(String::new());
                        },
                    };
                }
                _ => {
                    ()
                }
            }
        }

        string_table
    }
}

impl IntoIterator for StringTable {
    type Item = String;
    type IntoIter = ::std::vec::IntoIter<String>;

    fn into_iter(self) -> Self::IntoIter {
        self.strings.into_iter()
    }
}