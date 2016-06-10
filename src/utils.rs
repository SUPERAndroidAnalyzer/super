use std::{fs, io};
use std::path::Path;
use std::io::Write;

use colored::Colorize;

use super::Criticity;

pub fn print_error<S: AsRef<str>>(error: S, verbose: bool) {
    io::stderr()
        .write(&format!("{} {}\n", "Error:".bold().red(), error.as_ref().red()).into_bytes()[..])
        .unwrap();

    if !verbose {
        println!("If you need more information, try to run the program again with the {} flag.",
                 "-v".bold());
    }
}

pub fn print_warning<S: AsRef<str>>(warning: S, verbose: bool) {
    io::stderr()
        .write(&format!("{} {}\n",
                        "Warning:".bold().yellow(),
                        warning.as_ref().yellow())
            .into_bytes()[..])
        .unwrap();

    if !verbose {
        println!("If you need more information, try to run the program again with the {} flag.",
                 "-v".bold());
    }
}

pub fn print_vulnerability<S: AsRef<str>>(text: S, criticity: Criticity) {
    let text = text.as_ref();
    let start = format!("Possible {} criticity vulnerability found!:", criticity);
    let (start, message) = match criticity {
        Criticity::Low => (start.cyan(), text.cyan()),
        Criticity::Medium => (start.yellow(), text.yellow()),
        Criticity::High | Criticity::Critical => (start.red(), text.red()),
        _ => return,
    };
    println!("{} {}", start, message);
}

pub fn get_code(code: &str, s_line: usize, e_line: usize) -> String {
    let mut result = String::new();
    for (i, text) in code.lines().enumerate() {
        if i >= (e_line + 5) {
            break;
        } else if (s_line >= 5 && i > s_line - 5) || (s_line < 5 && i < s_line + 5) {
            result.push_str(text);
            result.push_str("\n");
        }
    }
    result
}

pub fn file_exists<P: AsRef<Path>>(path: P) -> bool {
    fs::metadata(path).is_ok()
}

#[cfg(test)]
mod test {
    use {get_code, file_exists};
    use std::fs;
    use std::fs::File;

    #[test]
    fn it_get_code() {
        let code = "Lorem ipsum dolor sit amet, consectetur adipiscing elit.\nCurabitur tortor. \
                    Pellentesque nibh. Aenean quam.\nSed lacinia, urna non tincidunt mattis, \
                    tortor neque\nPraesent blandit dolor. Sed non quam. In vel mi\nSed aliquet \
                    risus a tortor. Integer id quam. Morbi mi.\nNullam mauris orci, aliquet et, \
                    iaculis et, viverra vitae, ligula.\nPraesent mauris. Fusce nec tellus sed \
                    ugue semper porta. Mauris massa.\nProin ut ligula vel nunc egestas porttitor. \
                    Morbi lectus risus,\nVestibulum sapien. Proin quam. Etiam ultrices. \
                    Suspendisse in\nVestibulum tincidunt malesuada tellus. Ut ultrices ultrices \
                    enim.\nAenean laoreet. Vestibulum nisi lectus, commodo ac, facilisis\nInteger \
                    nec odio. Praesent libero. Sed cursus ante dapibus diam.\nPellentesque nibh. \
                    Aenean quam. In scelerisque sem at dolor.\nSed lacinia, urna non tincidunt \
                    mattis, tortor neque adipiscing\nVestibulum ante ipsum primis in faucibus \
                    orci luctus et ultrices";

        assert_eq!(get_code(code, 1, 1),
                   "Lorem ipsum dolor sit amet, consectetur adipiscing elit.\n\
                    Curabitur tortor. Pellentesque nibh. Aenean quam.\n\
                    Sed lacinia, urna non tincidunt mattis, tortor neque\n\
                    Praesent blandit dolor. Sed non quam. In vel mi\n\
                    Sed aliquet risus a tortor. Integer id quam. Morbi mi.\n\
                    Nullam mauris orci, aliquet et, iaculis et, viverra vitae, ligula.\n");

        assert_eq!(get_code(code, 13, 13),
                   "Vestibulum tincidunt malesuada tellus. Ut ultrices ultrices enim.\n\
                    Aenean laoreet. Vestibulum nisi lectus, commodo ac, facilisis\n\
                    Integer nec odio. Praesent libero. Sed cursus ante dapibus diam.\n\
                    Pellentesque nibh. Aenean quam. In scelerisque sem at dolor.\n\
                    Sed lacinia, urna non tincidunt mattis, tortor neque adipiscing\n\
                    Vestibulum ante ipsum primis in faucibus orci luctus et ultrices\n");

        assert_eq!(get_code(code, 7, 7),
                   "Praesent blandit dolor. Sed non quam. In vel mi\n\
                    Sed aliquet risus a tortor. Integer id quam. Morbi mi.\n\
                    Nullam mauris orci, aliquet et, iaculis et, viverra vitae, ligula.\n\
                    Praesent mauris. Fusce nec tellus sed ugue semper porta. Mauris massa.\n\
                    Proin ut ligula vel nunc egestas porttitor. Morbi lectus risus,\n\
                    Vestibulum sapien. Proin quam. Etiam ultrices. Suspendisse in\n\
                    Vestibulum tincidunt malesuada tellus. Ut ultrices ultrices enim.\n\
                    Aenean laoreet. Vestibulum nisi lectus, commodo ac, facilisis\n\
                    Integer nec odio. Praesent libero. Sed cursus ante dapibus diam.\n");

        assert_eq!(get_code(code, 7, 9),
                   "Praesent blandit dolor. Sed non quam. In vel mi\n\
                    Sed aliquet risus a tortor. Integer id quam. Morbi mi.\n\
                    Nullam mauris orci, aliquet et, iaculis et, viverra vitae, ligula.\n\
                    Praesent mauris. Fusce nec tellus sed ugue semper porta. Mauris massa.\n\
                    Proin ut ligula vel nunc egestas porttitor. Morbi lectus risus,\n\
                    Vestibulum sapien. Proin quam. Etiam ultrices. Suspendisse in\n\
                    Vestibulum tincidunt malesuada tellus. Ut ultrices ultrices enim.\n\
                    Aenean laoreet. Vestibulum nisi lectus, commodo ac, facilisis\n\
                    Integer nec odio. Praesent libero. Sed cursus ante dapibus diam.\n\
                    Pellentesque nibh. Aenean quam. In scelerisque sem at dolor.\n\
                    Sed lacinia, urna non tincidunt mattis, tortor neque adipiscing\n");
    }

    #[test]
    fn it_file_exists() {
        if file_exists("test.txt") {
            fs::remove_file("test.txt").unwrap();
        }
        assert!(!file_exists("test.txt"));
        File::create("test.txt").unwrap();
        assert!(file_exists("test.txt"));
        fs::remove_file("test.txt").unwrap();
        assert!(!file_exists("test.txt"));
    }
}
