//! Module containing the definition of error types.

/// Enumeration of the different error kinds.
#[derive(Debug, Fail)]
pub enum Kind {
    /// Configuration error.
    #[fail(display = "there was an error in the configuration: {}", message)]
    Config {
        /// Error message.
        message: String,
    },
    /// Parsing error.
    #[fail(display = "there was an error in the parsing process")]
    Parse,
    /// Template name error.
    #[fail(display = "invalid template name: {}", message)]
    TemplateName {
        /// Error message.
        message: String,
    },
    /// Code not found.
    #[fail(display = "no code was found in the file")]
    CodeNotFound,
}

// impl Into<i32> for Kind {
//     fn into(self) -> i32 {
//         let kind = self.kind();
//
//         match *kind {
//             ErrorKind::Parse | ErrorKind::TOML(_) => 20,
//             ErrorKind::JSON(_) => 30,
//             ErrorKind::CodeNotFound => 40,
//             ErrorKind::Config(_) => 50,
//             ErrorKind::IO(_) => 100,
//             ErrorKind::TemplateName(_) => 125,
//             ErrorKind::Template(_) => 150,
//             ErrorKind::TemplateRender(_) => 175,
//             ErrorKind::Msg(_) => 1,
//             _ => -1,
//         }
//     }
// }
