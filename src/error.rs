//! Module containing the definition of error types.

use failure::Fail;

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
