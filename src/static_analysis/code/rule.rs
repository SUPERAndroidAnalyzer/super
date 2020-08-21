//! Module for rules.

use crate::{
    criticality::Criticality, print_warning, static_analysis::manifest::Permission, Config,
};
use anyhow::{anyhow, Context, Result};
use colored::Colorize;
use regex::Regex;
use serde::{
    de::{self, SeqAccess, Visitor},
    Deserialize, Deserializer,
};
use std::{fmt, fs::File};

/// Vulnerability searching rule.
#[derive(Debug, Deserialize)]
pub struct Rule {
    #[serde(deserialize_with = "deserialize_main_regex")]
    regex: Regex,
    #[serde(default)]
    permissions: Box<[Permission]>,
    forward_check: Option<String>,
    max_sdk: Option<u32>,
    #[serde(deserialize_with = "deserialize_whitelist_regex")]
    #[serde(default)]
    whitelist: Box<[Regex]>,
    label: String,
    description: String,
    criticality: Criticality,
    #[serde(deserialize_with = "deserialize_file_regex")]
    #[serde(default)]
    include_file_regex: Option<Regex>,
    #[serde(deserialize_with = "deserialize_file_regex")]
    #[serde(default)]
    exclude_file_regex: Option<Regex>,
}

impl Rule {
    /// Gets the regex of the rule.
    pub fn regex(&self) -> &Regex {
        &self.regex
    }

    /// Gets the permissions required for this rule to be checked.
    pub fn permissions(&self) -> impl Iterator<Item = &Permission> {
        self.permissions.iter()
    }

    /// Gets the potential forward check of the rule.
    pub fn forward_check(&self) -> Option<&String> {
        self.forward_check.as_ref()
    }

    /// Gets the maximum SDK affected by this vulnerability.
    pub fn max_sdk(&self) -> Option<u32> {
        self.max_sdk
    }

    /// Gets the label of the vulnerability.
    pub fn label(&self) -> &str {
        self.label.as_str()
    }

    /// Gets the description of the vulnerability.
    pub fn description(&self) -> &str {
        self.description.as_str()
    }

    /// Gets the criticality for the vulnerabilities found by the rule.
    pub fn criticality(&self) -> Criticality {
        self.criticality
    }

    /// Gets the whitelist regex list.
    pub fn whitelist(&self) -> impl Iterator<Item = &Regex> {
        self.whitelist.iter()
    }

    /// Returns if this rule has to be applied to the given filename
    pub fn has_to_check(&self, filename: &str) -> bool {
        if self.include_file_regex.is_none() && self.exclude_file_regex.is_none() {
            return true;
        }

        let mut has_to_check = false;

        if let Some(ref r) = self.include_file_regex {
            has_to_check = r.is_match(filename)
        }

        if let Some(ref r) = self.exclude_file_regex {
            has_to_check = !r.is_match(filename)
        }

        has_to_check
    }
}

/// Regular expression serde visitor.
struct RegexVisitor;

impl<'de> Visitor<'de> for RegexVisitor {
    type Value = Regex;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a valid regular expression")
    }

    fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        Regex::new(value).map_err(E::custom)
    }

    fn visit_borrowed_str<E>(self, value: &'de str) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        self.visit_str(value)
    }

    fn visit_string<E>(self, value: String) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        self.visit_str(&value)
    }
}

/// Deserializes the main regular expression of a rule.
fn deserialize_main_regex<'de, D>(deserializer: D) -> Result<Regex, D::Error>
where
    D: Deserializer<'de>,
{
    deserializer.deserialize_str(RegexVisitor)
}

/// Deserializes the list of whitelist regular expressions.
fn deserialize_whitelist_regex<'de, D>(deserializer: D) -> Result<Box<[Regex]>, D::Error>
where
    D: Deserializer<'de>,
{
    /// Visitor that deserializes a sequence of regular expressions.
    struct RegexSeqVisitor;

    impl<'de> Visitor<'de> for RegexSeqVisitor {
        type Value = Box<[Regex]>;

        fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter.write_str("a list of valid regular expressions")
        }

        fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
        where
            A: SeqAccess<'de>,
        {
            use serde::de::Error as SerdeError;

            let mut list = Vec::with_capacity(seq.size_hint().unwrap_or(0));

            // While there are entries remaining in the input, add them into our vector.
            while let Some(regex_str) = seq.next_element::<String>()? {
                list.push(Regex::new(regex_str.as_str()).map_err(A::Error::custom)?)
            }

            Ok(list.into_boxed_slice())
        }
    }

    deserializer.deserialize_seq(RegexSeqVisitor)
}

/// Deserializes file regular expressions.
fn deserialize_file_regex<'de, D>(deserializer: D) -> Result<Option<Regex>, D::Error>
where
    D: Deserializer<'de>,
{
    /// Optional regular expression serde visitor.
    struct RegexOptionVisitor;

    impl<'de> Visitor<'de> for RegexOptionVisitor {
        type Value = Option<Regex>;

        fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter.write_str("a valid regular expression")
        }

        fn visit_some<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
        where
            D: Deserializer<'de>,
        {
            deserializer.deserialize_str(RegexVisitor).map(Some)
        }

        fn visit_none<E>(self) -> Result<Self::Value, E>
        where
            E: de::Error,
        {
            Ok(None)
        }
    }

    deserializer.deserialize_option(RegexOptionVisitor)
}

pub fn load_rules(config: &Config) -> Result<Vec<Rule>> {
    let f = File::open(config.rules_json())?;
    let format_error = || {
        format!(
            "rules must be objects with the following structure:\n{}\nAn optional {} attribute \
             can be added: an array of regular expressions that if matched, the found match will \
             be discarded. You can also include an optional {} attribute: an array of the \
             permissions needed for this rule to be checked. And finally, an optional {} \
             attribute can be added where you can specify a second regular expression to check if \
             the one in the {} attribute matches. You can add one or two capture groups with name \
             from the match to this check, with names {} and {}. To use them you have to include \
             {} or {} in the forward check.",
            "{\n\t\"label\": \"Label for the rule\",\n\t\"description\": \"Long description for \
             this rule\"\n\t\"criticality\": \"warning|low|medium|high|critical\"\n\t\"regex\": \
             \"regex_to_find_vulnerability\"\n}"
                .italic(),
            "whitelist".italic(),
            "permissions".italic(),
            "forward_check".italic(),
            "regex".italic(),
            "fc1".italic(),
            "fc2".italic(),
            "{fc1}".italic(),
            "{fc2}".italic()
        )
    };

    let rules: Vec<Rule> = serde_json::from_reader(f).with_context(format_error)?;
    let rules = rules
        .into_iter()
        .filter_map(|rule| {
            if rule.criticality >= config.min_criticality() {
                let fc1_in_regex = rule.regex().capture_names().any(|c| c == Some("fc1"));
                let fc2_in_regex = rule.regex().capture_names().any(|c| c == Some("fc2"));

                let forward_check = rule.forward_check().cloned();
                if let Some(forward_check) = forward_check {
                    let fc1_in_fc = forward_check.contains("{fc1}");
                    let fc2_in_fc = forward_check.contains("{fc2}");

                    if fc1_in_regex && !fc1_in_fc {
                        Some(Err(anyhow!(
                            "fc1 capture group used but no placeholder found in the forward check",
                        )))
                    } else if fc2_in_regex && !fc2_in_fc {
                        Some(Err(anyhow!(
                            "fc2 capture group used but no placeholder found in the forward check",
                        )))
                    } else {
                        if fc2_in_regex && !fc1_in_regex {
                            print_warning(format!(
                                "fc2 capture group used in the `{}` rule's forward check, but no \
                                 fc1 capture group used",
                                rule.label()
                            ));
                        }

                        if fc1_in_fc && !fc1_in_regex {
                            print_warning(format!(
                                "{{fc1}} used in the `{}` rule's forward check, but no capture \
                                 group is checking for it",
                                rule.label()
                            ));
                        }

                        if fc2_in_fc && !fc2_in_regex {
                            print_warning(format!(
                                "{{fc2}} used in the `{}` rule's forward check, but no capture \
                                 group is checking for it",
                                rule.label()
                            ));
                        }
                        Some(Ok(rule))
                    }
                } else {
                    Some(Ok(rule))
                }
            } else {
                None
            }
        })
        .collect::<Result<Vec<Rule>>>()
        .with_context(format_error)?;

    Ok(rules)
}

/// Tests for the rules.
#[cfg(tests)]
mod tests {
    use super::Rule;

    #[test]
    fn it_has_to_check_rule_if_exclude_and_include_regexp_are_not_provided() {
        let rule = Rule {
            regex: Regex::new("").unwrap(),
            permissions: Box::new([]),
            forward_check: None,
            max_sdk: None,
            whitelist: Box::new([]),
            label: String::new(),
            description: String::new(),
            criticality: Criticality::Warning,
            include_file_regex: None,
            exclude_file_regex: None,
        };

        assert!(rule.has_to_check("filename.xml"));
    }

    #[test]
    fn it_has_to_check_rule_if_include_regexp_is_match_and_exclude_not_provided() {
        let rule = Rule {
            regex: Regex::new("").unwrap(),
            permissions: Box::new([]),
            forward_check: None,
            max_sdk: None,
            whitelist: Box::new([]),
            label: String::new(),
            description: String::new(),
            criticality: Criticality::Warning,
            include_file_regex: Some(Regex::new(r".*\.xml").unwrap()),
            exclude_file_regex: None,
        };

        assert!(rule.has_to_check("filename.xml"));
    }

    #[test]
    fn it_does_not_have_to_check_rule_if_include_regexp_is_non_match_and_exclude_not_provided() {
        let rule = Rule {
            regex: Regex::new("").unwrap(),
            permissions: Box::new([]),
            forward_check: None,
            max_sdk: None,
            whitelist: Box::new([]),
            label: String::new(),
            description: String::new(),
            criticality: Criticality::Warning,
            include_file_regex: Some(Regex::new(r".*\.xml").unwrap()),
            exclude_file_regex: None,
        };

        assert!(!rule.has_to_check("filename.yml"));
    }

    #[test]
    fn it_has_to_check_rule_if_include_regexp_is_match_and_exclude_not() {
        let rule = Rule {
            regex: Regex::new("").unwrap(),
            permissions: Box::new([]),
            forward_check: None,
            max_sdk: None,
            whitelist: Box::new([]),
            label: String::new(),
            description: String::new(),
            criticality: Criticality::Warning,
            include_file_regex: Some(Regex::new(r".*\.xml").unwrap()),
            exclude_file_regex: Some(Regex::new(r"non_matching").unwrap()),
        };

        assert!(rule.has_to_check("filename.xml"));
    }

    #[test]
    fn it_does_not_have_to_check_rule_if_exclude_is_match() {
        let rule = Rule {
            regex: Regex::new("").unwrap(),
            permissions: Box::new([]),
            forward_check: None,
            max_sdk: None,
            whitelist: Box::new([]),
            label: String::new(),
            description: String::new(),
            criticality: Criticality::Warning,
            include_file_regex: Some(Regex::new(r"non_matching").unwrap()),
            exclude_file_regex: Some(Regex::new(r".*\.xml").unwrap()),
        };

        assert!(!rule.has_to_check("filename.xml"));
    }

    #[test]
    fn it_does_not_have_to_check_if_both_regexps_matches() {
        let rule = Rule {
            regex: Regex::new("").unwrap(),
            permissions: Box::new([]),
            forward_check: None,
            max_sdk: None,
            whitelist: Box::new([]),
            label: String::new(),
            description: String::new(),
            criticality: Criticality::Warning,
            include_file_regex: Some(Regex::new(r".*\.xml").unwrap()),
            exclude_file_regex: Some(Regex::new(r".*\.xml").unwrap()),
        };

        assert!(!rule.has_to_check("filename.xml"));
    }
}
