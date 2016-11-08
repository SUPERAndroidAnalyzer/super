use handlebars::{Context, Helper, Handlebars, RenderContext, RenderError};
use serde_json::Value;
use bytecount::count;

use super::utils::{split_indent, html_escape};

/// Generates a list of line numbers for the given vulnerability.
///
/// An optional line separator can be added that will be used at the end of each line. By default,
/// this separator will be `<br>`.
pub fn line_numbers(_: &Context,
                    h: &Helper,
                    _: &Handlebars,
                    rc: &mut RenderContext)
                    -> Result<(), RenderError> {
    let vulnerability = try!(h.param(0)
        .and_then(|v| v.value().as_object())
        .ok_or(RenderError::new("to generate the vulnerability index, the first parameter must \
                                 be a vulnerability")));
    let line_separator = match h.param(1) {
        Some(s) => {
            match *s.value() {
                Value::String(ref s) => s,
                _ => {
                    return Err(RenderError::new("the provided line separator for the code lines \
                                                 was not a string"))
                }
            }
        }
        None => "<br>",
    };
    let (start_line, end_line) = if let Some(l) = vulnerability.get("line") {
        let line = l.as_i64().unwrap();
        (line, line)
    } else {
        let start_line = vulnerability.get("start_line").unwrap().as_i64().unwrap();
        let end_line = vulnerability.get("end_line").unwrap().as_i64().unwrap();
        (start_line, end_line)
    };

    let iter_start = if start_line > 5 { start_line - 4 } else { 1 };
    let iter_end = end_line + 5;

    let mut rendered = String::with_capacity((line_separator.len() + 1) *
                                             (iter_end - iter_start) as usize);
    for l in iter_start..iter_end {
        rendered.push_str(&format!("{}", l));
        rendered.push_str(line_separator);
    }
    let _ = try!(rc.writer.write(rendered.as_bytes()));

    Ok(())
}

/// Generates a list of line numbers for all the given code.
///
/// An optional line separator can be added that will be used at the end of each line. By default,
/// this separator will be `<br>`.
pub fn all_lines(_: &Context,
                 h: &Helper,
                 _: &Handlebars,
                 rc: &mut RenderContext)
                 -> Result<(), RenderError> {
    let code = try!(h.param(0)
        .and_then(|v| v.value().as_str())
        .ok_or(RenderError::new("the code must be a string")));
    let line_separator = match h.param(1) {
        Some(s) => {
            match *s.value() {
                Value::String(ref s) => s,
                _ => {
                    return Err(RenderError::new("the provided line separator for the code lines \
                                                 was not a string"))
                }
            }
        }
        None => "<br>",
    };

    let line_count = count(code.as_bytes(), b'\n');
    let mut rendered = String::with_capacity((line_separator.len() + 1) * line_count);
    for l in 1..line_count + 1 {
        rendered.push_str(&format!("{}", l));
        rendered.push_str(line_separator);
    }
    let _ = try!(rc.writer.write(rendered.as_bytes()));

    Ok(())
}

/// Generates all the HTML for the given code.
///
/// An optional line separator can be added that will be used at the end of each line. By default,
/// this separator will be `<br>`.
pub fn all_code(_: &Context,
                h: &Helper,
                _: &Handlebars,
                rc: &mut RenderContext)
                -> Result<(), RenderError> {
    let code = try!(h.param(0)
        .and_then(|v| v.value().as_str())
        .ok_or(RenderError::new("the code must be a string")));
    let line_separator = match h.param(1) {
        Some(s) => {
            match *s.value() {
                Value::String(ref s) => s,
                _ => {
                    return Err(RenderError::new("the provided line separator for the code lines \
                                                 was not a string"))
                }
            }
        }
        None => "<br>",
    };

    for (i, line) in code.lines().enumerate() {
        let (indent, line) = split_indent(line);
        let line = format!("<code id=\"code-line-{}\">{}<span \
                            class=\"line_body\">{}</span></code>{}",
                           i + 1,
                           indent,
                           html_escape(line),
                           line_separator);
        let _ = try!(rc.writer.write(line.as_bytes()));
    }

    Ok(())
}

/// Generates HTML code for affected code in a vulnerability.
///
/// For lines without vulnerable code, only the line plus the optional separator (by default `<br>`)
/// will be rendered. For vulnerable lines, the following code will be generated:
///
/// ```html
/// <code class="vulnerable_line {{ criticity }}">{{ indent }}
/// <span class="line_body">{{ code }}</span></code>{{ line_separator }}
/// ```
///
/// This enables easy styling of the code in templates.
pub fn html_code(_: &Context,
                 h: &Helper,
                 _: &Handlebars,
                 rc: &mut RenderContext)
                 -> Result<(), RenderError> {
    let vulnerability = try!(h.param(0)
        .and_then(|v| v.value().as_object())
        .ok_or(RenderError::new("to generate the vulnerability index, the first parameter must \
                                 be a vulnerability")));
    let line_separator = match h.param(1) {
        Some(s) => {
            match *s.value() {
                Value::String(ref s) => s,
                _ => {
                    return Err(RenderError::new("the provided line separator for the code lines \
                                                 was not a string"))
                }
            }
        }
        None => "<br>",
    };
    let (start_line, end_line) = if let Some(l) = vulnerability.get("line") {
        let line = l.as_i64().unwrap();
        (line, line)
    } else {
        let start_line = vulnerability.get("start_line").unwrap().as_i64().unwrap();
        let end_line = vulnerability.get("end_line").unwrap().as_i64().unwrap();
        (start_line, end_line)
    };

    let iter_start = if start_line > 5 { start_line - 4 } else { 1 };

    for (i, line) in vulnerability.get("code").unwrap().as_str().unwrap().lines().enumerate() {
        let line_number = i + iter_start as usize;

        let rendered = if line_number >= start_line as usize && line_number <= end_line as usize {
            let (indent, code) = split_indent(line);
            format!("<code class=\"vulnerable_line {}\">{}<span \
                     class=\"line_body\">{}</span></code>{}",
                    vulnerability.get("criticity").unwrap().as_str().unwrap(),
                    indent,
                    html_escape(code),
                    line_separator)
        } else {
            format!("{}{}", html_escape(line), line_separator)
        };

        let _ = try!(rc.writer.write(rendered.as_bytes()));
    }

    Ok(())
}

/// Generates the report index for the given vulnerability.
///
/// E.g.: for a critical vulnerability in an application with between 100 and 200 vulnerability,
/// for the critical vulnerability number 12 it would produce `C012`.
pub fn report_index(_: &Context,
                    h: &Helper,
                    _: &Handlebars,
                    rc: &mut RenderContext)
                    -> Result<(), RenderError> {
    let vulnerability = try!(h.param(0)
        .and_then(|v| v.value().as_object())
        .ok_or(RenderError::new("to generate the vulnerability index, the first parameter must \
                                 be a vulnerability")));
    let index = try!(h.param(1)
        .and_then(|v| v.value().as_u64())
        .ok_or(RenderError::new("the index of the vulnerability in the current list must \
                                 be the second parameter"))) as usize + 1;

    let list_len = h.param(2).unwrap().value().as_u64().unwrap();
    let char_index = vulnerability.get("criticity")
        .unwrap()
        .as_str()
        .unwrap()
        .to_uppercase()
        .chars()
        .next()
        .unwrap();

    let mut index_padding = (list_len as f32 + 1f32).log10().ceil() as usize + 1;
    if index_padding < 2 {
        index_padding = 2;
    }
    let rendered = format!("{}{:#02$}", char_index, index, index_padding);
    let _ = try!(rc.writer.write(rendered.as_bytes()));

    Ok(())
}
