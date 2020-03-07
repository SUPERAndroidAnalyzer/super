//! Handlebars helpers.

use super::utils::{html_escape, split_indent};
use bytecount::count;
use handlebars::{
    Context, Handlebars as Registry, Helper, HelperDef, Output, RenderContext, RenderError,
};
use serde_json::Value;

/// Generates a list of line numbers for the given vulnerability.
///
/// An optional line separator can be added that will be used at the end of each line. By default,
/// this separator will be `<br>`.
pub struct LineNumbers;

impl HelperDef for LineNumbers {
    fn call<'reg: 'rc, 'rc>(
        &self,
        h: &Helper<'_, '_>,
        _: &Registry<'_>,
        _: &Context,
        _: &mut RenderContext<'_, '_>,
        out: &mut dyn Output,
    ) -> Result<(), RenderError> {
        let vulnerability = h
            .param(0)
            .and_then(|v| v.value().as_object())
            .ok_or_else(|| {
                RenderError::new(
                    "to generate the vulnerability index, the first parameter must be a \
                 vulnerability",
                )
            })?;
        let line_separator = if let Some(s) = h.param(1) {
            if let Value::String(ref s) = *s.value() {
                s
            } else {
                return Err(RenderError::new(
                    "the provided line separator for the code lines was \
                 not a string",
                ));
            }
        } else {
            "<br>"
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

        let mut rendered =
            String::with_capacity((line_separator.len() + 1) * (iter_end - iter_start) as usize);
        for l in iter_start..iter_end {
            rendered.push_str(&format!("{}", l));
            rendered.push_str(line_separator);
        }
        out.write(&rendered)?;

        Ok(())
    }
}

/// Generates a list of line numbers for all the given code.
///
/// An optional line separator can be added that will be used at the end of each line. By default,
/// this separator will be `<br>`.
pub struct AllLines;

impl HelperDef for AllLines {
    fn call<'reg: 'rc, 'rc>(
        &self,
        h: &Helper<'_, '_>,
        _: &Registry<'_>,
        _: &Context,
        _: &mut RenderContext<'_, '_>,
        out: &mut dyn Output,
    ) -> Result<(), RenderError> {
        let code = h
            .param(0)
            .and_then(|v| v.value().as_str())
            .ok_or_else(|| RenderError::new("the code must be a string"))?;
        let line_separator = if let Some(s) = h.param(1) {
            if let Value::String(ref s) = *s.value() {
                s
            } else {
                return Err(RenderError::new(
                    "the provided line separator for the code lines was \
                 not a string",
                ));
            }
        } else {
            "<br>"
        };

        let line_count = count(code.as_bytes(), b'\n');
        let mut rendered = String::with_capacity((line_separator.len() + 1) * line_count);
        for l in 1..=line_count {
            rendered.push_str(format!("{}", l).as_str());
            rendered.push_str(line_separator);
        }
        out.write(&rendered)?;

        Ok(())
    }
}

/// Generates all the HTML for the given code.
///
/// An optional line separator can be added that will be used at the end of each line. By default,
/// this separator will be `<br>`.
pub struct AllCode;

impl HelperDef for AllCode {
    fn call<'reg: 'rc, 'rc>(
        &self,
        h: &Helper<'_, '_>,
        _: &Registry<'_>,
        _: &Context,
        _: &mut RenderContext<'_, '_>,
        out: &mut dyn Output,
    ) -> Result<(), RenderError> {
        let code = h
            .param(0)
            .and_then(|v| v.value().as_str())
            .ok_or_else(|| RenderError::new("the code must be a string"))?;
        let line_separator = if let Some(s) = h.param(1) {
            if let Value::String(ref s) = *s.value() {
                s
            } else {
                return Err(RenderError::new(
                    "the provided line separator for the code lines was \
                 not a string",
                ));
            }
        } else {
            "<br>"
        };

        for (i, line) in code.lines().enumerate() {
            let (indent, line) = split_indent(line);
            let line = format!(
                "<code id=\"code-line-{}\">{}<span \
             class=\"line_body\">{}</span></code>{}",
                i + 1,
                indent,
                html_escape(line),
                line_separator
            );
            out.write(&line)?;
        }

        Ok(())
    }
}

/// Generates HTML code for affected code in a vulnerability.
///
/// For lines without vulnerable code, only the line plus the optional separator (by default `<br>`)
/// will be rendered. For vulnerable lines, the following code will be generated:
///
/// ```html
/// <code class="vulnerable_line {{ criticality }}">{{ indent }}
/// <span class="line_body">{{ code }}</span></code>{{ line_separator }}
/// ```
///
/// This enables easy styling of the code in templates.
pub struct HtmlCode;

impl HelperDef for HtmlCode {
    fn call<'reg: 'rc, 'rc>(
        &self,
        h: &Helper<'_, '_>,
        _: &Registry<'_>,
        _: &Context,
        _: &mut RenderContext<'_, '_>,
        out: &mut dyn Output,
    ) -> Result<(), RenderError> {
        let vulnerability = h
            .param(0)
            .and_then(|v| v.value().as_object())
            .ok_or_else(|| {
                RenderError::new(
                    "to generate the vulnerability index, the first parameter must be a \
                 vulnerability",
                )
            })?;

        let line_separator = if let Some(s) = h.param(1) {
            if let Value::String(ref s) = *s.value() {
                s
            } else {
                return Err(RenderError::new(
                    "the provided line separator for the code lines was \
                 not a string",
                ));
            }
        } else {
            "<br>"
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

        for (i, line) in vulnerability
            .get("code")
            .unwrap()
            .as_str()
            .unwrap()
            .lines()
            .enumerate()
        {
            let line_number = i + iter_start as usize;

            let rendered = if line_number >= start_line as usize && line_number <= end_line as usize
            {
                let (indent, code) = split_indent(line);
                format!(
                    "<code class=\"vulnerable_line {}\">{}<span \
                 class=\"line_body\">{}</span></code>{}",
                    vulnerability.get("criticality").unwrap().as_str().unwrap(),
                    indent,
                    html_escape(code),
                    line_separator
                )
            } else {
                format!("{}{}", html_escape(line), line_separator)
            };

            out.write(&rendered)?;
        }

        Ok(())
    }
}

/// Generates the report index for the given vulnerability.
///
/// E.g.: for a critical vulnerability in an application with between 100 and 200 vulnerability,
/// for the critical vulnerability number 12 it would produce `C012`.
pub struct ReportIndex;

impl HelperDef for ReportIndex {
    fn call<'reg: 'rc, 'rc>(
        &self,
        h: &Helper<'_, '_>,
        _: &Registry<'_>,
        _: &Context,
        _: &mut RenderContext<'_, '_>,
        out: &mut dyn Output,
    ) -> Result<(), RenderError> {
        let vulnerability = h
            .param(0)
            .and_then(|v| v.value().as_object())
            .ok_or_else(|| {
                RenderError::new(
                "to generate the vulnerability index, the first parameter must be a vulnerability",
            )
            })?;
        let index = h.param(1).and_then(|v| v.value().as_u64()).ok_or_else(|| {
            RenderError::new(
                "the index of the vulnerability in the current list must be the second parameter",
            )
        })? as usize
            + 1;

        let list_len = h.param(2).unwrap().value().as_u64().unwrap();
        let char_index = vulnerability
            .get("criticality")
            .unwrap()
            .as_str()
            .unwrap()
            .to_uppercase()
            .chars()
            .next()
            .unwrap();

        let mut index_padding = (list_len as f64 + 1_f64).log10().ceil() as usize + 1;
        if index_padding < 2 {
            index_padding = 2;
        }
        let rendered = format!("{}{:#02$}", char_index, index, index_padding);
        out.write(&rendered)?;

        Ok(())
    }
}

/// Generates the menu for the source tree.
///
/// It will generate an unordered HTML list (`<ul>…</ul>`) where all files and folders of the given
/// menu object.
pub struct GenerateMenu;

impl HelperDef for GenerateMenu {
    fn call<'reg: 'rc, 'rc>(
        &self,
        h: &Helper<'_, '_>,
        _: &Registry<'_>,
        _: &Context,
        _: &mut RenderContext<'_, '_>,
        out: &mut dyn Output,
    ) -> Result<(), RenderError> {
        let menu = h
            .param(0)
            .and_then(|m| m.value().as_array())
            .ok_or_else(|| {
                RenderError::new("to generate the menu, the first parameter must be a menu array")
            })?;
        out.write("<ul>")?;
        render_menu(menu, out)?;
        out.write("</ul>")?;
        Ok(())
    }
}

/// Recursive menu rendering.
fn render_menu(menu: &[Value], renderer: &mut dyn Output) -> Result<(), RenderError> {
    for value in menu {
        if let Value::Object(ref item) = *value {
            renderer.write("<li>")?;
            let name = item
                .get("name")
                .and_then(Value::as_str)
                .ok_or_else(|| RenderError::new("invalid menu object type"))?;
            if let Some(&Value::Array(ref menu)) = item.get("menu") {
                renderer.write(
                    format!(
                        "<a href=\"#\" title=\"{0}\"><img src=\"../img/folder.svg\">{0}</a>",
                        name
                    )
                    .as_str(),
                )?;
                renderer.write("<ul>")?;

                render_menu(menu, renderer)?;
                renderer.write("</ul>")?;
            } else {
                let path = item
                    .get("path")
                    .and_then(Value::as_str)
                    .ok_or_else(|| RenderError::new("invalid menu object type"))?;
                let file_type = item
                    .get("type")
                    .and_then(Value::as_str)
                    .ok_or_else(|| RenderError::new("invalid menu object type"))?;
                renderer.write(
                    format!(
                        "<a href=\"{1}.html\" title=\"{0}\" target=\"code\"><img src=\"../img/{2}.svg\">{0}</a>",
                        name, path, file_type
                    ).as_str()
                )?;
            }
            renderer.write("</li>")?;
        } else {
            return Err(RenderError::new("invalid menu object type"));
        }
    }
    Ok(())
}
