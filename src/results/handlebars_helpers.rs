use handlebars::{Context, Helper, Handlebars, RenderContext, RenderError, JsonRender};

fn line_numbers(c: &Context,
                h: &Helper,
                _: &Handlebars,
                rc: &mut RenderContext)
                -> Result<(), RenderError> {
    let vulnerability = h.param(0).unwrap();

    let rendered = format!("{:?}", vulnerability.value().render());
    try!(rc.writer.write(rendered.into_bytes().as_ref()));
    Ok(())
}
