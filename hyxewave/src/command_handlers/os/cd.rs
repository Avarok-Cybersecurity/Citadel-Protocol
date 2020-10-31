use super::super::imports::*;

pub fn handle<'a>(matches: &ArgMatches<'a>, ctx: &'a ConsoleContext, _ffi_io: Option<FFIIO>) -> Result<Option<KernelResponse>, ConsoleError> {
    let next_dir = matches.values_of("dir").unwrap().collect::<Vec<&str>>().join(" ");
    let (path, buf) = canonicalize_relative(ctx, next_dir)?;
    if !path.is_dir() {
        return Err(ConsoleError::Default("Not a directory"))
    }

    *ctx.active_dir.write() = PathBuf::from(buf);

    Ok(None)
}

/// Canonicalizes an input String w.r.t the console context. Does not update the context
/// This also returns a sanitized display-safe String of the path
pub fn canonicalize_relative(ctx: &ConsoleContext, append: String) -> Result<(PathBuf, String), ConsoleError> {
    let mut current_dir = ctx.active_dir.read().to_path_buf();
    current_dir.push(append);
    current_dir = current_dir.canonicalize().map_err(|err| ConsoleError::Generic(err.to_string()))?;
    let buf = current_dir.to_str().ok_or(ConsoleError::Default("Invalid format"))?;
    let buf = buf.replace(r#"\\?\"#, "");
    // clears the ugly \\?\ from the output (not sure why that shows)
    Ok((current_dir, buf))
}