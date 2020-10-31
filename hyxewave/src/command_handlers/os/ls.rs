use super::super::imports::*;

pub fn handle(ctx: &ConsoleContext, _ffi_io: Option<FFIIO>) -> Result<Option<KernelResponse>, ConsoleError> {
    let current_directory = ctx.active_dir.read();
    let mut dirs = current_directory.read_dir().map_err(|err| ConsoleError::Generic(err.to_string()))?.into_iter();

    printfs!({
        let mut count = 0;

        while let Some(Ok(entry)) = dirs.next() {
            let buf = entry.file_name();
            colour::white_ln!("{}", buf.to_str().unwrap_or("INVALID ENCODING"));
            count +=1;
        }

        if count == 0 {
            colour::yellow_ln!("Current directory empty\n")
        } else {
            println!();
        }
    });

    Ok(None)
}