// Copyright 2014-2017 The Rpassword Developers
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#[cfg(unix)]
extern crate libc;

#[cfg(windows)]
extern crate winapi;

mod zero_on_drop;
use zero_on_drop::ZeroOnDrop;

/// Removes the \n from the read line
fn fixes_newline(password: &mut ZeroOnDrop) {
    // We may not have a newline, e.g. if user sent CTRL-D or if
    // this is not a TTY.

    if password.ends_with('\n') {
        // Remove the \n from the line if present
        password.pop();

        // Remove the \r from the line if present
        if password.ends_with('\r') {
            password.pop();
        }
    }
}

/// Reads a password from STDIN
pub async fn read_password() -> ::std::io::Result<String> {
    read_password_with_reader(None::<tokio::io::Empty>).await
}

/// Reads a password from STDIN
pub fn read_password_blocking() -> ::std::io::Result<String> {
    read_password_with_reader_blocking(None::<std::io::Empty>)
}

#[cfg(unix)]
mod unix {
    use libc::{c_int, termios, isatty, tcsetattr, TCSANOW, ECHO, ECHONL, STDIN_FILENO};
    use std::io::{BufRead, Write};
    use std::mem;
    use std::os::unix::io::AsRawFd;

    /// Turns a C function return into an IO Result
    fn io_result(ret: c_int) -> ::std::io::Result<()> {
        match ret {
            0 => Ok(()),
            _ => Err(::std::io::Error::last_os_error()),
        }
    }

    fn safe_tcgetattr(fd: c_int) -> ::std::io::Result<termios> {
        let mut term = mem::MaybeUninit::<libc::termios>::uninit();
        io_result(unsafe { ::libc::tcgetattr(fd, term.as_mut_ptr()) })?;
        Ok(unsafe { term.assume_init() })
    }

    /// Reads a password from stdin
    pub async fn read_password_from_stdin(open_tty: bool) -> ::std::io::Result<String> {
        use tokio::io::AsyncBufReadExt;
        let mut password = super::ZeroOnDrop::new();

        enum Source {
            Tty(tokio::io::BufReader<tokio::fs::File>),
            Stdin(tokio::io::BufReader<tokio::io::Stdin>),
        }

        let (tty_fd, mut source) = if open_tty {
            let tty = tokio::fs::File::open("/dev/tty").await?;
            (tty.as_raw_fd(), Source::Tty(tokio::io::BufReader::new(tty)))
        } else {
            (STDIN_FILENO, Source::Stdin(tokio::io::BufReader::new(tokio::io::stdin())))
        };

        let input_is_tty = unsafe { isatty(tty_fd) } == 1;

        // When we ask for a password in a terminal, we'll want to hide the password as it is
        // typed by the user
        if input_is_tty {
            // Make two copies of the terminal settings. The first one will be modified
            // and the second one will act as a backup for when we want to set the
            // terminal back to its original state.
            let mut term      = safe_tcgetattr(tty_fd)?;
            let     term_orig = safe_tcgetattr(tty_fd)?;

            // Hide the password. This is what makes this function useful.
            term.c_lflag &= !ECHO;

            // But don't hide the NL character when the user hits ENTER.
            term.c_lflag |= ECHONL;

            // Save the settings for now.
            io_result(unsafe { tcsetattr(tty_fd, TCSANOW, &term) })?;

            // Read the password.
            let input = match source {
                Source::Tty(ref mut tty) => tty.read_line(&mut password).await,
                Source::Stdin(ref mut stdin) => stdin.read_line(&mut password).await,
            };

            // Reset the terminal.
            io_result(unsafe { tcsetattr(tty_fd, TCSANOW, &term_orig) })?;

            // Return if we have an error
            input?;
        } else {
            // If we don't have a TTY, the input was piped so we bypass
            // terminal hiding code
            match source {
                Source::Tty(mut tty) => tty.read_line(&mut password).await?,
                Source::Stdin(mut stdin) => stdin.read_line(&mut password).await?,
            };
        }

        super::fixes_newline(&mut password);

        Ok(password.into_inner())
    }

    /// Reads a password from stdin
    pub fn read_password_from_stdin_blocking(open_tty: bool) -> ::std::io::Result<String> {
        let mut password = super::ZeroOnDrop::new();

        enum Source {
            Tty(std::io::BufReader<std::fs::File>),
            Stdin(std::io::Stdin),
        }

        let (tty_fd, mut source) = if open_tty {
            let tty = std::fs::File::open("/dev/tty")?;
            (tty.as_raw_fd(), Source::Tty(std::io::BufReader::new(tty)))
        } else {
            (STDIN_FILENO, Source::Stdin(std::io::stdin()))
        };

        let input_is_tty = unsafe { isatty(tty_fd) } == 1;

        // When we ask for a password in a terminal, we'll want to hide the password as it is
        // typed by the user
        if input_is_tty {
            // Make two copies of the terminal settings. The first one will be modified
            // and the second one will act as a backup for when we want to set the
            // terminal back to its original state.
            let mut term      = safe_tcgetattr(tty_fd)?;
            let     term_orig = safe_tcgetattr(tty_fd)?;

            // Hide the password. This is what makes this function useful.
            term.c_lflag &= !ECHO;

            // But don't hide the NL character when the user hits ENTER.
            term.c_lflag |= ECHONL;

            // Save the settings for now.
            io_result(unsafe { tcsetattr(tty_fd, TCSANOW, &term) })?;

            // Read the password.
            let input = match source {
                Source::Tty(ref mut tty) => tty.read_line(&mut password),
                Source::Stdin(ref mut stdin) => stdin.read_line(&mut password),
            };

            // Reset the terminal.
            io_result(unsafe { tcsetattr(tty_fd, TCSANOW, &term_orig) })?;

            // Return if we have an error
            input?;
        } else {
            // If we don't have a TTY, the input was piped so we bypass
            // terminal hiding code
            match source {
                Source::Tty(mut tty) => tty.read_line(&mut password)?,
                Source::Stdin(stdin) => stdin.read_line(&mut password)?,
            };
        }

        super::fixes_newline(&mut password);

        Ok(password.into_inner())
    }

    /// Displays a prompt on the terminal
    pub fn display_on_tty(prompt: &str) -> ::std::io::Result<()> {
        let mut stream =
            ::std::fs::OpenOptions::new().write(true).open("/dev/tty")?;
        write!(stream, "{}", prompt)?;
        stream.flush()
    }
}

#[cfg(windows)]
mod windows {
    use std::ptr;
    use std::io::{self, Write};
    use std::os::windows::io::{FromRawHandle, AsRawHandle};
    use winapi::um::winnt::{
        GENERIC_READ, GENERIC_WRITE, FILE_SHARE_READ, FILE_SHARE_WRITE,
    };
    use winapi::um::fileapi::{CreateFileA, GetFileType, OPEN_EXISTING};
    use winapi::um::processenv::GetStdHandle;
    use winapi::um::winbase::{FILE_TYPE_PIPE, STD_INPUT_HANDLE};
    use winapi::um::handleapi::INVALID_HANDLE_VALUE;
    use winapi::um::consoleapi::{GetConsoleMode, SetConsoleMode};
    use winapi::shared::minwindef::LPDWORD;
    use winapi::um::wincon::{ENABLE_LINE_INPUT, ENABLE_PROCESSED_INPUT};
    use tokio::io::AsyncBufReadExt;

    /// Reads a password from stdin
    pub async fn read_password_from_stdin(open_tty: bool) -> io::Result<String> {
        let mut password = super::ZeroOnDrop::new();

        // Get the stdin handle
        let handle = if open_tty {
            unsafe {
                CreateFileA(b"CONIN$\x00".as_ptr() as *const i8,
                                      GENERIC_READ | GENERIC_WRITE,
                                      FILE_SHARE_READ | FILE_SHARE_WRITE,
                                      ptr::null_mut(), OPEN_EXISTING, 0,
                                      ptr::null_mut())
            }
        } else {
            unsafe {
                GetStdHandle(STD_INPUT_HANDLE)
            }
        };
        if handle == INVALID_HANDLE_VALUE {
            return Err(::std::io::Error::last_os_error());
        }

        let mut mode = 0;

        // Console mode does not apply when stdin is piped
        let handle_type = unsafe { GetFileType(handle) };
        if handle_type != FILE_TYPE_PIPE {
            // Get the old mode so we can reset back to it when we are done
            if unsafe { GetConsoleMode(handle, &mut mode as LPDWORD) } == 0 {
                return Err(::std::io::Error::last_os_error());
            }

            // We want to be able to read line by line, and we still want backspace to work
            let new_mode_flags = ENABLE_LINE_INPUT | ENABLE_PROCESSED_INPUT;
            if unsafe { SetConsoleMode(handle, new_mode_flags) } == 0 {
                return Err(::std::io::Error::last_os_error());
            }
        }

        // Read the password.
        let mut source = tokio::io::BufReader::new(tokio::io::stdin());
        let input = source.read_line(&mut password).await;
        //let handle = source.as_raw_handle();
        let handle = std::io::stdin().as_raw_handle();
        // Check the response.
        input?;

        if handle_type != FILE_TYPE_PIPE {
            // Set the the mode back to normal
            if unsafe { SetConsoleMode(handle, mode) } == 0 {
                return Err(::std::io::Error::last_os_error());
            }
        }

        super::fixes_newline(&mut password);

        // Newline for windows which otherwise prints on the same line.
        println!();

        Ok(password.into_inner())
    }

    /// Reads a password from stdin
    pub fn read_password_from_stdin_blocking(open_tty: bool) -> io::Result<String> {
        let mut password = super::ZeroOnDrop::new();

        // Get the stdin handle
        let handle = if open_tty {
            unsafe {
                CreateFileA(b"CONIN$\x00".as_ptr() as *const i8,
                            GENERIC_READ | GENERIC_WRITE,
                            FILE_SHARE_READ | FILE_SHARE_WRITE,
                            ptr::null_mut(), OPEN_EXISTING, 0,
                            ptr::null_mut())
            }
        } else {
            unsafe {
                GetStdHandle(STD_INPUT_HANDLE)
            }
        };
        if handle == INVALID_HANDLE_VALUE {
            return Err(::std::io::Error::last_os_error());
        }

        let mut mode = 0;

        // Console mode does not apply when stdin is piped
        let handle_type = unsafe { GetFileType(handle) };
        if handle_type != FILE_TYPE_PIPE {
            // Get the old mode so we can reset back to it when we are done
            if unsafe { GetConsoleMode(handle, &mut mode as LPDWORD) } == 0 {
                return Err(::std::io::Error::last_os_error());
            }

            // We want to be able to read line by line, and we still want backspace to work
            let new_mode_flags = ENABLE_LINE_INPUT | ENABLE_PROCESSED_INPUT;
            if unsafe { SetConsoleMode(handle, new_mode_flags) } == 0 {
                return Err(::std::io::Error::last_os_error());
            }
        }

        // Read the password.
        let source = std::io::stdin();
        let input = source.read_line(&mut password);
        let handle = source.as_raw_handle();

        // Check the response.
        input?;

        if handle_type != FILE_TYPE_PIPE {
            // Set the the mode back to normal
            if unsafe { SetConsoleMode(handle, mode) } == 0 {
                return Err(::std::io::Error::last_os_error());
            }
        }

        super::fixes_newline(&mut password);

        // Newline for windows which otherwise prints on the same line.
        println!();

        Ok(password.into_inner())
    }

    /// Displays a prompt on the terminal
    pub fn display_on_tty(prompt: &str) -> ::std::io::Result<()> {
        let handle = unsafe {
            CreateFileA(b"CONOUT$\x00".as_ptr() as *const i8,
                                  GENERIC_READ | GENERIC_WRITE,
                                  FILE_SHARE_READ | FILE_SHARE_WRITE,
                                  ::std::ptr::null_mut(), OPEN_EXISTING, 0,
                                  ::std::ptr::null_mut())
        };
        if handle == INVALID_HANDLE_VALUE {
            return Err(::std::io::Error::last_os_error());
        }

        let mut stream = unsafe {
            std::fs::File::from_raw_handle(handle)
        };

        write!(stream, "{}", prompt)?;
        stream.flush()
    }
}


#[cfg(unix)]
use unix::{read_password_from_stdin, display_on_tty, read_password_from_stdin_blocking};
#[cfg(windows)]
use windows::{read_password_from_stdin, display_on_tty, read_password_from_stdin_blocking};

/// Reads a password from anything that implements BufRead
pub async fn read_password_with_reader<T>(source: Option<T>) -> ::std::io::Result<String>
    where T: tokio::io::AsyncBufReadExt + Unpin {
    match source {
        Some(mut reader) => {
            let mut password = ZeroOnDrop::new();
            reader.read_line(&mut password).await?;
            fixes_newline(&mut password);
            Ok(password.into_inner())
        },
        None => read_password_from_stdin(false).await,
    }
}

/// Reads a password from anything that implements BufRead
pub fn read_password_with_reader_blocking<T>(source: Option<T>) -> ::std::io::Result<String>
    where T: std::io::BufRead + Unpin {
    match source {
        Some(mut reader) => {
            let mut password = ZeroOnDrop::new();
            reader.read_line(&mut password)?;
            fixes_newline(&mut password);
            Ok(password.into_inner())
        },
        None => read_password_from_stdin_blocking(false),
    }
}

/// Reads a password from the terminal
pub async fn read_password_from_tty(prompt: Option<&str>)
                              -> ::std::io::Result<String> {
    if let Some(prompt) = prompt {
        display_on_tty(prompt)?;
    }
    read_password_from_stdin(true).await
}

/// Prompts for a password on STDOUT and reads it from STDIN
pub async fn prompt_password_stdout(prompt: &str) -> std::io::Result<String> {
    use std::io::Write;
    let mut stdout = std::io::stdout();

    write!(stdout, "{}", prompt)?;
    stdout.flush()?;
    read_password().await
}

/// Prompts for a password on STDERR and reads it from STDIN
pub async fn prompt_password_stderr(prompt: &str) -> std::io::Result<String> {
    use std::io::Write;
    let mut stderr = std::io::stderr();

    write!(stderr, "{}", prompt)?;
    stderr.flush()?;
    read_password().await
}
