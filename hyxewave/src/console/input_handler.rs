use std::io::Write;
use std::sync::atomic::Ordering;

use parking_lot::{const_rwlock, RwLock};
#[cfg(not(target_os = "windows"))]
use termion::raw::IntoRawMode;
use tokio::sync::mpsc::Sender;
use std::sync::atomic::AtomicBool;

use hyxe_crypt::prelude::SecString;

use crate::console::console_context::ConsoleContext;
use crate::console_error::ConsoleError;

const MAX_HISTORY_COUNT: usize = 50;
static DAEMON_MODE: AtomicBool = AtomicBool::new(false);

fn in_daemon_mode() -> bool {
    DAEMON_MODE.load(Ordering::Relaxed)
}

/// Sometimes, stdin input needs to be fed into the CLAP processor. Other times, input needs
/// to be routed to a custom target
pub struct InputRouterInner {
    destination: TargetDestination,
    buffer: Option<SecString>,
    // the cursor position w.r.t the buffer above
    inline_cursor_pos: u16,
    // back the internal buffer with a SecVec since this can be used to capture passwords
    target_custom: Option<std::sync::mpsc::Sender<SecString>>,
    custom_prompt: Option<Box<dyn Fn() + 'static>>,
    to_clap: Option<Sender<SecString>>,
    tab_command: Option<String>,
    history: InputHistory,
    #[cfg(not(target_os = "windows"))]
    raw_termion: Option<termion::raw::RawTerminal<std::io::Stdout>>,
    password_mode: bool,
}

struct InputHistory {
    history: Vec<String>,
    current_index: usize,
}

impl InputHistory {
    const fn new() -> Self {
        Self { history: Vec::new(), current_index: 0 }
    }

    /// whenever a non-up/down key is pressed, this should be called
    /// When [enter] is pressed, new_item should be Some
    #[allow(unused_results)]
    fn on_key_pressed(&mut self, new_item: Option<String>) {
        if let Some(next_line) = new_item {
            self.history.push(next_line);
            if self.history.len() == MAX_HISTORY_COUNT {
                // remove the 0th element
                self.history.remove(0);
            }
        }

        self.current_index = self.history.len();
    }

    fn on_vertical_direction_pressed(&mut self, up: bool) -> Option<String> {
        let current_item_count = self.history.len();
        if up {
            // if up is pressed, we go back in time (to the start indexes)
            self.current_index = self.current_index.saturating_sub(1);
        } else {
            // if down is pressed, we go forwards in time (to the end indexes)
            // We allow the max value to be current_item_count = len, which is 1 index higher than the highest index
            // We do this so that, in the case that the user tries to return to a clear prompt by
            // pressing down repetedly, once they get to the 50th index, there will be None returned,
            // thus enabling the calling closure to create a clear prompt as desired
            self.current_index = std::cmp::min(self.current_index + 1, current_item_count);
        }

        self.history.get(self.current_index).cloned()
    }
}

pub struct InputRouter {
    inner: RwLock<InputRouterInner>
}

enum TargetDestination {
    Clap,
    Custom,
}

impl InputRouter {
    #[cfg(target_os = "windows")]
    pub const fn new() -> Self {
        Self { inner: const_rwlock(InputRouterInner { to_clap: None, tab_command: None, inline_cursor_pos: 0, history: InputHistory::new(), destination: TargetDestination::Clap, buffer: Some(SecString::new()), target_custom: None, custom_prompt: None, password_mode: false }) }
    }

    #[cfg(not(target_os = "windows"))]
    pub const fn new() -> Self {
        Self { inner: const_rwlock(InputRouterInner { to_clap: None, tab_command: None, inline_cursor_pos: 0, history: InputHistory::new(), destination: TargetDestination::Clap, buffer: Some(SecString::new()), target_custom: None, custom_prompt: None, raw_termion: None, password_mode: false }) }
    }

    #[allow(unused_results)]
    pub fn register_clap_sender(&self, to_clap: &Sender<SecString>) {
        self.inner.write().to_clap.replace(to_clap.clone());
    }

    /// Updates the buffer and prints the character, considerate of whether or not PASSWD_MODE is on
    pub fn push(&self, input: char, ctx: &ConsoleContext) {
        let mut inner = self.inner.write();

        inner.history.on_key_pressed(None);
        inner.inline_cursor_pos = inner.inline_cursor_pos.saturating_add(1);
        let cursor_pos = inner.inline_cursor_pos as usize;
        let buffer = inner.buffer.as_mut().unwrap();
        if cursor_pos - 1 == buffer.len() {
            buffer.push(input);
            if inner.password_mode {
                colour::white!("*")
            } else {
                colour::white!("{}", input)
            }
        } else {
            // we are adding data in the middle of the buffer
            let insert_idx = cursor_pos.saturating_sub(1);
            buffer.insert(insert_idx, input);
            let new_buffer_len = buffer.len();
            // clear line and print prompt
            Self::clear_line();
            inner.print_prompt_inner(false, ctx);
            Self::move_cursor((new_buffer_len - cursor_pos) as i32 * -1)
        }
    }

    /// Updates the prompt, keeping into consideration the current prompt
    pub fn backspace(&self, ctx: &ConsoleContext) {
        let mut inner = self.inner.write();
        let InputRouterInner {
            buffer,
            history,
            inline_cursor_pos,
            ..
         } = &mut *inner;

        let buffer = buffer.as_mut().unwrap();
        if buffer.len() != 0 {
            //let idx_to_remove = inner.buffer.len() - 1;
            let idx_to_remove = inline_cursor_pos.saturating_sub(1);
            buffer.remove(idx_to_remove as usize);
            history.on_key_pressed(None);
            *inline_cursor_pos = idx_to_remove;

            let new_buffer_len = buffer.len();
            Self::clear_line();
            inner.print_prompt_inner(false, ctx);
            Self::move_cursor((new_buffer_len - idx_to_remove as usize) as i32 * -1)
        }
    }

    pub fn on_delete_key_pressed(&self, ctx: &ConsoleContext) {
        let mut inner = self.inner.write();
        let idx_to_remove = inner.inline_cursor_pos;
        let buffer = inner.buffer.as_mut().unwrap();
        if buffer.len() != 0 {
            //let idx_to_remove = inner.buffer.len() - 1;
            if (idx_to_remove as usize) < buffer.len() {
                buffer.remove(idx_to_remove as usize);
                let new_buffer_len = buffer.len();
                inner.history.on_key_pressed(None);
                //inner.inline_cursor_pos = idx_to_remove;

                Self::clear_line();
                inner.print_prompt_inner(false, ctx);
                Self::move_cursor((new_buffer_len - idx_to_remove as usize) as i32 * -1)
            }
        }
    }

    #[allow(unused_results)]
    pub fn on_tab_pressed(&self) {
        let mut write = self.inner.write();
        if let Some(cmd) = write.tab_command.take() {
            write.send_inner(SecString::from(cmd));
        }
    }

    /// this will overwrite any previous actions
    #[allow(unused_results)]
    pub fn register_tab_action<T: ToString>(&self, cmd: T) {
        self.inner.write().tab_command.replace(cmd.to_string());
    }

    pub fn print_prompt(&self, clear: bool, ctx: &ConsoleContext) {
        self.inner.read_recursive().print_prompt_inner(clear, ctx)
    }

    pub fn clear_line() {
        #[cfg(target_os = "windows")]
        crossterm::execute!(std::io::stdout(), crossterm::terminal::Clear(crossterm::terminal::ClearType::CurrentLine)).unwrap();
        #[cfg(not(target_os = "windows"))]
        print!("{}", termion::clear::CurrentLine);
        //print!("{}{}", 8u8 as char, termion::clear::AfterCursor);
    }

    pub fn on_horizantal_key_pressed(&self, right: bool) {
        let mut inner = self.inner.write();
        let buffer_len = inner.buffer.as_ref().unwrap().len();
        if right {
            if buffer_len != 0 {
                let proposed_pos = std::cmp::min(inner.inline_cursor_pos.saturating_add(1), buffer_len as u16);
                if (proposed_pos.saturating_sub(1) as usize) <= buffer_len {
                    inner.inline_cursor_pos = proposed_pos;
                    Self::move_cursor(1);
                }
            }
        } else {
            let proposed_pos = std::cmp::max(inner.inline_cursor_pos.saturating_sub(1), 0);
            if inner.inline_cursor_pos != 0 {
                inner.inline_cursor_pos = proposed_pos;
                Self::move_cursor(-1);
            }
        }
    }

    pub fn move_cursor(amount: i32) {
        if amount < 0 {
            #[cfg(target_os = "windows")] {
                crossterm::execute!(std::io::stdout(), crossterm::cursor::MoveLeft(amount.abs() as u16)).unwrap();
            }

            #[cfg(not(target_os = "windows"))] {
                crossterm::execute!(std::io::stdout(), crossterm::cursor::MoveLeft(amount.abs() as u16)).unwrap();
            }
        } else {
            #[cfg(target_os = "windows")] {
                crossterm::execute!(std::io::stdout(), crossterm::cursor::MoveRight(amount as u16)).unwrap();
            }

            #[cfg(not(target_os = "windows"))] {
                crossterm::execute!(std::io::stdout(), crossterm::cursor::MoveRight(amount as u16)).unwrap();
            }
        }
    }

    pub fn clear_screen() {
        #[cfg(target_os = "windows")] {
            crossterm::execute!(std::io::stdout(), crossterm::terminal::Clear(crossterm::terminal::ClearType::All)).unwrap();
        }

        #[cfg(not(target_os = "windows"))] {
            print!("{}", termion::clear::All);
        }
    }

    pub fn reset_cursor_position() {
        #[cfg(target_os = "windows")] {
            crossterm::execute!(std::io::stdout(), crossterm::cursor::MoveTo(0,0)).unwrap();
        }

        #[cfg(not(target_os = "windows"))] {
            print!("{}", termion::cursor::Goto(1, 1));
        }
    }

    /// Automatically routes the input to the correct destination
    /// called after pressing [enter]
    pub fn send_internal_buffer(&self) -> bool {
        let mut inner = self.inner.write();
        let input = inner.buffer.replace(SecString::new()).unwrap();
        //inner.buffer.clear();

        // don't save password to history, ever
        if !inner.password_mode {
            inner.history.on_key_pressed(Some(input.as_str().to_string()));
        }
        inner.inline_cursor_pos = 0;

        print!("\n\r");
        inner.send_inner(input)
    }

    #[allow(unused_results)]
    pub fn execute_command<T: ToString>(&self, cmd: T) {
        self.inner.write().send_inner(SecString::from(cmd.to_string()));
    }

    pub fn on_vertical_key_pressed(&self, up: bool, ctx: &ConsoleContext) {
        let mut write = self.inner.write();
        let leftover = write.history.on_vertical_direction_pressed(up).unwrap_or(String::new());
        // set the buffer before calling the prompt, but first reset the cursor to the end
        write.inline_cursor_pos = leftover.len() as u16;
        write.buffer.replace(SecString::from(leftover));
        // reprint the prompt, clearing the current line first
        Self::clear_line();
        write.print_prompt_inner(false, ctx)
    }

    /// Blocks the thread until data is received. Will reset the source upon completion
    pub fn read_line(&self, ctx: &ConsoleContext, prompt: Option<fn()>) -> String {
        self.read_line_inner(false, ctx, prompt).into_buffer()
    }

    /// Blocks the thread until data is received. Will reset the source upon completion
    pub fn read_password(&self, ctx: &ConsoleContext, prompt: Option<fn()>) -> String {
        self.read_line_inner(true, ctx, prompt).into_buffer()
    }

    fn read_line_inner(&self, password: bool, ctx: &ConsoleContext, prompt: Option<fn()>) -> SecString {
        let (tx, rx) = std::sync::mpsc::channel();
        let mut inner = self.inner.write();
        if let Some(prompt) = prompt {
            inner.custom_prompt.replace(Box::new(prompt));
            inner.print_prompt_inner(false, ctx);
        }

        inner.destination = TargetDestination::Custom;
        inner.target_custom.replace(tx);
        // setting this will ensure the output gets obfuscated
        inner.toggle_password(true, password);

        // drop inner to not block future calls
        std::mem::drop(inner);
        let output = rx.recv().unwrap();
        let mut inner = self.inner.write();
        // reset
        inner.toggle_password(false, password);
        inner.destination = TargetDestination::Clap;
        inner.custom_prompt = None;

        output
    }

    /// The windows version gets raw mode toggled on by default. However, this behavior is not preferred on linux because
    /// the prints to stdout become malformatted. Thus, there is a need to control when raw mode gets turned on
    #[cfg(not(target_os = "windows"))]
    pub fn toggle_raw_mode(&self, raw_mode: bool) {
        let inner = self.inner.read();
        inner.toggle_raw(raw_mode)
    }

    /// This shouldn't be called directly. Instead, call printf!().
    /// The reason you input a function is because you may want to print coloured text from
    /// the colour crate, and as such, use it
    pub fn print(&self, print: impl FnOnce()) {
        if !in_daemon_mode() {
            #[cfg(target_os = "windows")]
                {
                    print();
                }

            #[cfg(not(target_os = "windows"))]
                {
                    let inner = self.inner.read_recursive();
                    let raw_terminal = inner.raw_termion.as_ref().unwrap();
                    raw_terminal.suspend_raw_mode().unwrap();
                    print();
                    raw_terminal.activate_raw_mode().unwrap();
                }
        } else {
            // just print, as output will still need to be redirected
            print();
        }
    }

    #[cfg(target_os = "windows")]
    // Raw terminal mode can always be on for windows, whereas for linux, it cannot
    pub fn init(&self, daemon_mode: bool) -> Result<(), ConsoleError> {
        if daemon_mode {
            DAEMON_MODE.store(true, Ordering::Relaxed);
            Ok(())
        } else {
            self.inner.write().buffer.replace(SecString::new());
            crossterm::terminal::enable_raw_mode().map_err(|err| ConsoleError::Generic(err.to_string()))
        }
    }

    #[cfg(not(target_os = "windows"))]
    pub fn init(&self, daemon_mode: bool) -> Result<(), ConsoleError> {
        if daemon_mode {
            DAEMON_MODE.store(true, Ordering::Relaxed);
            Ok(())
        } else {
            let raw_terminal = std::io::stdout().into_raw_mode().map_err(|err| ConsoleError::Generic(err.to_string()))?;
            let mut write = self.inner.write();
            write.raw_termion.replace(raw_terminal);
            write.buffer.replace(SecString::new());
            Ok(())
        }
    }

    #[cfg(target_os = "windows")]
    pub fn deinit(&self) -> Result<(), ConsoleError> {
        if !in_daemon_mode() {
            Self::clear_screen();
            Self::reset_cursor_position();
            crossterm::terminal::disable_raw_mode().map_err(|err| ConsoleError::Generic(err.to_string()))
        } else {
            Ok(())
        }
    }

    #[cfg(not(target_os = "windows"))]
    pub fn deinit(&self) -> Result<(), ConsoleError> {
        if !in_daemon_mode() {
            let raw_terminal = self.inner.write().raw_termion.take().ok_or(ConsoleError::Default("Already turned off"))?;
            raw_terminal.suspend_raw_mode().unwrap();
            std::mem::drop(raw_terminal);
            Self::clear_screen();
            Self::reset_cursor_position();
        }

        Ok(())
    }
}

impl InputRouterInner {
    fn print_prompt_inner(&self, clear: bool, ctx: &ConsoleContext) {

        //self.toggle_raw(false);
        if clear {
            print!("\x1B[2J\x1B[1;1H");
        }
        // carriage return to go to beginning of line
        print!("\r");

        if let Some(print_custom_prompt) = self.custom_prompt.as_ref() {
            print_custom_prompt()
        } else {
            //println!("Will append: {}", leftover.as_str());
            if ctx.in_personal.load(Ordering::Relaxed) {
                let active_user = ctx.active_user.read();
                colour::green!("{} ", &active_user);
                colour::white!("{}", ctx.active_dir.read().display());
            } else {
                colour::green!("admin@");
                colour::white!("{}", &ctx.bind_addr);
            }

            colour::dark_yellow!(" >> ");
        }

        let leftover = self.buffer.as_ref().unwrap();
        let leftover = leftover.as_str();
        // finally, put whatever is in the buffer
        if self.password_mode {
            colour::white!("{}", (0..leftover.len()).into_iter().map(|_| "*").collect::<String>());
        } else {
            colour::white!("{}", leftover);
        }

        //self.toggle_raw(true);
    }

    fn toggle_password(&mut self, value: bool, password: bool) {
        if password {
            self.password_mode = value;
        }
    }

    /// This will panic if to_clap hasn't been registered
    fn send_inner(&mut self, input: SecString) -> bool {
        match self.destination {
            TargetDestination::Clap => {
                self.to_clap.as_mut().unwrap().try_send(input).is_ok()
            }

            TargetDestination::Custom => {
                self.target_custom.take().unwrap().send(input).is_ok()
            }
        }
    }

    #[cfg(not(target_os = "windows"))]
    fn toggle_raw(&self, raw_mode: bool) {
        if raw_mode {
            self.raw_termion.as_ref().unwrap().activate_raw_mode().unwrap();
        } else {
            self.raw_termion.as_ref().unwrap().suspend_raw_mode().unwrap();
        }
    }
}

unsafe impl Sync for InputRouter {}