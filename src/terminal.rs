use std::{sync::Mutex, io::stdin, io::stdout, sync::mpsc::Sender};
use termion::input::TermRead;

pub struct Terminal{
    tx: Mutex<Sender<u8>>,
}

impl Terminal{
    pub fn new(tx: Mutex<Sender<u8>>) -> Terminal { Terminal { tx } }

    pub fn handle_command(&mut self) -> usize{
        use termion::event::Key;
        use termion::raw::IntoRawMode;

        let stdin = stdin();
        let _stdout = stdout().into_raw_mode().unwrap();

        for c in stdin.keys() {
            match c.unwrap() {
                Key::Char('\n') => {
                    self.tx.try_lock().unwrap().send('\n' as u8).unwrap();
                }
                Key::Ctrl('c') => return 1,
                Key::Char(c) => {
                    self.tx.try_lock().unwrap().send(c as u8).unwrap();
                }
                //Key::Alt(c) => print!("^{}", c),
                //Key::Ctrl(c) => print!("*{}", c),
                //Key::Esc => print!("ESC"),
                //Key::Left => print!("←"),
                //Key::Right => print!("→"),
                //Key::Up => print!("↑"),
                //Key::Down => print!("↓"),
                //Key::Backspace => print!("×"),
                _ => {}
            }  
        }
        0
    }
}