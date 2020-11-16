use std::{sync::Mutex, io::stdin, io::stdout, sync::mpsc::Sender};
use termion::input::TermRead;

pub struct Terminal{
    tx: Mutex<Sender<u8>>,
}

impl Terminal{
    pub fn new(tx: Mutex<Sender<u8>>) -> Terminal { Terminal { tx } }

    pub fn handle_command(&mut self) {
        use termion::event::Key;
        use termion::raw::IntoRawMode;

        let stdin = stdin();
        let _stdout = stdout().into_raw_mode().unwrap();
        let mut command = String::new();

        for c in stdin.keys() {
            match c.unwrap() {
                Key::Ctrl('c') => self.tx.try_lock().unwrap().send(0x03).unwrap(),
                Key::Char(c) => {
                    command.push(c);
                    self.tx.try_lock().unwrap().send(c as u8).unwrap();
                    if c == '\n' { 
                        if command== "exit\n" || command == "logout\n" { break; }
                        command.clear();
                    }
                }
                Key::Backspace => self.tx.try_lock().unwrap().send(0x7f).unwrap(),
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
    }
}