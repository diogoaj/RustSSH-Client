use std::{sync::Mutex, io::stdin, io::stdout, sync::mpsc::Sender};
use termion::input::TermRead;

pub struct Terminal{
    tx: Mutex<Sender<Vec<u8>>>,
}

impl Terminal{
    pub fn new(tx: Mutex<Sender<Vec<u8>>>) -> Terminal { Terminal { tx } }

    pub fn handle_command(&mut self) {
        use termion::event::Key;
        use termion::raw::IntoRawMode;

        let stdin = stdin();
        let _stdout = stdout().into_raw_mode().unwrap();
        let mut command = String::new();

        for c in stdin.keys() {
            match c.unwrap() {
                Key::Ctrl('c') => self.tx.try_lock().unwrap().send(vec![0x03]).unwrap(),
                Key::Ctrl('l') => self.tx.try_lock().unwrap().send(vec![0x0c]).unwrap(),
                Key::Char(c) => {
                    command.push(c);
                    self.tx.try_lock().unwrap().send(vec![c as u8]).unwrap();
                    if c == '\n' { 
                        if command == "exit\n" || command == "logout\n" { break; }
                        command.clear();
                    }
                }
                Key::Backspace => self.tx.try_lock().unwrap().send(vec![0x7f]).unwrap(),
                Key::Up => self.tx.try_lock().unwrap().send(vec![0x1b, 0x5b, 0x41]).unwrap(),
                Key::Down => self.tx.try_lock().unwrap().send(vec![0x1b, 0x5b, 0x42]).unwrap(),
                _ => {}
            }  
        }
    }
}