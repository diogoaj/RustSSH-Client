use std::{io, io::stdin, io::stdout, sync::mpsc::Sender, sync::Mutex};
use termion::event::Key;
use termion::input::TermRead;
use termion::raw::IntoRawMode;

pub struct Terminal {
    tx: Mutex<Sender<Vec<u8>>>,
}

impl Terminal {
    pub fn new(tx: Mutex<Sender<Vec<u8>>>) -> Terminal {
        Terminal { tx }
    }

    pub fn handle_command(&mut self) {
        let stdin = stdin();
        let _stdout = stdout().into_raw_mode().unwrap();
        let mut command = String::new();

        for c in stdin.keys() {
            match c.unwrap() {
                Key::Ctrl(c) => {
                    self.tx
                        .try_lock()
                        .unwrap()
                        .send(vec![(c as u8) - 96])
                        .unwrap();

                    // Handle Ctrl + d
                    if c == 'd' {
                        break;
                    }
                }
                Key::Char(c) => {
                    command.push(c);
                    self.tx.try_lock().unwrap().send(vec![c as u8]).unwrap();
                    if c == '\n' {
                        if command.contains("exit") || command.contains("logout") {
                            break;
                        }
                        command.clear();
                    }
                }
                Key::Backspace => self.tx.try_lock().unwrap().send(vec![0x7f]).unwrap(),
                Key::Up => self
                    .tx
                    .try_lock()
                    .unwrap()
                    .send(vec![0x1b, 0x5b, 0x41])
                    .unwrap(),
                Key::Down => self
                    .tx
                    .try_lock()
                    .unwrap()
                    .send(vec![0x1b, 0x5b, 0x42])
                    .unwrap(),
                Key::Right => self
                    .tx
                    .try_lock()
                    .unwrap()
                    .send(vec![0x1b, 0x5b, 0x43])
                    .unwrap(),
                Key::Left => self
                    .tx
                    .try_lock()
                    .unwrap()
                    .send(vec![0x1b, 0x5b, 0x44])
                    .unwrap(),
                Key::Esc => self.tx.try_lock().unwrap().send(vec![0x1b]).unwrap(),
                _ => {}
            }
        }
    }
}

pub fn get_terminal_size() -> io::Result<(u16, u16)> {
    termion::terminal_size()
}
