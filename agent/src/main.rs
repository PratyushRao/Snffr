mod win_capture;

use crossbeam_channel::unbounded;

fn main() {
    let (tx, _rx) = unbounded();

    win_capture::start_capture(tx);

    loop {
        std::thread::park();
    }
}