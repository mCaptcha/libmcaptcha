/*
 * mCaptcha - A proof of work based DoS protection system
 * Copyright © 2022 Aravinth Manivannan <realravinth@batsense.net>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */
use std::collections::HashMap;
use std::collections::VecDeque;
//use std::sync::crossbeam_channel::{self, Receiver, Sender, Sender};
use std::sync::{Arc, RwLock};
//use tokio::sync::oneshot::{Receiver as Receiver, Sender as Sender, self};
use std::thread::{self, JoinHandle};

use pow_sha256::{Config, PoW};

use crossbeam_channel::{self, Receiver, Sender};
use println as debug;

trait Runnable {
    type Output;
    fn run(&self) -> Self::Output;
}

#[derive(Debug)]
pub struct QueuedWork {
    tx: Sender<bool>,
    pow: Arc<Config>,
    work: PoW<String>,
    string: String,
    difficulty_factor: u32,
}

impl QueuedWork {
    pub fn new(
        pow: Arc<Config>,
        work: PoW<String>,
        string: String,
        difficulty_factor: u32,
    ) -> (Self, Receiver<bool>) {
        let (tx, rx) = crossbeam_channel::bounded(2);
        (
            Self {
                tx,
                pow,
                work,
                difficulty_factor,
                string,
            },
            rx,
        )
    }
    fn validate(self) {
        //        let res = self
        //            .pow
        //            .is_sufficient_difficulty(self.pow.as_ref(), self.difficulty_factor);

        if !self
            .pow
            .is_sufficient_difficulty(&self.work, self.difficulty_factor)
        {
            if let Err(e) = self.tx.send(false) {
                debug!("[ERROR] unable to send work result: {e}");
            }
        }

        if !self.pow.is_valid_proof(&self.work, &self.string) {
            if let Err(e) = self.tx.send(false) {
                debug!("[ERROR] unable to send work result: {e}");
            }
        }

        if let Err(e) = self.tx.send(true) {
            debug!("[ERROR] unable to send work result: {e}");
        }
    }
}

enum Message {
    Stop,
    Prove(QueuedWork),
}

struct RunnerThread {
    tx: Sender<Message>,
    thread: JoinHandle<()>,
}

impl RunnerThread {
    pub fn spawn() -> Self {
        let (tx, rx) = crossbeam_channel::unbounded();

        let thread = thread::spawn(move || Self::run(&rx));
        Self { tx, thread }
    }

    fn run(rx: &Receiver<Message>) {
        println!("Spawned thread");
        loop {
            if let Ok(msg) = rx.recv() {
                match msg {
                    Message::Stop => return,
                    Message::Prove(w) => w.validate(),
                }
            }
        }
    }
}

struct InnerManager {
    queues: Arc<RwLock<HashMap<Arc<String>, RwLock<VecDeque<QueuedWork>>>>>,
    runners: Vec<RunnerThread>,
    ips: Arc<RwLock<Vec<Arc<String>>>>,
    currnet_index: RwLock<usize>,
}

type InnerManagerQueue = Arc<RwLock<HashMap<Arc<String>, RwLock<VecDeque<QueuedWork>>>>>;
type InnerManagerIP = Arc<RwLock<Vec<Arc<String>>>>;

impl Drop for InnerManager {
    fn drop(&mut self) {
        for r in self.runners.iter() {
            r.tx.send(Message::Stop).unwrap();
        }
        for r in self.runners.drain(0..) {
            r.thread.join().unwrap()
        }
    }
}

impl InnerManager {
    fn dispatch(&self) {
        for r in self.runners.iter() {
            let ip_vec_len = { self.ips.read().unwrap().len() };
            let mut currnet_index = { self.currnet_index.read().unwrap().clone() };

            if currnet_index < ip_vec_len {
                currnet_index += 1
            } else {
                currnet_index = 0;
            }

            {
                *(self.currnet_index.write().unwrap()) = currnet_index;
            }

            if let Some(ip) = self
                .ips
                .read()
                .unwrap()
                .get(*self.currnet_index.read().unwrap())
            {
                if let Some(ip_queue) = self.queues.read().unwrap().get(ip) {
                    if let Some(work) = ip_queue.write().unwrap().pop_front() {
                        if let Err(e) = r.tx.send(Message::Prove(work)) {
                            debug!("[ERROR] unable to schedule work on thread: {e}");
                        }
                    }
                }
            }
        }
    }

    fn new(workers: usize) -> Self {
        let mut runners = Vec::with_capacity(workers);
        for _ in 0..workers {
            runners.push(RunnerThread::spawn());
        }
        let queues = Arc::new(RwLock::new(HashMap::default()));
        let ips = Arc::new(RwLock::new(Vec::default()));
        InnerManager {
            queues: queues.clone(),
            runners,
            ips: ips.clone(),
            currnet_index: RwLock::new(0),
        }
    }

    fn spawn(im: InnerManager, rx: Receiver<()>) -> JoinHandle<()> {
        thread::spawn(move || loop {
            if let Ok(_) = rx.try_recv() {
                drop(im);
                break;
            } else {
                im.dispatch()
            };
        })
    }
}

pub struct Manager {
    stop_dispatch_runner: Sender<()>,
    queues: InnerManagerQueue,
    ips: InnerManagerIP,
    dispatch_runner: Option<JoinHandle<()>>,
}

impl Drop for Manager {
    fn drop(&mut self) {
        self.stop_dispatch_runner.send(()).unwrap();
        let dispatch_runner = self.dispatch_runner.take().unwrap();
        dispatch_runner.join().unwrap();
    }
}

impl Manager {
    pub fn new(workers: usize) -> Self {
        let (tx, rx) = crossbeam_channel::unbounded();
        let im = InnerManager::new(workers);

        let queues = im.queues.clone();
        let ips = im.ips.clone();
        let j = thread::spawn(move || {
            InnerManager::spawn(im, rx);
        });

        Manager {
            dispatch_runner: Some(j),
            stop_dispatch_runner: tx,
            queues,
            ips,
        }
    }

    pub fn add(&self, ip: String, work: QueuedWork) {
        if let Some(queue) = self.queues.read().unwrap().get(&ip) {
            queue.write().unwrap().push_back(work);
            return;
        }

        let queue = {
            let mut queue = VecDeque::with_capacity(1);
            queue.push_back(work);
            RwLock::new(queue)
        };
        let ip = Arc::new(ip);
        self.queues.write().unwrap().insert(ip.clone(), queue);
        self.ips.write().unwrap().push(ip);
    }
}

//#[cfg(test)]
//mod tests {
//    use std::time::Duration;
//
//    use super::*;
//
//    impl Manager {
//        fn add_works(&self) {
//            const IP: &str = "foo bar";
//
//            let (w, rx) = QueuedWork::new("1".to_string());
//
//            {
//                self.add(IP.into(), w);
//                assert_eq!(self.queues.read().unwrap().len(), 1);
//            }
//
//            let (w2, rx2) = QueuedWork::new("2".into());
//            {
//                self.add(IP.into(), w2);
//                assert_eq!(self.queues.read().unwrap().len(), 1);
//            }
//
//            thread::sleep(Duration::new(2, 0));
//            assert!(rx.recv().unwrap());
//            assert!(rx2.recv().unwrap());
//        }
//    }
//
//    #[test]
//    fn manager_works() {
//        let manager = Manager::new(4);
//
//        manager.add_works();
//        drop(manager);
//    }
//
//    #[test]
//    fn abuse_manager() {
//        let num_threads = 18;
//        let manager = Arc::new(Manager::new(num_threads));
//
//        let mut threads = Vec::with_capacity(num_threads);
//        for t in 0..num_threads {
//            let m = manager.clone();
//            let j = thread::spawn(move || {
//                let num_jobs = 100000;
//                let mut jobs = Vec::with_capacity(num_jobs);
//                for i in 0..num_jobs {
//                    let (w, rx) = QueuedWork::new(format!("thread {t} job {i}"));
//                    jobs.push(rx);
//                    m.add(i.to_string(), w);
//                }
//                let mut err = false;
//
//                let mut count = 0;
//
//                for rx in jobs.drain(..0) {
//                    loop {
//                        match rx.try_recv() {
//                            Err(crossbeam_channel::TryRecvError::Empty) => continue,
//                            Err(crossbeam_channel::TryRecvError::Disconnected) => panic!("{count}"),
//                            Ok(t) => {
//                                count += 1;
//                                assert!(t);
//                                break;
//                            }
//                        };
//                    }
//                }
//
//                if err {
//                    panic!()
//                }
//                true
//            });
//            threads.push(j);
//        }
//        for t in threads.drain(0..) {
//            assert!(t.join().unwrap());
//        }
//    }
//}
