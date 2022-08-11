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
use std::sync::{Arc, RwLock};
use std::thread::{self, JoinHandle};

use crossbeam_channel::{self, Receiver, Sender};
use log::debug;

use crate::errors::*;

enum Message {
    Stop,
    Prove(Box<dyn Runnable>),
}

struct RunnerThread {
    tx: Sender<Message>,
    thread: JoinHandle<()>,
}

pub trait Runnable: Send + Sync {
    fn run(&self);
}

impl RunnerThread {
    pub fn spawn(name: usize, tx_manager: Sender<InnerManagerMessage>) -> Self {
        let (tx, rx) = crossbeam_channel::unbounded();

        let thread = thread::spawn(move || Self::run(name, &rx, &tx_manager));
        Self { tx, thread }
    }

    fn run(name: usize, rx: &Receiver<Message>, tx_manager: &Sender<InnerManagerMessage>) {
        loop {
            if let Ok(msg) = rx.recv() {
                match msg {
                    Message::Stop => return,
                    Message::Prove(r) => {
                        r.run();
                        if tx_manager
                            .send(InnerManagerMessage::Dispatch(name))
                            .is_err()
                        {
                            // inner manager is dead
                            return;
                        }
                    }
                };
            }
        }
    }
}

type InnerManagerQueue = Arc<RwLock<HashMap<Arc<String>, RwLock<VecDeque<Box<dyn Runnable>>>>>>;
type InnerManagerIP = Arc<RwLock<Vec<Arc<String>>>>;

struct InnerManager {
    queues: InnerManagerQueue,
    runners: HashMap<usize, RunnerThread>,
    ips: InnerManagerIP,
    currnet_index: RwLock<usize>,
}

impl Drop for InnerManager {
    fn drop(&mut self) {
        for (_, r) in self.runners.iter() {
            r.tx.send(Message::Stop).unwrap();
        }
        for (_, r) in self.runners.drain() {
            r.thread.join().unwrap()
        }
    }
}

enum InnerManagerMessage {
    Stop,
    Dispatch(usize),
    DispatchAll,
}

impl InnerManager {
    fn dispatch_to(&self, name: usize) {
        if let Some(r) = self.runners.get(&name) {
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
    fn dispatch(&self) {
        for (name, _) in self.runners.iter() {
            self.dispatch_to(*name)
        }
    }

    fn new(tx: Sender<InnerManagerMessage>, workers: usize) -> Self {
        let mut runners = HashMap::with_capacity(workers);
        for name in 0..workers {
            runners.insert(name, RunnerThread::spawn(name, tx.clone()));
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

    fn spawn(im: InnerManager, rx: Receiver<InnerManagerMessage>) -> JoinHandle<()> {
        thread::spawn(move || loop {
            if let Ok(m) = rx.recv() {
                match m {
                    InnerManagerMessage::Stop => {
                        drop(im);
                        break;
                    }
                    InnerManagerMessage::DispatchAll => im.dispatch(),
                    InnerManagerMessage::Dispatch(name) => im.dispatch_to(name),
                }
            }
        })
    }
}

pub struct Manager {
    stop_dispatch_runner: Sender<InnerManagerMessage>,
    queues: InnerManagerQueue,
    ips: InnerManagerIP,
    dispatch_runner: Option<JoinHandle<()>>,
    queue_length: usize,
}

impl Drop for Manager {
    fn drop(&mut self) {
        self.stop_dispatch_runner
            .send(InnerManagerMessage::Stop)
            .unwrap();
        let dispatch_runner = self.dispatch_runner.take().unwrap();
        dispatch_runner.join().unwrap();
    }
}

impl Manager {
    pub fn new(workers: usize, queue_length: usize) -> Self {
        let (tx, rx) = crossbeam_channel::unbounded();
        let im = InnerManager::new(tx.clone(), workers);

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
            queue_length,
        }
    }

    pub fn add(&self, ip: String, job: Box<dyn Runnable>) -> CaptchaResult<()> {
        {
            if self.queues.read().unwrap().len() == self.queue_length {
                return Err(CaptchaError::QueueFull);
            }
        }
        if let Some(queue) = self.queues.read().unwrap().get(&ip) {
            queue.write().unwrap().push_back(job);
            self.stop_dispatch_runner
                .send(InnerManagerMessage::DispatchAll);
            return Ok(());
        }

        let queue = {
            let mut queue = VecDeque::with_capacity(1);
            queue.push_back(job);
            RwLock::new(queue)
        };
        let ip = Arc::new(ip);
        self.queues.write().unwrap().insert(ip.clone(), queue);
        self.ips.write().unwrap().push(ip);
        self.stop_dispatch_runner
            .send(InnerManagerMessage::DispatchAll);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;

    #[derive(Debug)]
    pub struct MockedRunnable {
        tx: Sender<bool>,
        pub tag: String,
    }

    impl MockedRunnable {
        fn new(tag: String) -> (Box<Self>, Receiver<bool>) {
            let (tx, rx) = crossbeam_channel::bounded(2);
            (Box::new(Self { tx, tag }), rx)
        }
    }

    impl Runnable for MockedRunnable {
        fn run(&self) {
            if let Err(e) = self.tx.send(true) {
                debug!("[ERROR][{}] send failed: {e}", self.tag)
            }
        }
    }

    impl Manager {
        fn add_works(&self) {
            const IP: &str = "foo bar";

            let (w, rx) = MockedRunnable::new("1".to_string());

            {
                self.add(IP.into(), w).unwrap();
                assert_eq!(self.queues.read().unwrap().len(), 1);
            }

            let (w2, rx2) = MockedRunnable::new("2".into());
            {
                self.add(IP.into(), w2).unwrap();
                assert_eq!(self.queues.read().unwrap().len(), 1);
            }

            thread::sleep(Duration::new(2, 0));
            assert!(rx.recv().unwrap());
            assert!(rx2.recv().unwrap());
        }
    }

    #[test]
    fn manager_works() {
        let manager = Manager::new(4, 10);

        manager.add_works();
        drop(manager);
    }

    #[test]
    fn abuse_manager() {
        let num_threads = 18;
        let num_jobs = 100_000;
        let manager = Arc::new(Manager::new(num_threads, num_jobs * num_threads));

        let mut threads = Vec::with_capacity(num_threads);
        for t in 0..num_threads {
            let m = manager.clone();
            let j = thread::spawn(move || {
                let mut jobs = Vec::with_capacity(num_jobs);
                for i in 0..num_jobs {
                    let (w, rx) = MockedRunnable::new(format!("thread {t} job {i}"));
                    jobs.push(rx);
                    m.add(i.to_string(), w).unwrap();
                }

                let mut count = 0;

                for rx in jobs.drain(..0) {
                    loop {
                        match rx.recv() {
                            Err(crossbeam_channel::RecvError) => panic!("{count}"),
                            Ok(t) => {
                                count += 1;
                                assert!(t);
                                break;
                            }
                        };
                    }
                }

                true
            });
            threads.push(j);
        }
        for t in threads.drain(0..) {
            assert!(t.join().unwrap());
        }
    }
}
