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
use std::rc::Rc;
use std::thread::{self, JoinHandle};

use crossbeam_channel::{self, Receiver, Sender};
use log::debug;
use log::error;
use tokio::sync::oneshot::{self, Receiver as OneshotReceiver, Sender as OneshotSender};

use crate::errors::*;

enum Message {
    Stop,
    Prove(Box<dyn Runnable>),
}

struct RunnerThread {
    tx: Sender<Message>,
    thread: Option<JoinHandle<()>>,
}

pub trait Runnable: Send + Sync {
    fn run(&self);
}

impl RunnerThread {
    pub fn spawn(name: usize, tx_manager: Sender<InnerManagerMessage>) -> Self {
        let (tx, rx) = crossbeam_channel::unbounded();

        let thread = Some(thread::spawn(move || Self::run(name, &rx, &tx_manager)));
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

pub struct ScheduleWork {
    job: Box<dyn Runnable>,
    tx: OneshotSender<CaptchaResult<()>>,
    ip: String,
}

impl ScheduleWork {
    pub fn new(job: Box<dyn Runnable>, ip: String) -> (Self, OneshotReceiver<CaptchaResult<()>>) {
        let (tx, rx) = oneshot::channel();
        (Self { ip, job, tx }, rx)
    }
}

enum InnerManagerMessage {
    Stop,
    Dispatch(usize),
    Schedule(ScheduleWork),
}

type InnerManagerQueue = HashMap<Rc<String>, VecDeque<Box<dyn Runnable>>>;
type InnerManagerIP = Vec<Rc<String>>;

struct InnerManager {
    queues: InnerManagerQueue,
    runners: HashMap<usize, RunnerThread>,
    ips: InnerManagerIP,
    currnet_index: usize,
    queue_length: usize,
}

impl Drop for InnerManager {
    fn drop(&mut self) {
        for (_, r) in self.runners.iter() {
            r.tx.send(Message::Stop).unwrap();
        }
        for (_, r) in self.runners.iter_mut() {
            if let Some(thread) = r.thread.take() {
                thread.join().unwrap()
            }
        }
    }
}

impl InnerManager {
    fn dispatch_to(&mut self, name: usize) {
        if let Some(r) = self.runners.get(&name) {
            let ip_vec_len = { self.ips.len() };

            if self.currnet_index < ip_vec_len - 1 {
                self.currnet_index += 1
            } else {
                self.currnet_index = 0;
            }

            let ip = self.ips.get(self.currnet_index).unwrap();
            let ip_queue = self.queues.get_mut(ip).unwrap();
            if let Some(work) = ip_queue.pop_front() {
                r.tx.send(Message::Prove(work)).unwrap();
            }
        }
    }

    fn dispatch(&mut self) {
        for name in 0..self.runners.len() {
            if !self.runners.contains_key(&name) {
                panic!("unable to find thread: {name}");
            } else {
                self.dispatch_to(name)
            }
        }
    }

    fn new(tx: Sender<InnerManagerMessage>, workers: usize, queue_length: usize) -> Self {
        let mut runners = HashMap::with_capacity(workers);
        for name in 0..workers {
            runners.insert(name, RunnerThread::spawn(name, tx.clone()));
        }
        let queues = HashMap::default();
        let ips = Vec::default();
        InnerManager {
            queues,
            runners,
            ips,
            currnet_index: 0,
            queue_length,
        }
    }

    pub fn schedule(&mut self, ip: String, job: Box<dyn Runnable>) -> CaptchaResult<()> {
        if self.queues.len() == self.queue_length {
            return Err(CaptchaError::QueueFull);
        }
        if let Some(queue) = self.queues.get_mut(&ip) {
            queue.push_back(job);
            self.dispatch();
            return Ok(());
        }

        let mut queue = VecDeque::with_capacity(1);
        queue.push_back(job);
        let ip = Rc::new(ip);
        self.queues.insert(ip.clone(), queue);
        self.ips.push(ip);
        self.dispatch();
        Ok(())
    }

    fn run(mut im: InnerManager, rx: Receiver<InnerManagerMessage>) {
        loop {
            if let Ok(m) = rx.recv() {
                match m {
                    InnerManagerMessage::Stop => {
                        drop(im);
                        break;
                    }
                    InnerManagerMessage::Dispatch(name) => im.dispatch_to(name),
                    InnerManagerMessage::Schedule(job) => {
                        let res = im.schedule(job.ip, job.job);
                        let _ = job.tx.send(res);
                    }
                }
            }
        }
    }
}

pub struct Manager {
    manager_tx: Sender<InnerManagerMessage>,
    dispatch_runner: Option<JoinHandle<()>>,
}

impl Drop for Manager {
    fn drop(&mut self) {
        self.manager_tx.send(InnerManagerMessage::Stop).unwrap();
        let dispatch_runner = self.dispatch_runner.take().unwrap();
        dispatch_runner.join().unwrap();
    }
}

impl Manager {
    pub fn new(workers: usize, queue_length: usize) -> Self {
        let (tx, rx) = crossbeam_channel::unbounded();

        let j = {
            let tx = tx.clone();
            thread::spawn(move || {
                let im = InnerManager::new(tx.clone(), workers, queue_length);
                InnerManager::run(im, rx);
            })
        };

        Manager {
            dispatch_runner: Some(j),
            manager_tx: tx,
        }
    }

    pub async fn add(&self, ip: String, job: Box<dyn Runnable>) -> CaptchaResult<()> {
        let (job, rx) = ScheduleWork::new(job, ip);
        self.manager_tx
            .send(InnerManagerMessage::Schedule(job))
            .unwrap();
        rx.await?
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
                error!("[ERROR][{}] send failed: {e}", self.tag)
            }
        }
    }

    impl Manager {
        async fn add_works(&self) {
            const IP: &str = "foo bar";

            let (w, rx) = MockedRunnable::new("1".to_string());

            self.add(IP.into(), w).await.unwrap();

            let (w2, rx2) = MockedRunnable::new("2".into());
            self.add(IP.into(), w2).await.unwrap();

            thread::sleep(Duration::new(2, 0));
            assert!(rx.recv().unwrap());
            assert!(rx2.recv().unwrap());
        }
    }

    #[actix_rt::test]
    async fn manager_works() {
        let manager = Manager::new(3, 10);

        manager.add_works().await;
        drop(manager);
    }

    #[actix_rt::test]
    async fn abuse_manager() {
        let num_threads = 18;
        let num_jobs = 100_000;
        let manager = std::sync::Arc::new(Manager::new(num_threads, num_jobs * num_threads));

        let m = manager.clone();
        //////////////////let j = thread::spawn(move || async move {
        let mut jobs = Vec::with_capacity(num_jobs);
        for i in 0..num_jobs {
            let (w, rx) = MockedRunnable::new(format!("job {i}"));
            jobs.push(rx);
            m.add(i.to_string(), w).await.unwrap();
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
    }
}
