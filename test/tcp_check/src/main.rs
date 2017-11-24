#![feature(box_syntax)]
extern crate e2d2;
extern crate fnv;
extern crate time;
extern crate getopts;
extern crate rand;
extern crate futures;
extern crate tokio_core;
use self::nf::*;
use e2d2::config::{basic_opts, read_matches};
use e2d2::interface::*;
use e2d2::operators::*;
use e2d2::scheduler::*;
use std::env;
use std::fmt::Display;
use std::process;
use std::sync::Arc;
use futures::Stream;
mod nf;

fn test<T, S>(ports: Vec<T>, sched: &mut S, send: &futures::sync::mpsc::Sender<Vec<u8>>)
where
    T: PacketRx + PacketTx + Display + Clone + 'static,
    S: Scheduler + Sized,
{
    println!("Receiving started");

    let pipelines: Vec<_> = ports
        .iter()
        .map({
            |port| {
                tcp_nf(ReceiveBatch::new(port.clone()), sched, send.clone()).send(port.clone())
            }
        })
        .collect();
    println!("Running {} pipelines", pipelines.len());
    for pipeline in pipelines {
        sched.add_task(pipeline).unwrap();
    }
}

fn main() {
    let opts = basic_opts();
    let args: Vec<String> = env::args().collect();
    let matches = match opts.parse(&args[1..]) {
        Ok(m) => m,
        Err(f) => panic!(f.to_string()),
    };

    let mut configuration = read_matches(&matches, &opts);
    configuration.pool_size = 512; // Travis allocates at most 512 hugepages.

    match initialize_system(&configuration) {
        Ok(mut context) => {
            let (send, recv) = futures::sync::mpsc::channel(5);
            context.start_schedulers();
            context.add_pipeline_to_run(Arc::new(move |p, s: &mut StandaloneScheduler| test(p, s, &send)));
            context.execute();

            let mut core = tokio_core::reactor::Core::new().unwrap();

            core.run(recv.map(|buf| println!("Got UDP packet (len: {})", buf.len())).collect()).unwrap();

            println!("Closing down");
        }
        Err(ref e) => {
            println!("Error: {}", e);
            if let Some(backtrace) = e.backtrace() {
                println!("Backtrace: {:?}", backtrace);
            }
            process::exit(1);
        }
    }
}
