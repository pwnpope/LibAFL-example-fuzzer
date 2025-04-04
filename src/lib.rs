use core::time::Duration;
use std::num::NonZero; 

use libafl::{
    Error, Fuzzer,
    generators::RandBytesGenerator, 
    inputs::{BytesInput, HasMutatorBytes},
    corpus::{InMemoryCorpus, OnDiskCorpus}, 
    events::{EventConfig, llmp::restarting::setup_restarting_mgr_std}, 
    executors::{ExitKind, InProcessExecutor}, feedback_or, feedback_or_fast, 
    feedbacks::{CrashFeedback, MaxMapFeedback, TimeFeedback, TimeoutFeedback}, 
    fuzzer::StdFuzzer, 
    monitors::SimpleMonitor, 
    mutators::{havoc_mutations, StdScheduledMutator}, 
    observers::{CanTrack, HitcountsMapObserver, StdMapObserver, TimeObserver}, 
    schedulers::RandScheduler, stages::mutational::StdMutationalStage, 
    state::StdState,
};

use libafl_targets::{ MAX_EDGES_FOUND, EDGES_MAP};
use libafl_bolts::rands::StdRand;
use libafl_bolts::SimpleStdoutLogger;
use libafl_bolts::tuples::tuple_list;

extern "C" {
    fn vuln_func(magic: *const u8, payload: *const u8, payload_len: u32) -> bool;
}

fn fuzz() {
    let mut harness = |input: &BytesInput| {
        let total_len = input.bytes().len();
        if total_len <= 4 {
            return ExitKind::Ok;
        }

        let magic = &input.bytes()[..3];
        let payload = &input.bytes()[3..];
        
        unsafe {
            vuln_func(magic.as_ptr(), payload.as_ptr(), payload.len() as u32);
                ExitKind::Ok
        }
    };

    let monitor = SimpleMonitor::new(|s| println!("{s}"));
    let (_, mut restarting_mgr) = 
        match setup_restarting_mgr_std(monitor, 0x539, EventConfig::AlwaysUnique) {
            Ok(res) => res,
            Err(err) => match err {
                Error::ShuttingDown => {
                    return
                }
                _ => {
                    panic!("[-] Failed to setup the restarter: {err}")
                }
            },
        };

    let edges_observer = unsafe {
        HitcountsMapObserver::new(
            StdMapObserver::from_mut_ptr(
                "edges",
                EDGES_MAP.as_mut_ptr(),
                MAX_EDGES_FOUND)).track_indices()
    };

    let time_observer = TimeObserver::new("Time");
    let map_feedback = MaxMapFeedback::new(&edges_observer);
    let time_feedback = TimeFeedback::new(&time_observer);

    let mut feedback = feedback_or!(
        map_feedback,
        time_feedback
    );

    let mut objective = feedback_or_fast!(CrashFeedback::new(), TimeoutFeedback::new());
    let mut state = state.unwrap_or_else(|| {
        StdState::new(
            StdRand::new(),
            InMemoryCorpus::new(),
            OnDiskCorpus::new("./crashes").unwrap(),
            &mut feedback,
            &mut objective,
        )
        .unwrap()
    });

    let mutator = StdScheduledMutator::new(havoc_mutations());

    let scheduler = RandScheduler::new();

    let mut fuzzer = StdFuzzer::new(scheduler, feedback, objective);

    let mut executor = InProcessExecutor::with_timeout(
        &mut harness, 
        tuple_list!(edges_observer, time_observer), 
        &mut fuzzer, 
        &mut state, 
        &mut restarting_mgr, 
        Duration::new(10, 0),
    ).unwrap();

    let mut generator = RandBytesGenerator::new(NonZero::new(1024).unwrap());
    if state.must_load_initial_inputs() {
        state.generate_initial_inputs_forced(&mut fuzzer, &mut executor, &mut generator, &mut restarting_mgr, 8).unwrap();
    }

    let stages = StdMutationalStage::new(mutator);

    let iters = 1_000_000;
    fuzzer.fuzz_loop_for(
        &mut tuple_list!(stages),
        &mut executor,
        &mut state,
        &mut restarting_mgr,
        iters,
    ).unwrap();
}

#[no_mangle]
pub extern "C" fn fuzzer_main() {
    SimpleStdoutLogger::set_logger().unwrap();
    log::set_max_level(log::LevelFilter::Trace);
    fuzz();
}
