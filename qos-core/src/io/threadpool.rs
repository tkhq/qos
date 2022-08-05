use std::{
	sync::{mpsc, Arc, Mutex},
	thread,
};

type Job = Box<dyn FnOnce() + Send + 'static>;

/// Errors for a [`ThreadPool`]
pub enum ThreadPoolError {
	MpscSendError(std::sync::mpsc::SendError<Message>),
}

/// An abstraction for executing jobs concurrently across a fixed number of
/// threads.
pub struct ThreadPool {
	workers: Vec<Worker>,
	sender: mpsc::Sender<Message>,
}

/// Message sent to a worker thread in the thread pool.
pub enum Message {
	NewJob(Job),
	Terminate,
}

impl ThreadPool {
	/// Create a new instance of [`Self`].
	///
	/// # Arguments
	///
	/// * `size` - Number of threads in pool.
	///
	/// # Panics
	///
	/// Panics if the `size` is zero.
	pub fn new(size: usize) -> ThreadPool {
		assert!(size > 0);

		let (sender, receiver) = mpsc::channel();

		let receiver = Arc::new(Mutex::new(receiver));

		let mut workers = Vec::with_capacity(size);

		for id in 0..size {
			workers.push(Worker::new(id, Arc::clone(&receiver)));
		}

		ThreadPool { workers, sender }
	}

	/// Execute `f` in the next free thread. This is non blocking.
	///
	/// # Errors
	///
	/// Returns an error if the `f` could not be sent to a worker thread.
	pub fn execute<F>(&self, f: F) -> Result<(), ThreadPoolError>
	where
		F: FnOnce() + Send + 'static,
	{
		let job = Box::new(f);

		self.sender
			.send(Message::NewJob(job))
			.map_err(|e| ThreadPoolError::MpscSendError(e));
		Ok(())
	}
}

impl Drop for ThreadPool {
	fn drop(&mut self) {
		// Send 1 termination signal per worker thread. We don't know exactly
		// which worker will recieve each message, but since we know that a
		// worker will stop receiving after getting the terminate message, we
		// can be confident that non-terminated threads will recieve the
		// terminate message exactly once and terminated threads will never
		// receive the message. Thus, if we have N workers and send N terminate
		// messages we will terminate all worker threads.
		for _ in &self.workers {
			drop(
				self.sender
					.send(Message::Terminate)
					.map_err(|e| eprintln!("`ThreadPool::drop`: {:?}", e)),
			);
		}

		for worker in &mut self.workers {
			if let Some(thread) = worker.thread.take() {
				drop(thread.join().map_err(|e| {
					eprintln!("`ThreadPool::drop: failed to join: {:?}`", e)
				}))
			}
		}
	}
}

struct Worker {
	id: usize,
	thread: Option<thread::JoinHandle<()>>,
}

impl Worker {
	fn new(id: usize, receiver: Arc<Mutex<mpsc::Receiver<Message>>>) -> Worker {
		let thread = thread::spawn(move || loop {
			let message = receiver
				.lock()
				.expect("channel receiver mutex poisoned")
				.recv()
				.expect("tried to receive on a closed chanel");

			match message {
				Message::NewJob(job) => {
					println!("Worker {} got a job; executing.", id);

					job();
				}
				Message::Terminate => {
					println!("Worker {} was told to terminate.", id);

					break;
				}
			}
		});

		Worker { id, thread: Some(thread) }
	}
}
