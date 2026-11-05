//! A single boot attestation, refreshed before its certificates expire.

use std::sync::{Arc, RwLock};
use std::time::Duration;

use qos_nsm::NsmProvider;
use tokio::{task::JoinHandle, time::Instant};

use crate::{
	AttestationInputs, Error, NsmProviderExt, VerifiedAttestationDocument,
};

const LEAD: Duration = Duration::from_mins(30);
const RETRY_RATIO: u32 = 4;
const RETRY_FLOOR: Duration = Duration::from_secs(5);

/// An initial verified document and the fixed boot inputs used to refresh it.
/// Create this value with [`attest`], then pass it to [`AttestationCache::new`].
pub struct Attestation {
	entry: Entry,
	inputs: Arc<AttestationInputs>,
}

/// The sole owner of a boot attestation's refresh task.
///
/// Construction performs no NSM requests and starts no task. Obtain a serving
/// handle with [`Self::reader`], then consume the owner with [`Self::start`].
/// Every document is verified against the provider root and expected boot
/// inputs, which remain fixed for all refreshes.
///
/// ```rust
/// use std::sync::Arc;
/// use qos_attestation::cache::{attest, AttestationCache};
/// use qos_nsm::NsmProvider;
/// use qos_attestation::AttestationInputs;
///
/// async fn run<P: NsmProvider + 'static>(
///     nsm: Arc<P>, inputs: AttestationInputs,
/// ) -> Result<(), qos_attestation::Error> {
///     let initial = attest(nsm.clone(), inputs).await?;
///     let cache = AttestationCache::new(nsm, initial);
///     let reader = cache.reader();
///     let refresh_task = cache.start();
///     let document = reader.latest();
///     refresh_task.abort();
///     Ok(())
/// }
/// ```
pub struct AttestationCache<P> {
	nsm: Arc<P>,
	entry: Arc<RwLock<Entry>>,
	inputs: Arc<AttestationInputs>,
}

/// A cloneable serving handle for one boot attestation.
///
/// Every document is verified against the fixed boot inputs and provider root.
/// Requests use [`Self::latest`], which never waits on an NSM call. Every clone
/// observes the same document and diagnostics.
///
/// Lock poisoning is fatal. Access panics and the refresh task fails on its
/// next lock access. Discard all readers and restart the application or create
/// a new cache rather than retrying access to this instance.
#[derive(Clone)]
pub struct AttestationCacheReader(Arc<RwLock<Entry>>);

struct Entry {
	document: Arc<VerifiedAttestationDocument>,
	expiry_unix: u64,
	valid_until: Instant,
	last_error: Option<Arc<Error>>,
	refreshes: u64,
}

fn time_remaining(valid_until: Instant) -> Duration {
	valid_until.saturating_duration_since(Instant::now())
}

fn refresh_retry_delay(valid_until: Instant) -> Duration {
	(time_remaining(valid_until) / RETRY_RATIO).max(RETRY_FLOOR)
}

/// Request the initial document for a cache without starting refresh.
///
/// The inputs supply the manifest hash, live public key, and expected PCRs.
/// Requests use no nonce. Every document is verified against these inputs and
/// the provider root.
///
/// # Errors
///
/// Returns an error if the NSM request or verification fails, or the document
/// expires before it can be served.
///
/// # Panics
///
/// Panics if polled outside a Tokio runtime.
pub async fn attest<P: NsmProvider + 'static>(
	nsm: Arc<P>,
	inputs: AttestationInputs,
) -> Result<Attestation, Error> {
	let inputs = Arc::new(inputs);
	let entry = request_entry(nsm, inputs.clone()).await?;
	Ok(Attestation { entry, inputs })
}

impl<P: NsmProvider + 'static> AttestationCache<P> {
	/// Construct a cache without I/O or a background task.
	/// The initial document keeps its original serving deadline, even if it
	/// expires before construction or refresh starts.
	#[must_use]
	pub fn new(nsm: Arc<P>, initial: Attestation) -> Self {
		Self {
			nsm,
			entry: Arc::new(RwLock::new(initial.entry)),
			inputs: initial.inputs,
		}
	}

	/// A serving handle that remains usable after [`Self::start`] consumes this
	/// owner.
	#[must_use]
	pub fn reader(&self) -> AttestationCacheReader {
		AttestationCacheReader(self.entry.clone())
	}

	/// Consume the owner and spawn its only refresh task.
	///
	/// Consumers should exit if the task resolves and use process supervision
	/// such as QOS's `RestartPolicy::Always`. Dropping the handle detaches the
	/// task. Abort it to stop future refreshes. An NSM request already in progress
	/// may still finish.
	///
	/// The owner cannot start a second task.
	///
	/// ```compile_fail,E0382
	/// use qos_attestation::cache::AttestationCache;
	/// use qos_nsm::NsmProvider;
	///
	/// fn start_twice<P: NsmProvider + 'static>(cache: AttestationCache<P>) {
	///     let first = cache.start();
	///     let second = cache.start();
	/// }
	/// ```
	///
	/// # Panics
	///
	/// Panics if called outside a Tokio runtime.
	#[must_use]
	pub fn start(self) -> JoinHandle<()> {
		let Self { nsm, entry, inputs } = self;
		tokio::spawn(async move {
			loop {
				let (expiry, valid_until) = {
					let current =
						entry.read().expect("attestation cache lock poisoned");
					(current.expiry_unix, current.valid_until)
				};
				let time_remaining = time_remaining(valid_until);
				if time_remaining > LEAD {
					tokio::time::sleep(time_remaining.saturating_sub(LEAD))
						.await;
					continue;
				}
				match request_entry(nsm.clone(), inputs.clone()).await {
					Ok(mut new) if new.expiry_unix > expiry => {
						let mut current = entry
							.write()
							.expect("attestation cache lock poisoned");
						new.refreshes = current.refreshes.saturating_add(1);
						*current = new;
						continue;
					}
					Err(error) => {
						let error = Arc::new(error);
						entry
							.write()
							.expect("attestation cache lock poisoned")
							.last_error = Some(error);
					}
					// New expiry less than or equal to cached expiry. Latter
					// happens when fresh attestations reuse unexpired certificates
					Ok(_) => {}
				}
				// Recalculate after the attempt: a slow NSM call consumes time too.
				tokio::time::sleep(refresh_retry_delay(valid_until)).await;
			}
		})
	}
}

impl AttestationCacheReader {
	/// The current verified document, or `None` at or after its monotonic deadline.
	/// Never loads files or waits on a refresh. Previously returned documents
	/// remain accessible after expiry.
	///
	/// # Panics
	///
	/// Panics if the cache lock is poisoned.
	#[must_use]
	pub fn latest(&self) -> Option<Arc<VerifiedAttestationDocument>> {
		self.with(|entry| {
			(Instant::now() < entry.valid_until).then(|| entry.document.clone())
		})
	}

	/// Whether an unexpired document is available.
	///
	/// # Panics
	///
	/// Panics if the cache lock is poisoned.
	#[must_use]
	pub fn has_unexpired_document(&self) -> bool {
		self.latest().is_some()
	}

	/// The stored document's earliest certificate expiry, in seconds since the
	/// Unix epoch. This remains available even after the document expires.
	///
	/// # Panics
	///
	/// Panics if the cache lock is poisoned.
	#[must_use]
	pub fn expiry(&self) -> u64 {
		self.with(|entry| entry.expiry_unix)
	}

	/// Remaining serving time, or zero once the stored document expires.
	///
	/// # Panics
	///
	/// Panics if the cache lock is poisoned.
	#[must_use]
	pub fn valid_for(&self) -> Duration {
		self.with(|entry| time_remaining(entry.valid_until))
	}

	/// The most recent refresh error, cleared when a later-expiring document is
	/// stored. A verified, unexpired document with unchanged or earlier expiry
	/// is ignored without clearing the error. The returned handle does not hold
	/// the cache lock.
	///
	/// # Panics
	///
	/// Panics if the cache lock is poisoned.
	#[must_use]
	pub fn last_error(&self) -> Option<Arc<Error>> {
		self.with(|entry| entry.last_error.clone())
	}

	/// Number of document replacements after the initial attestation.
	///
	/// # Panics
	///
	/// Panics if the cache lock is poisoned.
	#[must_use]
	pub fn refreshes(&self) -> u64 {
		self.with(|entry| entry.refreshes)
	}

	fn with<T>(&self, f: impl FnOnce(&Entry) -> T) -> T {
		let entry = self.0.read().expect("attestation cache lock poisoned");
		f(&entry)
	}
}

async fn request_entry<P: NsmProvider + 'static>(
	nsm: Arc<P>,
	inputs: Arc<AttestationInputs>,
) -> Result<Entry, Error> {
	let started = Instant::now();
	let document =
		tokio::task::spawn_blocking(move || nsm.attest_and_verify(&inputs))
			.await
			.map_err(|error| Error::Task(error.to_string()))??;
	let expiry_unix = document.not_after_unix();
	let valid_until = started + document.remaining_lifetime_at_verification();
	if Instant::now() >= valid_until {
		return Err(Error::Expired);
	}

	Ok(Entry {
		document: Arc::new(document),
		expiry_unix,
		valid_until,
		last_error: None,
		refreshes: 0,
	})
}

#[cfg(test)]
mod tests {
	use std::{sync::Arc, time::Duration};

	use qos_nsm::{mock::MOCK_NSM_ATTESTATION_DOCUMENT, types::NsmResponse};
	use tokio::time::{Instant, advance};

	use crate::cache::{attest, refresh_retry_delay};
	use crate::{
		Error,
		tests::{ReplyNsm, sample_inputs},
	};

	#[tokio::test(start_paused = true)]
	async fn refresh_retry_delay_shrinks_to_a_five_second_floor() {
		let now = Instant::now();
		for (left, delay) in [(1200, 300), (60, 15), (20, 5), (8, 5), (0, 5)] {
			assert_eq!(
				refresh_retry_delay(now + Duration::from_secs(left)),
				Duration::from_secs(delay),
				"{left} seconds remaining"
			);
		}
		advance(Duration::from_secs(1)).await;
		assert_eq!(refresh_retry_delay(now), Duration::from_secs(5));
	}

	#[tokio::test(start_paused = true)]
	async fn aws_fixture_is_rejected_for_incompatible_boot_inputs() {
		let nsm = Arc::new(ReplyNsm(NsmResponse::Attestation {
			document: MOCK_NSM_ATTESTATION_DOCUMENT.to_vec(),
		}));
		assert!(matches!(
			attest(nsm, sample_inputs(8)).await,
			Err(Error::Binding(_))
		));
	}
}
