//! A single-flight attestation cache with background refresh.
//!
//! Serve requests from [`AttestationCache::latest`], which never blocks, and
//! let [`AttestationCache::spawn_watcher`] (plus one [`AttestationCache::get`]
//! at startup) do the loading, attesting and verifying.

use std::{
	path::PathBuf,
	sync::{
		Arc, Mutex, MutexGuard, PoisonError,
		atomic::{AtomicBool, Ordering},
	},
	time::Duration,
};

use qos_nsm::NsmProvider;
use tokio::{
	sync::{Mutex as AsyncMutex, watch},
	task::JoinHandle,
	time::{Instant, MissedTickBehavior},
};

#[cfg(feature = "unsafe-verifier")]
use crate::verify::unsafe_verify_self_attestation_skip_chain;
use crate::{
	AttestationInputs, Error, VerifiedAttestation, VerifyPolicy, verify,
};

/// The longest a single document is ever served for, whatever its chain says.
const MAX_SERVE_TIME: Duration = Duration::from_secs(10 * 365 * 24 * 60 * 60);

/// When the cache attests again.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RefreshPolicy {
	/// Attest once and serve that document for the cache's lifetime,
	/// ignoring certificate expiry. Fits verifiers that check a document at
	/// its own timestamp. Changed inputs still trigger a new attestation.
	AttestOnce,
	/// Attest again within `margin` of the chain's earliest `notAfter`, and
	/// never serve a document past it.
	BeforeExpiry {
		/// How long before expiry to start refreshing.
		margin: Duration,
		/// How long to wait after a near-expiry refresh that failed or didn't
		/// extend `notAfter`, e.g. because the NSM reused its leaf.
		same_leaf_backoff: Duration,
	},
}

/// Cache configuration.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CacheConfig {
	/// When to attest again.
	pub refresh: RefreshPolicy,
	/// The longest one load-and-attest call may take.
	pub call_timeout: Duration,
}

impl Default for CacheConfig {
	fn default() -> Self {
		Self {
			refresh: RefreshPolicy::BeforeExpiry {
				margin: Duration::from_secs(30 * 60),
				same_leaf_backoff: Duration::from_secs(60),
			},
			call_timeout: Duration::from_secs(5),
		}
	}
}

/// Loads the inputs a document must bind to. Called on every
/// [`AttestationCache::get`], on a blocking thread.
///
/// Return [`Error::InputsChanged`] when the inputs no longer match what the
/// process can serve; the cache then stops serving permanently. Any other
/// error is treated as transient.
pub trait InputLoader: Send + Sync + 'static {
	/// Load the current inputs.
	///
	/// # Errors
	///
	/// Returns an error if the inputs can't be loaded or have changed.
	fn load(&self) -> Result<AttestationInputs, Error>;
}

impl<F> InputLoader for F
where
	F: Fn() -> Result<AttestationInputs, Error> + Send + Sync + 'static,
{
	fn load(&self) -> Result<AttestationInputs, Error> {
		self()
	}
}

/// Inputs pinned at startup.
///
/// A pivot signs with the key it loaded at startup and serves the manifest
/// it read then, so a document for any other inputs is useless to it. If
/// the files later differ, [`InputLoader::load`] returns
/// [`Error::InputsChanged`]; the pivot should then exit so it restarts on
/// the new inputs. This never happens in normal operation: QOS rotates to
/// the live key before the pivot starts.
#[derive(Debug, Clone)]
pub struct PinnedInputs {
	pinned: AttestationInputs,
	ephemeral_key_path: PathBuf,
	manifest_path: PathBuf,
}

impl PinnedInputs {
	/// Pin `pinned`, re-reading the given files on each load.
	pub fn new(
		pinned: AttestationInputs,
		ephemeral_key_path: impl Into<PathBuf>,
		manifest_path: impl Into<PathBuf>,
	) -> Self {
		Self {
			pinned,
			ephemeral_key_path: ephemeral_key_path.into(),
			manifest_path: manifest_path.into(),
		}
	}

	/// Pin `pinned`, re-reading the paths QOS writes inside the enclave.
	#[must_use]
	pub fn at_default_paths(pinned: AttestationInputs) -> Self {
		Self::new(pinned, qos_core::EPHEMERAL_KEY_FILE, qos_core::MANIFEST_FILE)
	}

	/// The pinned inputs.
	#[must_use]
	pub fn pinned(&self) -> &AttestationInputs {
		&self.pinned
	}
}

impl InputLoader for PinnedInputs {
	fn load(&self) -> Result<AttestationInputs, Error> {
		let (current, _) = AttestationInputs::load(
			&self.ephemeral_key_path,
			&self.manifest_path,
		)?;
		if current == self.pinned {
			Ok(current)
		} else {
			Err(Error::InputsChanged)
		}
	}
}

/// Counters and the active configuration.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct CacheStats {
	/// The PCR18 policy in force.
	pub policy: VerifyPolicy,
	/// The refresh policy in force.
	pub refresh: RefreshPolicy,
	/// NSM attestation attempts.
	pub attestations: u64,
	/// `get` calls answered from the cached document.
	pub hits: u64,
	/// Attestations made with no valid document cached.
	pub initial: u64,
	/// Attestations made because the inputs changed.
	pub inputs_changed_refreshes: u64,
	/// Attestations made because the document neared expiry.
	pub near_expiry_refreshes: u64,
	/// Near-expiry refreshes that didn't extend `notAfter`.
	pub not_extended: u64,
	/// Of those, refreshes that returned the same leaf certificate.
	pub same_leaf: u64,
	/// Failures while a valid document was kept and still served.
	pub refresh_failures: u64,
	/// Failures that left no document to serve.
	pub failures: u64,
	/// Calls that timed out.
	pub timeouts: u64,
	/// Calls refused because an earlier timed-out call is still running.
	pub in_flight_rejections: u64,
	/// Whether the inputs changed; once set, the cache never serves again.
	pub inputs_changed: bool,
	/// The most recent error.
	pub last_error: Option<String>,
}

impl CacheStats {
	fn new(policy: VerifyPolicy, refresh: RefreshPolicy) -> Self {
		Self {
			policy,
			refresh,
			attestations: 0,
			hits: 0,
			initial: 0,
			inputs_changed_refreshes: 0,
			near_expiry_refreshes: 0,
			not_extended: 0,
			same_leaf: 0,
			refresh_failures: 0,
			failures: 0,
			timeouts: 0,
			in_flight_rejections: 0,
			inputs_changed: false,
			last_error: None,
		}
	}
}

/// A single-flight cache of a verified self-attestation.
///
/// Only verified documents are ever cached, and only for the inputs they
/// were requested with. Consumers should treat a watcher exit or
/// [`Self::wait_inputs_changed`] resolving as fatal, and gate readiness on
/// [`Self::healthy`].
pub struct AttestationCache<P> {
	nsm: Arc<P>,
	loader: Arc<dyn InputLoader>,
	policy: VerifyPolicy,
	config: CacheConfig,
	root_der: Arc<Vec<u8>>,
	verifier: Verifier,
	/// Set while a load-and-attest job runs, including after its caller
	/// timed out, since a blocked NSM call can't be cancelled.
	in_flight: Arc<AtomicBool>,
	/// Held across the whole refresh so concurrent callers share one.
	state: AsyncMutex<State>,
	/// What [`Self::latest`] serves, readable without `state`.
	snapshot: Arc<Mutex<Option<Entry>>>,
	inputs_changed: watch::Sender<bool>,
	stats: Mutex<CacheStats>,
}

#[derive(Clone)]
enum Verifier {
	Full,
	#[cfg(feature = "unsafe-verifier")]
	SkipChain,
	#[cfg(test)]
	Fake(Arc<FakeVerify>),
}

#[cfg(test)]
type FakeResult = Result<VerifiedAttestation, Error>;
#[cfg(test)]
type FakeVerify = dyn Fn(&[u8], &AttestationInputs) -> FakeResult + Send + Sync;

#[derive(Clone)]
struct Entry {
	attestation: Arc<VerifiedAttestation>,
	/// `None` means no deadline ([`RefreshPolicy::AttestOnce`]).
	valid_until: Option<Instant>,
}

impl Entry {
	fn valid_at(&self, now: Instant) -> bool {
		self.valid_until.is_none_or(|until| now < until)
	}
}

#[derive(Default)]
struct State {
	entry: Option<Entry>,
	/// No near-expiry attempt before this instant.
	retry_after: Option<Instant>,
}

#[derive(Clone, Copy)]
enum Reason {
	Initial,
	InputsChanged,
	NearExpiry,
}

enum Outcome {
	Unchanged,
	Attested { reason: Reason, result: Result<VerifiedAttestation, Error> },
	LoadFailed(Error),
}

impl<P: NsmProvider + 'static> AttestationCache<P> {
	/// A cache that verifies every document's chain against
	/// [`NsmProvider::attestation_root_ca_der`], its signature, and its
	/// binding to the loaded inputs under `policy`.
	pub fn new(
		nsm: Arc<P>,
		loader: impl InputLoader,
		policy: VerifyPolicy,
		config: CacheConfig,
	) -> Self {
		Self::build(nsm, Arc::new(loader), policy, config, Verifier::Full)
	}

	/// A cache that skips the certificate chain, the signature and expiry,
	/// keeping every binding and policy check. Always uses
	/// [`RefreshPolicy::AttestOnce`].
	///
	/// Only for emulated NSMs such as QEMU's, which don't sign documents.
	#[cfg(feature = "unsafe-verifier")]
	pub fn unsafe_new_skip_chain_verification(
		nsm: Arc<P>,
		loader: impl InputLoader,
		policy: VerifyPolicy,
		call_timeout: Duration,
	) -> Self {
		let config =
			CacheConfig { refresh: RefreshPolicy::AttestOnce, call_timeout };
		Self::build(nsm, Arc::new(loader), policy, config, Verifier::SkipChain)
	}

	fn build(
		nsm: Arc<P>,
		loader: Arc<dyn InputLoader>,
		policy: VerifyPolicy,
		config: CacheConfig,
		verifier: Verifier,
	) -> Self {
		Self {
			root_der: Arc::new(nsm.attestation_root_ca_der()),
			nsm,
			loader,
			policy,
			config,
			verifier,
			in_flight: Arc::new(AtomicBool::new(false)),
			state: AsyncMutex::new(State::default()),
			snapshot: Arc::new(Mutex::new(None)),
			inputs_changed: watch::channel(false).0,
			stats: Mutex::new(CacheStats::new(policy, config.refresh)),
		}
	}

	/// The current document, loading the inputs and attesting again first if
	/// they changed, nothing valid is cached, or a refresh is due.
	///
	/// If a refresh fails while a valid document is cached, that document is
	/// returned and the failure is counted in [`Self::stats`].
	///
	/// # Errors
	///
	/// Returns an error if no valid document can be served.
	pub async fn get(&self) -> Result<Arc<VerifiedAttestation>, Error> {
		if self.inputs_changed() {
			return Err(Error::InputsChanged);
		}
		let mut state = self.state.lock().await;
		// Anchor expiry before the NSM call so a document is never served
		// past its chain's `notAfter`.
		let started = Instant::now();
		let current = state.entry.clone().filter(|e| e.valid_at(started));
		let due = current.as_ref().is_some_and(|e| {
			self.near_expiry_due(e, state.retry_after, started)
		});

		let Some(guard) = InFlight::claim(&self.in_flight) else {
			let mut counters = self.lock_stats();
			counters.in_flight_rejections += 1;
			return Self::keep_or_fail(
				&mut state,
				current,
				Error::InFlight,
				&mut counters,
			);
		};
		let job = Job {
			nsm: Arc::clone(&self.nsm),
			loader: Arc::clone(&self.loader),
			policy: self.policy,
			root_der: Arc::clone(&self.root_der),
			verifier: self.verifier.clone(),
			cached_inputs: current
				.as_ref()
				.map(|e| e.attestation.inputs.clone()),
			due,
			snapshot: Arc::clone(&self.snapshot),
			saw_change: Arc::new(AtomicBool::new(false)),
		};
		let saw_change = Arc::clone(&job.saw_change);
		let handle = tokio::task::spawn_blocking(move || {
			let _guard = guard;
			job.run()
		});
		let outcome = match tokio::time::timeout(
			self.config.call_timeout,
			handle,
		)
		.await
		{
			Ok(Ok(outcome)) => Ok(outcome),
			Ok(Err(join)) => Err(Error::Task(join.to_string())),
			Err(_) => Err(Error::Timeout),
		};
		// A job that saw new inputs already withdrew the old document.
		let current = current.filter(|_| !saw_change.load(Ordering::Acquire));
		self.apply(&mut state, current, started, outcome)
	}

	/// The cached document if it is still valid, without loading inputs,
	/// calling the NSM, or waiting behind a refresh in progress.
	#[must_use]
	pub fn latest(&self) -> Option<Arc<VerifiedAttestation>> {
		if self.inputs_changed() {
			return None;
		}
		let now = Instant::now();
		lock(&self.snapshot)
			.as_ref()
			.filter(|e| e.valid_at(now))
			.map(|e| Arc::clone(&e.attestation))
	}

	/// Whether a verified, unexpired document can be served. Never blocks.
	#[must_use]
	pub fn healthy(&self) -> bool {
		self.latest().is_some()
	}

	/// Whether the loader reported [`Error::InputsChanged`]. Permanent.
	#[must_use]
	pub fn inputs_changed(&self) -> bool {
		*self.inputs_changed.borrow()
	}

	/// Resolves once [`Self::inputs_changed`] is set, including if it was
	/// set before this call.
	pub async fn wait_inputs_changed(&self) {
		let mut changed = self.inputs_changed.subscribe();
		// The sender lives as long as `self`, so this can't fail.
		let _ = changed.wait_for(|changed| *changed).await;
	}

	/// Counters and the active configuration.
	#[must_use]
	pub fn stats(&self) -> CacheStats {
		self.lock_stats().clone()
	}

	/// Call [`Self::get`] every `every`, so the document stays fresh with no
	/// requests. Errors are recorded in [`Self::stats`].
	///
	/// The task only ends if it is aborted or panics. Treat the handle
	/// resolving as fatal.
	pub fn spawn_watcher(self: &Arc<Self>, every: Duration) -> JoinHandle<()> {
		let cache = Arc::clone(self);
		tokio::spawn(async move {
			let mut ticks = tokio::time::interval(every);
			ticks.set_missed_tick_behavior(MissedTickBehavior::Delay);
			loop {
				ticks.tick().await;
				let _ = cache.get().await;
			}
		})
	}

	fn near_expiry_due(
		&self,
		entry: &Entry,
		retry_after: Option<Instant>,
		now: Instant,
	) -> bool {
		match self.config.refresh {
			RefreshPolicy::AttestOnce => false,
			RefreshPolicy::BeforeExpiry { margin, .. } => {
				entry.valid_until.is_some_and(|until| {
					until.saturating_duration_since(now) <= margin
				}) && retry_after.is_none_or(|after| now >= after)
			}
		}
	}

	fn apply(
		&self,
		state: &mut State,
		current: Option<Entry>,
		started: Instant,
		outcome: Result<Outcome, Error>,
	) -> Result<Arc<VerifiedAttestation>, Error> {
		let mut counters = self.lock_stats();
		let (reason, result) = match outcome {
			Ok(Outcome::Unchanged) => {
				return match current {
					Some(entry) => {
						counters.hits += 1;
						Ok(entry.attestation)
					}
					None => Err(Error::Task("no cached document".to_string())),
				};
			}
			Ok(Outcome::LoadFailed(Error::InputsChanged)) => {
				self.withdraw(state);
				let _ = self.inputs_changed.send_replace(true);
				counters.inputs_changed = true;
				counters.failures += 1;
				counters.last_error = Some(Error::InputsChanged.to_string());
				return Err(Error::InputsChanged);
			}
			Ok(Outcome::LoadFailed(e)) => {
				return Self::keep_or_fail(state, current, e, &mut counters);
			}
			Err(e) => {
				if matches!(e, Error::Timeout) {
					counters.timeouts += 1;
				}
				return Self::keep_or_fail(state, current, e, &mut counters);
			}
			Ok(Outcome::Attested { reason, result }) => (reason, result),
		};

		counters.attestations += 1;
		match reason {
			Reason::Initial => counters.initial += 1,
			Reason::InputsChanged => counters.inputs_changed_refreshes += 1,
			Reason::NearExpiry => counters.near_expiry_refreshes += 1,
		}

		if let (Reason::NearExpiry, Some(entry)) = (reason, &current) {
			let extends = match &result {
				Ok(fresh) => {
					fresh.not_after_unix > entry.attestation.not_after_unix
				}
				Err(_) => false,
			};
			if !extends {
				state.retry_after = Some(started + self.backoff());
				match result {
					Ok(fresh) => {
						counters.not_extended += 1;
						if fresh.leaf_fingerprint
							== entry.attestation.leaf_fingerprint
						{
							counters.same_leaf += 1;
						}
					}
					Err(e) => {
						counters.refresh_failures += 1;
						counters.last_error = Some(e.to_string());
					}
				}
				return Ok(Arc::clone(&entry.attestation));
			}
		}

		match result {
			Ok(fresh) => {
				let entry = Entry {
					valid_until: self.deadline(&fresh, started),
					attestation: Arc::new(fresh),
				};
				*lock(&self.snapshot) = Some(entry.clone());
				state.entry = Some(entry.clone());
				state.retry_after = None;
				Ok(entry.attestation)
			}
			Err(e) => {
				self.withdraw(state);
				counters.failures += 1;
				counters.last_error = Some(e.to_string());
				Err(e)
			}
		}
	}

	/// Keep serving a still-valid document after a transient failure, or
	/// fail if there is none.
	fn keep_or_fail(
		state: &mut State,
		current: Option<Entry>,
		error: Error,
		counters: &mut CacheStats,
	) -> Result<Arc<VerifiedAttestation>, Error> {
		counters.last_error = Some(error.to_string());
		if let Some(entry) = current {
			counters.refresh_failures += 1;
			Ok(entry.attestation)
		} else {
			state.entry = None;
			counters.failures += 1;
			Err(error)
		}
	}

	fn withdraw(&self, state: &mut State) {
		*lock(&self.snapshot) = None;
		state.entry = None;
		state.retry_after = None;
	}

	fn deadline(
		&self,
		fresh: &VerifiedAttestation,
		started: Instant,
	) -> Option<Instant> {
		match self.config.refresh {
			RefreshPolicy::AttestOnce => None,
			RefreshPolicy::BeforeExpiry { .. } => {
				// Round the timestamp up so the deadline never passes notAfter.
				let remaining = fresh
					.not_after_unix
					.saturating_sub(fresh.timestamp_ms.div_ceil(1000));
				Some(
					started
						+ Duration::from_secs(remaining).min(MAX_SERVE_TIME),
				)
			}
		}
	}

	fn backoff(&self) -> Duration {
		match self.config.refresh {
			RefreshPolicy::AttestOnce => Duration::ZERO,
			RefreshPolicy::BeforeExpiry { same_leaf_backoff, .. } => {
				same_leaf_backoff
			}
		}
	}

	fn lock_stats(&self) -> MutexGuard<'_, CacheStats> {
		lock(&self.stats)
	}
}

#[cfg(test)]
impl<P: NsmProvider + 'static> AttestationCache<P> {
	fn with_fake_verifier(
		nsm: Arc<P>,
		loader: impl InputLoader,
		policy: VerifyPolicy,
		config: CacheConfig,
		verify: Arc<FakeVerify>,
	) -> Self {
		Self::build(
			nsm,
			Arc::new(loader),
			policy,
			config,
			Verifier::Fake(verify),
		)
	}
}

/// One load-and-attest call, run on a blocking thread.
struct Job<P> {
	nsm: Arc<P>,
	loader: Arc<dyn InputLoader>,
	policy: VerifyPolicy,
	root_der: Arc<Vec<u8>>,
	verifier: Verifier,
	cached_inputs: Option<AttestationInputs>,
	due: bool,
	snapshot: Arc<Mutex<Option<Entry>>>,
	saw_change: Arc<AtomicBool>,
}

impl<P: NsmProvider> Job<P> {
	fn run(self) -> Outcome {
		let inputs = match self.loader.load() {
			Ok(inputs) => inputs,
			Err(e) => return Outcome::LoadFailed(e),
		};
		let reason = match &self.cached_inputs {
			None => Reason::Initial,
			Some(cached) if *cached != inputs => {
				// Stop serving the old document before attesting the new
				// inputs, however long that takes.
				self.saw_change.store(true, Ordering::Release);
				*lock(&self.snapshot) = None;
				Reason::InputsChanged
			}
			Some(_) if self.due => Reason::NearExpiry,
			Some(_) => return Outcome::Unchanged,
		};
		Outcome::Attested { reason, result: self.attest(&inputs) }
	}

	fn attest(
		&self,
		inputs: &AttestationInputs,
	) -> Result<VerifiedAttestation, Error> {
		let document = verify::request_document(&*self.nsm, inputs)?;
		match &self.verifier {
			Verifier::Full => verify::verify_self_attestation(
				&document,
				&self.root_der,
				inputs,
				&self.policy,
			),
			#[cfg(feature = "unsafe-verifier")]
			Verifier::SkipChain => unsafe_verify_self_attestation_skip_chain(
				&document,
				inputs,
				&self.policy,
			),
			#[cfg(test)]
			Verifier::Fake(verify) => verify(&document, inputs),
		}
	}
}

/// Marks a job in flight until dropped, which happens when the blocking
/// call actually returns.
struct InFlight(Arc<AtomicBool>);

impl InFlight {
	fn claim(flag: &Arc<AtomicBool>) -> Option<Self> {
		(!flag.swap(true, Ordering::AcqRel)).then(|| Self(Arc::clone(flag)))
	}
}

impl Drop for InFlight {
	fn drop(&mut self) {
		self.0.store(false, Ordering::Release);
	}
}

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
	mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

#[cfg(test)]
mod tests;
