//! A single boot attestation, refreshed before its certificates expire.

use std::sync::{Arc, RwLock};
use std::time::Duration;

use qos_nsm::{NsmProvider, nitro::unsafe_attestation_doc_from_der};
use qos_p256::P256Public;
use tokio::{task::JoinHandle, time::Instant};

use crate::{Error, NsmProviderExt, verify::earliest_expiry};

const LEAD: Duration = Duration::from_mins(30);
const RETRY_RATIO: u32 = 4;
const RETRY_FLOOR: Duration = Duration::from_secs(5);

/// Original signed COSE bytes returned by the NSM.
/// Has not undergone cryptographic verification.
/// Dereferences to a read-only byte slice without copying the bytes.
pub struct AttestationDocument(Vec<u8>);

impl std::ops::Deref for AttestationDocument {
	type Target = [u8];

	fn deref(&self) -> &[u8] {
		&self.0
	}
}

/// One set of boot inputs, with a document available until certificate expiry.
///
/// The cache does not verify signatures or bindings. Its inputs are fixed for
/// its lifetime; consumers load and retain their manifest and key once at boot.
/// Requests use [`Self::latest`], which never waits on an NSM call.
///
/// Lock poisoning is fatal: access panics and the refresh task fails on its
/// next lock access. Discard the cache; recover by restarting the application
/// or creating a new cache, not by retrying access to this instance.
pub struct AttestationCache {
	slot: Arc<RwLock<Entry>>,
}

struct Entry {
	document: Arc<AttestationDocument>,
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

impl AttestationCache {
	/// Attest once, then spawn the only task that refreshes the document.
	/// Requires a Tokio runtime with timers enabled.
	///
	/// The manifest hash is sent as `user_data`, with `public_key` and no nonce.
	/// Consumers should exit if startup fails or the returned task resolves,
	/// and use a supervisor (e.g. QOS's `RestartPolicy::Always`) to restart.
	/// Dropping the handle detaches the task; abort it to stop refreshing.
	///
	/// # Errors
	///
	/// Returns an error if the first NSM request or document parse fails, or
	/// the first document expires before it can be served.
	pub async fn start<P: NsmProvider + 'static>(
		nsm: Arc<P>,
		manifest_hash: [u8; 32],
		public_key: P256Public,
	) -> Result<(Self, JoinHandle<()>), Error> {
		let public_key = Arc::new(public_key);
		let first =
			attest(nsm.clone(), manifest_hash, public_key.clone()).await?;
		let cache = Self { slot: Arc::new(RwLock::new(first)) };
		let refresh_cache = Self { slot: cache.slot.clone() };

		let task = tokio::spawn(async move {
			loop {
				let (expiry, valid_until) = refresh_cache
					.with(|entry| (entry.expiry_unix, entry.valid_until));
				let time_remaining = time_remaining(valid_until);
				if time_remaining > LEAD {
					tokio::time::sleep(time_remaining.saturating_sub(LEAD))
						.await;
					continue;
				}
				match attest(nsm.clone(), manifest_hash, public_key.clone())
					.await
				{
					Ok(mut new) if new.expiry_unix > expiry => {
						refresh_cache.with_mut(|entry| {
							new.refreshes = entry.refreshes.saturating_add(1);
							*entry = new;
						});
						continue;
					}
					Err(error) => {
						let error = Arc::new(error);
						refresh_cache.with_mut(|entry| {
							entry.last_error = Some(error);
						});
					}
					Ok(_) => {}
				}
				// Recalculate after the attempt: a slow NSM call consumes time too.
				tokio::time::sleep(refresh_retry_delay(valid_until)).await;
			}
		});
		Ok((cache, task))
	}

	/// The current document, or `None` at or after its monotonic deadline.
	/// Never loads files or waits on a refresh.
	///
	/// # Panics
	///
	/// Panics if the cache lock is poisoned.
	#[must_use]
	pub fn latest(&self) -> Option<Arc<AttestationDocument>> {
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
	/// stored. A parseable, unexpired document with unchanged or earlier expiry
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

	// Synchronous callbacks keep lock guards inside these methods.
	fn with<T>(&self, f: impl FnOnce(&Entry) -> T) -> T {
		let entry = self.slot.read().expect("attestation cache lock poisoned");
		f(&entry)
	}

	fn with_mut<T>(&self, f: impl FnOnce(&mut Entry) -> T) -> T {
		let mut entry =
			self.slot.write().expect("attestation cache lock poisoned");
		f(&mut entry)
	}
}

async fn attest<P: NsmProvider + 'static>(
	nsm: Arc<P>,
	hash: [u8; 32],
	key: Arc<P256Public>,
) -> Result<Entry, Error> {
	// Anchor before the NSM call, and round its timestamp up, so time spent
	// attesting cannot extend serving beyond certificate expiry. No wall clock.
	let started = Instant::now();
	let (document, root) = tokio::task::spawn_blocking(move || {
		Ok::<_, Error>((
			nsm.request_attestation_doc(&hash, &key)?,
			nsm.attestation_root_ca_der(),
		))
	})
	.await
	.map_err(|error| Error::Task(error.to_string()))??;

	let (expiry_unix, valid_until) = parse_document(&document, &root, started)?;

	Ok(Entry {
		document: Arc::new(AttestationDocument(document)),
		expiry_unix,
		valid_until,
		last_error: None,
		refreshes: 0,
	})
}

/// Parses the document and returns its earliest certificate expiry (Unix
/// seconds) and monotonic serving deadline. `started` must precede the NSM call
/// so time spent attesting counts against the remaining lifetime.
/// Rejects elapsed deadlines; does not verify signatures or bindings.
fn parse_document(
	document: &[u8],
	root: &[u8],
	started: Instant,
) -> Result<(u64, Instant), Error> {
	let doc =
		unsafe_attestation_doc_from_der(document).map_err(Error::Document)?;
	let expiry_unix = earliest_expiry(&doc, root)?;
	let remaining = expiry_unix.saturating_sub(doc.timestamp.div_ceil(1000));
	let valid_until = started + Duration::from_secs(remaining);
	if Instant::now() >= valid_until {
		return Err(Error::Expired);
	}
	Ok((expiry_unix, valid_until))
}

#[cfg(test)]
mod tests {
	use std::{
		sync::{Arc, Mutex, mpsc},
		time::Duration,
	};

	use qos_nsm::{
		NsmProvider,
		mock::{
			MOCK_ATTESTATION_DOC_TIMESTAMP, MOCK_INTERMEDIATE_CERT_DER,
			MOCK_LEAF_CERT_DER, MOCK_NSM_ATTESTATION_DOCUMENT,
			MOCK_ROOT_CERT_DER,
		},
		nitro::{AttestError, unsafe_attestation_doc_from_der},
		types::{NsmErrorCode, NsmRequest, NsmResponse},
	};
	use serde_bytes::ByteBuf;
	use tokio::{
		sync::Notify,
		task::JoinHandle,
		time::{Instant, advance},
	};
	use x509_cert::{
		Certificate,
		der::{Decode, Encode},
	};

	use crate::cache::{
		AttestationCache, LEAD, RETRY_FLOOR, RETRY_RATIO, parse_document,
		refresh_retry_delay,
	};
	use crate::{
		Error, NsmProviderExt,
		tests::{
			ReplyNsm, bound_doc, enclave_mock_nsm, qemu_shaped_document,
			sample_inputs, signed_with_zeros,
		},
	};

	const T0: u64 = 1_800_000_000;
	const LIFETIME: Duration = Duration::from_secs(3 * 60 * 60);
	const UNTIL_REFRESH: Duration = LIFETIME.saturating_sub(LEAD);

	#[derive(Clone)]
	enum Reply {
		Doc { not_after: u64, id: u8 },
		RawDocument(Vec<u8>),
		Fail,
		Panic,
	}

	struct TestNsm {
		reply: Mutex<Reply>,
		requests: Mutex<Vec<NsmRequest>>,
		gate: Mutex<Option<(usize, mpsc::Receiver<()>)>>,
		requested: Notify,
		epoch: Instant,
		root: Vec<u8>,
	}

	impl TestNsm {
		fn new(reply: Reply) -> Arc<Self> {
			Arc::new(Self {
				reply: Mutex::new(reply),
				requests: Mutex::new(Vec::new()),
				gate: Mutex::new(None),
				requested: Notify::new(),
				epoch: Instant::now(),
				root: MOCK_ROOT_CERT_DER.to_vec(),
			})
		}

		fn set(&self, reply: Reply) {
			*self.reply.lock().unwrap() = reply;
		}

		fn calls(&self) -> usize {
			self.requests.lock().unwrap().len()
		}

		fn block_next(&self) -> mpsc::Sender<()> {
			self.block_call(self.calls() + 1)
		}

		fn block_call(&self, call: usize) -> mpsc::Sender<()> {
			let (send, receive) = mpsc::channel();
			*self.gate.lock().unwrap() = Some((call, receive));
			send
		}

		async fn wait_for_call(&self, call: usize) {
			while self.calls() < call {
				self.requested.notified().await;
			}
		}
	}

	impl NsmProvider for TestNsm {
		fn nsm_process_request(&self, request: NsmRequest) -> NsmResponse {
			let call = {
				let mut requests = self.requests.lock().unwrap();
				requests.push(request);
				requests.len()
			};
			let gate = self
				.gate
				.lock()
				.unwrap()
				.take_if(|(number, _)| *number == call);
			self.requested.notify_one();
			if let Some((_, gate)) = gate {
				gate.recv().unwrap();
			}
			let reply = self.reply.lock().unwrap().clone();
			match reply {
				Reply::Fail => NsmResponse::Error(NsmErrorCode::InternalError),
				Reply::Panic => panic!("simulate NSM provider panic"),
				Reply::RawDocument(document) => {
					NsmResponse::Attestation { document }
				}
				Reply::Doc { not_after, id } => {
					let timestamp_ms = T0 * 1000
						+ u64::try_from(self.epoch.elapsed().as_millis())
							.unwrap();
					NsmResponse::Attestation {
						document: document_with_expiry(
							not_after,
							timestamp_ms,
							id,
						),
					}
				}
			}
		}

		fn timestamp_ms(&self) -> Result<u64, AttestError> {
			panic!(
				"the cache must use the document's timestamp, not another NSM call"
			)
		}

		fn attestation_root_ca_der(&self) -> Vec<u8> {
			self.root.clone()
		}
	}

	// Aborting on drop keeps test tasks from surviving their assertions.
	struct Running {
		cache: AttestationCache,
		task: JoinHandle<()>,
	}

	impl Drop for Running {
		fn drop(&mut self) {
			self.task.abort();
		}
	}

	async fn start(nsm: &Arc<TestNsm>) -> Result<Running, Error> {
		let (cache, task) = AttestationCache::start(
			nsm.clone(),
			[7; 32],
			sample_inputs(8).ephemeral_public_key,
		)
		.await?;
		Ok(Running { cache, task })
	}

	async fn populated() -> (Arc<TestNsm>, Running) {
		let nsm = TestNsm::new(Reply::Doc {
			not_after: T0 + LIFETIME.as_secs(),
			id: 1,
		});
		let running = start(&nsm).await.unwrap();
		(nsm, running)
	}

	async fn wait_until(mut ready: impl FnMut() -> bool) {
		let deadline = std::time::Instant::now() + Duration::from_secs(5);
		while !ready() {
			assert!(
				std::time::Instant::now() < deadline,
				"task made no progress"
			);
			// Yield without sleeping: automatic time advancement would skip timers
			// while spawn_blocking is still completing.
			tokio::task::yield_now().await;
		}
	}

	async fn next_error(
		cache: &AttestationCache,
		previous: Option<&Arc<Error>>,
	) {
		wait_until(|| {
			cache.last_error().is_some_and(|error| {
				previous.is_none_or(|previous| !Arc::ptr_eq(previous, &error))
			})
		})
		.await;
	}

	// The cache only parses expiry, so these fixtures deliberately have invalid
	// signatures. Give the leaf the requested expiry without re-signing it.
	fn document_with_expiry(
		not_after: u64,
		timestamp_ms: u64,
		id: u8,
	) -> Vec<u8> {
		let mut cert = Certificate::from_der(MOCK_LEAF_CERT_DER).unwrap();
		cert.tbs_certificate.validity.not_after =
			x509_cert::der::asn1::GeneralizedTime::from_unix_duration(
				Duration::from_secs(not_after),
			)
			.unwrap()
			.into();
		let mut doc = bound_doc(&sample_inputs(8), true);
		doc.timestamp = timestamp_ms;
		doc.module_id = id.to_string();
		doc.certificate = ByteBuf::from(cert.to_der().unwrap());
		doc.cabundle = vec![
			ByteBuf::from(MOCK_ROOT_CERT_DER.to_vec()),
			ByteBuf::from(MOCK_INTERMEDIATE_CERT_DER.to_vec()),
		];
		signed_with_zeros(&doc)
	}

	#[tokio::test(start_paused = true)]
	async fn parse_document_rounds_timestamp_and_preserves_start() {
		let started = Instant::now();
		advance(Duration::from_secs(2)).await;
		for (millis, lifetime) in [(0, 10), (1, 9), (999, 9), (1000, 9)] {
			let document = document_with_expiry(T0 + 10, T0 * 1000 + millis, 1);
			let (expiry, deadline) =
				parse_document(&document, MOCK_ROOT_CERT_DER, started).unwrap();
			assert_eq!(expiry, T0 + 10);
			assert_eq!(deadline, started + Duration::from_secs(lifetime));
		}
	}

	#[tokio::test(start_paused = true)]
	async fn parse_document_rejects_expired_documents_and_elapsed_deadlines() {
		let started = Instant::now();
		for expiry in [T0 - 1, T0] {
			let document = document_with_expiry(expiry, T0 * 1000, 1);
			assert!(matches!(
				parse_document(&document, MOCK_ROOT_CERT_DER, started),
				Err(Error::Expired)
			));
		}
		let document = document_with_expiry(T0 + 10, T0 * 1000, 1);
		advance(Duration::from_secs(10)).await;
		assert!(matches!(
			parse_document(&document, MOCK_ROOT_CERT_DER, started),
			Err(Error::Expired)
		));
	}

	#[test]
	fn parse_document_rejects_malformed_document_or_certificates() {
		let started = Instant::now();
		assert!(matches!(
			parse_document(&[0], MOCK_ROOT_CERT_DER, started),
			Err(Error::Document(_))
		));
		let document = qemu_shaped_document(&sample_inputs(8), true);
		assert!(matches!(
			parse_document(&document, MOCK_ROOT_CERT_DER, started),
			Err(Error::Certificate(_))
		));
		let document = document_with_expiry(T0 + 10, T0 * 1000, 1);
		assert!(matches!(
			parse_document(&document, &[0], started),
			Err(Error::Certificate(_))
		));
	}

	#[tokio::test(start_paused = true)]
	async fn invalid_refresh_preserves_the_entry() {
		let original_expiry = T0 + LIFETIME.as_secs();
		let candidates = [
			("malformed document", vec![0]),
			(
				"malformed certificate",
				qemu_shaped_document(&sample_inputs(8), true),
			),
			("expired document", document_with_expiry(T0, T0 * 1000, 2)),
			(
				"earlier expiry",
				document_with_expiry(original_expiry - 60, T0 * 1000, 2),
			),
		];
		for (case, candidate) in candidates {
			let nsm =
				TestNsm::new(Reply::Doc { not_after: original_expiry, id: 1 });
			let running = start(&nsm).await.unwrap();
			let old = running.cache.latest().unwrap();
			let deadline = running.cache.with(|entry| entry.valid_until);
			nsm.set(Reply::RawDocument(candidate));
			let release = nsm.block_call(3);
			// Reaching the next retry proves the candidate was processed. Block
			// that request so it cannot change the state we are inspecting.
			nsm.wait_for_call(3).await;
			assert!(
				Arc::ptr_eq(&old, &running.cache.latest().unwrap()),
				"{case}"
			);
			assert_eq!(running.cache.expiry(), original_expiry, "{case}");
			assert_eq!(
				running.cache.with(|entry| entry.valid_until),
				deadline,
				"{case}"
			);
			assert_eq!(running.cache.refreshes(), 0, "{case}");
			match (case, running.cache.last_error().as_deref()) {
				("malformed document", Some(Error::Document(_)))
				| ("malformed certificate", Some(Error::Certificate(_)))
				| ("expired document", Some(Error::Expired))
				| ("earlier expiry", None) => {}
				(_, error) => panic!("{case}: unexpected error {error:?}"),
			}

			running.task.abort();
			release.send(()).unwrap();
		}
	}

	#[tokio::test(start_paused = true)]
	async fn startup_rejects_unusable_attestations() {
		let cases = [
			("NSM error", Reply::Fail),
			("already expired", Reply::Doc { not_after: T0 - 1, id: 1 }),
			("at expiry", Reply::Doc { not_after: T0, id: 1 }),
			("malformed document", Reply::RawDocument(vec![0])),
			(
				"malformed certificate",
				Reply::RawDocument(qemu_shaped_document(
					&sample_inputs(1),
					true,
				)),
			),
		];
		for (case, reply) in cases {
			let error = start(&TestNsm::new(reply)).await.err().expect(case);
			match (case, error) {
				("NSM error", Error::Nsm(_))
				| ("already expired" | "at expiry", Error::Expired)
				| ("malformed document", Error::Document(_))
				| ("malformed certificate", Error::Certificate(_)) => {}
				(_, error) => panic!("{case}: unexpected error {error:?}"),
			}
		}
	}

	#[tokio::test(start_paused = true)]
	async fn poisoned_cache_panics_on_read_and_stops_refresh() {
		let (nsm, mut running) = populated().await;
		let cache = AttestationCache { slot: running.cache.slot.clone() };
		let writer = tokio::task::spawn_blocking(move || {
			cache.with_mut(|_| panic!("simulate cache writer panic"));
		});
		assert!(writer.await.unwrap_err().is_panic());
		assert!(std::panic::catch_unwind(|| running.cache.latest()).is_err());

		advance(UNTIL_REFRESH).await;
		assert!((&mut running.task).await.unwrap_err().is_panic());
		assert_eq!(nsm.calls(), 1, "a poisoned cache must not refresh");
	}

	#[tokio::test(start_paused = true)]
	async fn latest_expires_at_the_exact_deadline() {
		let (_, running) = populated().await;
		running.task.abort();
		let cache = &running.cache;
		let document = cache.latest().unwrap();
		assert!(cache.has_unexpired_document());
		assert!(Arc::ptr_eq(&document, &cache.latest().unwrap()));
		assert_eq!(cache.expiry(), T0 + LIFETIME.as_secs());
		assert_eq!(cache.refreshes(), 0);
		assert!(cache.last_error().is_none());
		advance(cache.valid_for().saturating_sub(Duration::from_nanos(1)))
			.await;
		assert!(cache.latest().is_some());
		advance(Duration::from_nanos(1)).await;
		assert!(cache.latest().is_none());
		assert!(!cache.has_unexpired_document());
		assert_eq!(cache.valid_for(), Duration::ZERO);
	}

	#[tokio::test(start_paused = true)]
	async fn refresh_starts_at_lead_time_and_keeps_the_original_inputs() {
		let (nsm, running) = populated().await;
		nsm.set(Reply::Doc { not_after: T0 + 2 * LIFETIME.as_secs(), id: 2 });
		advance(UNTIL_REFRESH.saturating_sub(Duration::from_secs(1))).await;
		assert_eq!(nsm.calls(), 1);
		advance(Duration::from_secs(1)).await;
		wait_until(|| running.cache.refreshes() == 1).await;
		assert_eq!(
			unsafe_attestation_doc_from_der(&running.cache.latest().unwrap())
				.unwrap()
				.module_id,
			"2"
		);
		assert_eq!(running.cache.expiry(), T0 + 2 * LIFETIME.as_secs());
		assert_eq!(running.cache.valid_for(), LIFETIME + LEAD);
		let requests = nsm.requests.lock().unwrap();
		assert_eq!(requests.len(), 2);
		let expected_key = sample_inputs(8).ephemeral_public_key.to_bytes();
		for request in requests.iter() {
			assert!(matches!(request, NsmRequest::Attestation {
			user_data: Some(hash), public_key: Some(key), nonce: None,
		} if hash == &vec![7; 32] && key == &expected_key));
		}
	}

	#[tokio::test(start_paused = true)]
	async fn refresh_counter_saturates_without_preventing_replacement() {
		let (nsm, running) = populated().await;
		let old = running.cache.latest().unwrap();
		running.cache.with_mut(|entry| entry.refreshes = u64::MAX);
		let expiry = T0 + 2 * LIFETIME.as_secs();
		nsm.set(Reply::Doc { not_after: expiry, id: 2 });
		advance(UNTIL_REFRESH).await;
		wait_until(|| running.cache.expiry() == expiry).await;
		assert_eq!(running.cache.refreshes(), u64::MAX);
		assert!(!Arc::ptr_eq(&old, &running.cache.latest().unwrap()));
		assert!(!running.cache.slot.is_poisoned());
		assert!(!running.task.is_finished());
	}

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
	async fn certificate_reuse_keeps_the_bytes_and_retries() {
		let (nsm, running) = populated().await;
		let old = running.cache.latest().unwrap();
		nsm.set(Reply::Doc { not_after: running.cache.expiry(), id: 2 });
		let release = nsm.block_call(3);
		nsm.wait_for_call(3).await;
		assert_eq!(
			nsm.epoch.elapsed(),
			UNTIL_REFRESH + Duration::from_secs(450)
		);
		assert_eq!(nsm.calls(), 3);
		assert!(Arc::ptr_eq(&old, &running.cache.latest().unwrap()));
		assert_eq!(running.cache.refreshes(), 0);
		assert!(running.cache.last_error().is_none());
		running.task.abort();
		release.send(()).unwrap();
	}

	#[tokio::test(start_paused = true)]
	async fn ignored_documents_preserve_the_previous_refresh_error() {
		for earlier_by in [0, 60] {
			let (nsm, running) = populated().await;
			let old = running.cache.latest().unwrap();
			nsm.set(Reply::Fail);
			advance(UNTIL_REFRESH).await;
			wait_until(|| running.cache.last_error().is_some()).await;
			let error = running.cache.last_error().unwrap();
			nsm.set(Reply::Doc {
				not_after: running.cache.expiry() - earlier_by,
				id: 2,
			});
			let release = nsm.block_call(4);
			nsm.wait_for_call(4).await;
			assert!(Arc::ptr_eq(&error, &running.cache.last_error().unwrap()));
			assert!(Arc::ptr_eq(&old, &running.cache.latest().unwrap()));
			assert_eq!(running.cache.refreshes(), 0);
			running.task.abort();
			release.send(()).unwrap();
		}
	}

	#[tokio::test(start_paused = true)]
	async fn failed_refresh_serves_until_expiry_then_recovers() {
		let (nsm, running) = populated().await;
		let old = running.cache.latest().unwrap();
		nsm.set(Reply::Fail);
		advance(UNTIL_REFRESH).await;
		wait_until(|| running.cache.last_error().is_some()).await;
		assert!(Arc::ptr_eq(&old, &running.cache.latest().unwrap()));
		assert!(matches!(
			running.cache.last_error().as_deref(),
			Some(Error::Nsm(code)) if code == "InternalError"
		));
		let previous_error = running.cache.last_error().unwrap();
		advance(running.cache.valid_for()).await;
		assert!(!running.cache.has_unexpired_document());
		assert!(running.cache.latest().is_none());
		next_error(&running.cache, Some(&previous_error)).await;
		let failed = nsm.calls();
		nsm.set(Reply::Doc { not_after: T0 + 2 * LIFETIME.as_secs(), id: 3 });
		advance(RETRY_FLOOR).await;
		wait_until(|| running.cache.refreshes() == 1).await;
		assert!(nsm.calls() > failed);
		assert_eq!(
			unsafe_attestation_doc_from_der(&running.cache.latest().unwrap())
				.unwrap()
				.module_id,
			"3"
		);
		assert!(running.cache.last_error().is_none());
		assert!(running.cache.has_unexpired_document());
	}

	#[tokio::test(start_paused = true)]
	async fn provider_panic_preserves_the_cache_and_allows_retry() {
		let (nsm, running) = populated().await;
		let old = running.cache.latest().unwrap();
		nsm.set(Reply::Panic);
		advance(UNTIL_REFRESH).await;
		wait_until(|| running.cache.last_error().is_some()).await;
		assert!(matches!(
			running.cache.last_error().as_deref(),
			Some(Error::Task(_))
		));
		assert!(Arc::ptr_eq(&old, &running.cache.latest().unwrap()));
		assert_eq!(running.cache.refreshes(), 0);
		assert!(!running.cache.slot.is_poisoned());
		assert!(!running.task.is_finished());
		nsm.set(Reply::Doc { not_after: T0 + 2 * LIFETIME.as_secs(), id: 2 });
		advance(LEAD / RETRY_RATIO).await;
		wait_until(|| running.cache.refreshes() == 1).await;
		assert!(!Arc::ptr_eq(&old, &running.cache.latest().unwrap()));
		assert!(running.cache.last_error().is_none());
		assert_eq!(nsm.calls(), 3);
	}

	#[tokio::test(start_paused = true)]
	async fn slow_refresh_does_not_block_readers_or_extend_the_deadline() {
		let (nsm, running) = populated().await;
		let old = running.cache.latest().unwrap();
		let release = nsm.block_next();
		advance(UNTIL_REFRESH).await;
		wait_until(|| nsm.calls() == 2).await;
		assert!(running.cache.slot.try_read().is_ok());
		assert!(running.cache.slot.try_write().is_ok());
		assert!(Arc::ptr_eq(&old, &running.cache.latest().unwrap()));
		assert!(running.cache.has_unexpired_document());
		advance(LEAD).await;
		assert!(running.cache.latest().is_none());
		assert_eq!(running.cache.valid_for(), Duration::ZERO);
		assert_eq!(nsm.calls(), 2, "one writer cannot pile up NSM calls");
		nsm.set(Reply::Doc { not_after: T0 + 2 * LIFETIME.as_secs(), id: 2 });
		release.send(()).unwrap();
		wait_until(|| running.cache.refreshes() == 1).await;
		// Its timestamp is now 3h, but the deadline is anchored 30m earlier.
		assert_eq!(running.cache.valid_for(), LIFETIME.saturating_sub(LEAD));
	}

	#[tokio::test(start_paused = true)]
	async fn slow_start_rejects_a_document_whose_deadline_elapsed() {
		let nsm = TestNsm::new(Reply::Doc { not_after: T0 + 10, id: 1 });
		let release = nsm.block_next();
		let starting = tokio::spawn({
			let nsm = nsm.clone();
			async move { start(&nsm).await }
		});
		wait_until(|| nsm.calls() == 1).await;
		advance(Duration::from_secs(6)).await;
		release.send(()).unwrap();
		// Four seconds remain at issuance, but six passed since the call started.
		assert!(matches!(starting.await.unwrap(), Err(Error::Expired)));
	}

	#[tokio::test(start_paused = true)]
	async fn provider_root_limits_cache_lifetime_without_binding_checks() {
		let key = sample_inputs(8).ephemeral_public_key;
		// The signed document deliberately has commitments for different inputs.
		let nsm = enclave_mock_nsm(&sample_inputs(1), false);
		let document = nsm.request_attestation_doc(&[7; 32], &key).unwrap();
		let doc = unsafe_attestation_doc_from_der(&document).unwrap();
		let expiry = doc.timestamp.div_ceil(1000) + 60;
		let leaf = Certificate::from_der(&doc.certificate).unwrap();
		assert!(
			leaf.tbs_certificate
				.validity
				.not_after
				.to_unix_duration()
				.as_secs() > expiry
		);
		let mut root = Certificate::from_der(MOCK_ROOT_CERT_DER).unwrap();
		root.tbs_certificate.validity.not_after =
			x509_cert::der::asn1::GeneralizedTime::from_unix_duration(
				Duration::from_secs(expiry),
			)
			.unwrap()
			.into();
		let mut nsm = TestNsm::new(Reply::RawDocument(document.clone()));
		Arc::get_mut(&mut nsm).unwrap().root = root.to_der().unwrap();
		let (cache, task) =
			AttestationCache::start(nsm, [7; 32], key).await.unwrap();
		let running = Running { cache, task };
		assert_eq!(&running.cache.latest().unwrap()[..], document);
		assert_eq!(running.cache.expiry(), expiry);
		assert_eq!(running.cache.valid_for(), Duration::from_secs(60));
	}

	#[tokio::test(start_paused = true)]
	async fn aws_fixture_reads_real_expiry_and_rounds_its_timestamp() {
		let nsm = Arc::new(ReplyNsm(NsmResponse::Attestation {
			document: MOCK_NSM_ATTESTATION_DOCUMENT.to_vec(),
		}));
		let (cache, task) = AttestationCache::start(
			nsm,
			[7; 32],
			sample_inputs(8).ephemeral_public_key,
		)
		.await
		.unwrap();
		let running = Running { cache, task };
		let document = running.cache.latest().unwrap();
		assert_eq!(&document[..], MOCK_NSM_ATTESTATION_DOCUMENT);
		let doc =
			unsafe_attestation_doc_from_der(MOCK_NSM_ATTESTATION_DOCUMENT)
				.unwrap();
		let leaf = Certificate::from_der(&doc.certificate).unwrap();
		let expected = leaf
			.tbs_certificate
			.validity
			.not_after
			.to_unix_duration()
			.as_secs();
		assert_eq!(running.cache.expiry(), expected);
		assert_eq!(
			running.cache.valid_for(),
			Duration::from_secs(
				expected - MOCK_ATTESTATION_DOC_TIMESTAMP.div_ceil(1000)
			)
		);
	}
}
