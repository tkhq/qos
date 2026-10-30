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

/// One set of boot inputs, with a document available until certificate expiry.
///
/// Every document is verified against the provider root and expected boot
/// inputs, which are fixed for the cache lifetime.
/// Requests use [`Self::latest`], which never waits on an NSM call.
///
/// Lock poisoning is fatal: access panics and the refresh task fails on its
/// next lock access. Discard the cache; recover by restarting the application
/// or creating a new cache, not by retrying access to this instance.
pub struct AttestationCache {
	slot: Arc<RwLock<Entry>>,
}

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

impl AttestationCache {
	/// Attest once, then spawn the only task that refreshes the document.
	/// Requires a Tokio runtime with timers enabled.
	///
	/// The inputs supply the manifest hash, live public key and expected PCRs.
	/// Requests use no nonce.
	/// Consumers should exit if startup fails or the returned task resolves,
	/// and use a supervisor (e.g. QOS's `RestartPolicy::Always`) to restart.
	/// Dropping the handle detaches the task; abort it to stop refreshing.
	///
	/// # Errors
	///
	/// Returns an error if the first NSM request or verification fails, or
	/// the first document expires before it can be served.
	pub async fn start<P: NsmProvider + 'static>(
		nsm: Arc<P>,
		inputs: AttestationInputs,
	) -> Result<(Self, JoinHandle<()>), Error> {
		let inputs = Arc::new(inputs);
		let first = attest(nsm.clone(), inputs.clone()).await?;
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
				match attest(nsm.clone(), inputs.clone()).await {
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
					// New expiry less than or equal to cached expiry. Latter
					// happens when fresh attestations reuse unexpired certificates
					Ok(_) => {}
				}
				// Recalculate after the attempt: a slow NSM call consumes time too.
				tokio::time::sleep(refresh_retry_delay(valid_until)).await;
			}
		});
		Ok((cache, task))
	}

	/// The current verified document, or `None` at or after its monotonic deadline.
	/// Never loads files or waits on a refresh.
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
	use std::{
		sync::{
			Arc, Mutex, OnceLock,
			atomic::{AtomicUsize, Ordering},
			mpsc,
		},
		time::Duration,
	};

	use p384::ecdsa::{Signature, SigningKey, signature::Signer};
	use qos_nsm::{
		NsmProvider,
		mock::{
			MOCK_INTERMEDIATE_CERT_DER, MOCK_LEAF_CERT_DER,
			MOCK_NSM_ATTESTATION_DOCUMENT, MOCK_ROOT_CERT_DER,
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
		AttestationCache, LEAD, RETRY_FLOOR, RETRY_RATIO, attest,
		refresh_retry_delay,
	};
	use crate::{
		Error, NsmProviderExt, VerifiedAttestationDocument,
		tests::{
			ReplyNsm, bound_doc, enclave_mock_nsm, mock_signing_key,
			qemu_shaped_document, sample_inputs, signed_with_mock_key,
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

	#[derive(Clone, Copy)]
	enum ClockReply {
		Now,
		Fixed(u64),
		Fail,
	}

	struct TestNsm {
		reply: Mutex<Reply>,
		requests: Mutex<Vec<NsmRequest>>,
		gate: Mutex<Option<(usize, mpsc::Receiver<()>)>>,
		requested: Notify,
		epoch: Instant,
		root: Vec<u8>,
		clock: Mutex<ClockReply>,
		clock_calls: AtomicUsize,
		clock_gate: Mutex<Option<mpsc::Receiver<()>>>,
	}

	impl TestNsm {
		fn new(reply: Reply) -> Arc<Self> {
			Arc::new(Self {
				reply: Mutex::new(reply),
				requests: Mutex::new(Vec::new()),
				gate: Mutex::new(None),
				requested: Notify::new(),
				epoch: Instant::now(),
				root: test_ca_bundle().0.clone(),
				clock: Mutex::new(ClockReply::Now),
				clock_calls: AtomicUsize::new(0),
				clock_gate: Mutex::new(None),
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
			self.clock_calls.fetch_add(1, Ordering::SeqCst);
			if let Some(gate) = self.clock_gate.lock().unwrap().take() {
				gate.recv().unwrap();
			}
			match *self.clock.lock().unwrap() {
				ClockReply::Now => Ok(T0 * 1000
					+ u64::try_from(self.epoch.elapsed().as_millis()).unwrap()),
				ClockReply::Fixed(millis) => Ok(millis),
				ClockReply::Fail => Err(AttestError::InvalidTimeStamp),
			}
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
		let (cache, task) =
			AttestationCache::start(nsm.clone(), sample_inputs(8)).await?;
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

	fn signed_certificate(
		template: &[u8],
		subject: &SigningKey,
		issuer: &SigningKey,
		not_after: Option<u64>,
	) -> Vec<u8> {
		let mut cert = Certificate::from_der(template).unwrap();
		cert.tbs_certificate.subject_public_key_info.subject_public_key =
			x509_cert::der::asn1::BitString::from_bytes(
				subject.verifying_key().to_encoded_point(false).as_bytes(),
			)
			.unwrap();
		if let Some(extensions) = &mut cert.tbs_certificate.extensions {
			extensions.retain(|extension| {
				!matches!(
					extension.extn_id.to_string().as_str(),
					"2.5.29.14" | "2.5.29.35"
				)
			});
		}
		if let Some(expiry) = not_after {
			cert.tbs_certificate.validity.not_after =
				x509_cert::der::asn1::GeneralizedTime::from_unix_duration(
					Duration::from_secs(expiry),
				)
				.unwrap()
				.into();
		}
		let signature: Signature =
			issuer.sign(&cert.tbs_certificate.to_der().unwrap());
		cert.signature = x509_cert::der::asn1::BitString::from_bytes(
			signature.to_der().as_bytes(),
		)
		.unwrap();
		cert.to_der().unwrap()
	}

	fn test_ca_bundle() -> &'static (Vec<u8>, Vec<u8>) {
		static CA: OnceLock<(Vec<u8>, Vec<u8>)> = OnceLock::new();
		CA.get_or_init(|| {
			let root = SigningKey::from_slice(&[1; 48]).unwrap();
			let intermediate = SigningKey::from_slice(&[2; 48]).unwrap();
			(
				signed_certificate(MOCK_ROOT_CERT_DER, &root, &root, None),
				signed_certificate(
					MOCK_INTERMEDIATE_CERT_DER,
					&intermediate,
					&root,
					None,
				),
			)
		})
	}

	fn sign_document(
		mut doc: aws_nitro_enclaves_nsm_api::api::AttestationDoc,
		not_after: u64,
	) -> Vec<u8> {
		doc.certificate = ByteBuf::from(signed_certificate(
			MOCK_LEAF_CERT_DER,
			&mock_signing_key(),
			&SigningKey::from_slice(&[2; 48]).unwrap(),
			Some(not_after),
		));
		let (root, intermediate) = test_ca_bundle();
		doc.cabundle = vec![
			ByteBuf::from(root.clone()),
			ByteBuf::from(intermediate.clone()),
		];
		signed_with_mock_key(&doc)
	}

	fn document_with_expiry(
		not_after: u64,
		timestamp_ms: u64,
		id: u8,
	) -> Vec<u8> {
		let mut doc = bound_doc(&sample_inputs(8), true);
		doc.timestamp = timestamp_ms;
		doc.module_id = id.to_string();
		sign_document(doc, not_after)
	}

	#[tokio::test(start_paused = true)]
	async fn verified_deadline_rounds_trusted_clock_and_preserves_start() {
		for (millis, lifetime) in [(0, 10), (1, 9), (999, 9), (1000, 9)] {
			let document = document_with_expiry(T0 + 10, T0 * 1000, 1);
			let nsm = TestNsm::new(Reply::RawDocument(document));
			*nsm.clock.lock().unwrap() = ClockReply::Fixed(T0 * 1000 + millis);
			let started = Instant::now();
			let release = nsm.block_next();
			let pending =
				tokio::spawn(attest(nsm.clone(), Arc::new(sample_inputs(8))));
			wait_until(|| nsm.calls() == 1).await;
			advance(Duration::from_secs(2)).await;
			release.send(()).unwrap();
			let entry = pending.await.unwrap().unwrap();
			assert_eq!(entry.expiry_unix, T0 + 10);
			assert_eq!(
				entry.valid_until,
				started + Duration::from_secs(lifetime)
			);
		}
	}

	#[tokio::test(start_paused = true)]
	async fn old_document_deadline_uses_current_clock_without_reader_io() {
		let expiry = T0 + 100;
		let nsm = TestNsm::new(Reply::RawDocument(document_with_expiry(
			expiry,
			T0 * 1000,
			1,
		)));
		*nsm.clock.lock().unwrap() = ClockReply::Fixed((T0 + 90) * 1000 + 1);
		let running = start(&nsm).await.unwrap();
		running.task.abort();
		assert_eq!(running.cache.valid_for(), Duration::from_secs(9));
		for _ in 0..20 {
			assert!(running.cache.latest().is_some());
			assert!(running.cache.has_unexpired_document());
			assert_eq!(running.cache.expiry(), expiry);
		}
		assert_eq!(nsm.calls(), 1);
		assert_eq!(nsm.clock_calls.load(Ordering::SeqCst), 1);
		advance(Duration::from_secs(9)).await;
		assert!(running.cache.latest().is_none());
	}

	#[tokio::test(start_paused = true)]
	async fn slow_clock_read_consumes_serving_lifetime() {
		let nsm = TestNsm::new(Reply::RawDocument(document_with_expiry(
			T0 + 10,
			T0 * 1000,
			1,
		)));
		let (send, recv) = mpsc::channel();
		*nsm.clock_gate.lock().unwrap() = Some(recv);
		let pending =
			tokio::spawn(attest(nsm.clone(), Arc::new(sample_inputs(8))));
		wait_until(|| nsm.clock_calls.load(Ordering::SeqCst) == 1).await;
		advance(Duration::from_secs(4)).await;
		send.send(()).unwrap();
		let entry = pending.await.unwrap().unwrap();
		assert_eq!(entry.valid_until, nsm.epoch + Duration::from_secs(6));
		assert_eq!(
			entry.valid_until.duration_since(Instant::now()),
			Duration::from_secs(2)
		);
	}

	#[tokio::test(start_paused = true)]
	async fn clock_failure_preserves_cached_entry_and_deadline() {
		let (nsm, running) = populated().await;
		let old = running.cache.latest().unwrap();
		let deadline = running.cache.with(|entry| entry.valid_until);
		*nsm.clock.lock().unwrap() = ClockReply::Fail;
		advance(UNTIL_REFRESH).await;
		next_error(&running.cache, None).await;
		assert!(matches!(
			running.cache.last_error().as_deref(),
			Some(Error::Clock(_))
		));
		assert!(Arc::ptr_eq(&old, &running.cache.latest().unwrap()));
		assert_eq!(running.cache.with(|entry| entry.valid_until), deadline);
		advance(running.cache.valid_for()).await;
		assert!(running.cache.latest().is_none());
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
				"future timestamp",
				document_with_expiry(
					original_expiry + 60,
					(T0 + LIFETIME.as_secs()) * 1000,
					2,
				),
			),
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
				(
					"malformed document" | "malformed certificate",
					Some(Error::Document(_)),
				)
				| (
					"expired document",
					Some(
						Error::Expired
						| Error::Document(AttestError::InvalidCertChain(_)),
					),
				)
				| ("future timestamp", Some(Error::FutureTimestamp))
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
				| (
					"already expired" | "at expiry",
					Error::Expired
					| Error::Document(AttestError::InvalidCertChain(_)),
				)
				| (
					"malformed document" | "malformed certificate",
					Error::Document(_),
				) => {}
				(_, error) => panic!("{case}: unexpected error {error:?}"),
			}
		}
	}

	fn rejected_documents() -> Vec<(&'static str, Vec<u8>)> {
		let inputs = sample_inputs(8);
		let expiry = T0 + 2 * LIFETIME.as_secs();
		let signed =
			|mut doc: aws_nitro_enclaves_nsm_api::api::AttestationDoc| {
				doc.timestamp = T0 * 1000;
				sign_document(doc, expiry)
			};
		let mut cases = Vec::new();
		let valid = signed(bound_doc(&inputs, true));
		let mut tampered = valid.clone();
		*tampered.last_mut().unwrap() ^= 1;
		cases.push(("COSE signature", tampered));
		let other_root = enclave_mock_nsm(&inputs, true);
		cases.push((
			"wrong root",
			other_root
				.request_attestation_doc(
					&inputs.manifest_hash,
					&inputs.ephemeral_public_key,
				)
				.unwrap(),
		));
		let mut certificate = unsafe_attestation_doc_from_der(&valid).unwrap();
		let last = certificate.certificate.len() - 1;
		certificate.certificate[last] ^= 1;
		cases.push((
			"certificate signature",
			signed_with_mock_key(&certificate),
		));
		let mut other = inputs.clone();
		other.manifest_hash = [9; 32];
		cases.push(("manifest", signed(bound_doc(&other, true))));
		other = inputs.clone();
		other.ephemeral_public_key = sample_inputs(9).ephemeral_public_key;
		cases.push(("key", signed(bound_doc(&other, true))));
		for (label, index) in [
			("PCR0", 0),
			("PCR1", 1),
			("PCR2", 2),
			("PCR3", 3),
			("PCR17", 17),
			("PCR18", 18),
		] {
			let mut doc = bound_doc(&inputs, true);
			doc.pcrs.insert(index, ByteBuf::from(vec![0xab; 48]));
			cases.push((label, signed(doc)));
		}
		let mut doc = bound_doc(&inputs, true);
		doc.pcrs.remove(&18);
		cases.push(("missing PCR18", signed(doc)));
		cases.push(("unprovisioned PCR18", signed(bound_doc(&inputs, false))));
		let mut doc = bound_doc(&inputs, true);
		doc.nonce = Some(ByteBuf::from(vec![1]));
		cases.push(("nonce", signed(doc)));
		cases
	}

	fn assert_rejection(case: &str, error: &Error) {
		assert!(
			match case {
				"COSE signature" | "wrong root" | "certificate signature" =>
					matches!(error, Error::Document(_)),
				"key" => matches!(error, Error::PublicKeyMismatch),
				"PCR18" | "unprovisioned PCR18" =>
					matches!(error, Error::ManifestOnlyCommitment(_)),
				_ => matches!(error, Error::Binding(_)),
			},
			"{case}: unexpected error {error:?}"
		);
	}

	#[tokio::test(start_paused = true)]
	async fn startup_and_refresh_require_authentic_bound_documents() {
		for (case, candidate) in rejected_documents() {
			let error =
				start(&TestNsm::new(Reply::RawDocument(candidate.clone())))
					.await
					.err()
					.expect(case);
			assert_rejection(case, &error);
			let (nsm, running) = populated().await;
			let old = running.cache.latest().unwrap();
			let deadline = running.cache.with(|entry| entry.valid_until);
			nsm.set(Reply::RawDocument(candidate));
			advance(UNTIL_REFRESH).await;
			next_error(&running.cache, None).await;
			assert_rejection(case, &running.cache.last_error().unwrap());
			assert!(
				Arc::ptr_eq(&old, &running.cache.latest().unwrap()),
				"{case}"
			);
			assert_eq!(
				running.cache.with(|entry| entry.valid_until),
				deadline,
				"{case}"
			);
			assert_eq!(
				running.cache.expiry(),
				T0 + LIFETIME.as_secs(),
				"{case}"
			);
			assert_eq!(running.cache.refreshes(), 0, "{case}");
			advance(running.cache.valid_for()).await;
			assert!(running.cache.latest().is_none(), "{case}");
			nsm.set(Reply::Doc {
				not_after: T0 + 2 * LIFETIME.as_secs(),
				id: 2,
			});
			advance(RETRY_FLOOR).await;
			wait_until(|| running.cache.refreshes() == 1).await;
			assert!(running.cache.last_error().is_none(), "{case}");
			assert!(
				!Arc::ptr_eq(&old, &running.cache.latest().unwrap()),
				"{case}"
			);
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
			unsafe_attestation_doc_from_der(
				running.cache.latest().unwrap().document()
			)
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
		} if hash == &vec![8; 32] && key == &expected_key));
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
			unsafe_attestation_doc_from_der(
				running.cache.latest().unwrap().document()
			)
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

	#[test]
	fn supplied_root_and_intermediate_validity_hold_at_both_times() {
		let inputs = sample_inputs(8);
		let original = document_with_expiry(T0 + 120, T0 * 1000, 1);
		let (root, _) = test_ca_bundle();
		let root_key = SigningKey::from_slice(&[1; 48]).unwrap();
		let intermediate_key = SigningKey::from_slice(&[2; 48]).unwrap();
		let short_root = signed_certificate(
			MOCK_ROOT_CERT_DER,
			&root_key,
			&root_key,
			Some(T0 + 60),
		);
		VerifiedAttestationDocument::verify_at(
			original.clone(),
			&short_root,
			&inputs,
			(T0 + 59) * 1000,
		)
		.unwrap();
		assert!(matches!(
			VerifiedAttestationDocument::verify_at(
				original.clone(),
				&short_root,
				&inputs,
				(T0 + 60) * 1000
			),
			Err(Error::Expired)
		));

		let mut later_root = Certificate::from_der(root).unwrap();
		later_root.tbs_certificate.validity.not_before =
			x509_cert::der::asn1::GeneralizedTime::from_unix_duration(
				Duration::from_secs(T0 + 1),
			)
			.unwrap()
			.into();
		let signature: Signature =
			root_key.sign(&later_root.tbs_certificate.to_der().unwrap());
		later_root.signature = x509_cert::der::asn1::BitString::from_bytes(
			signature.to_der().as_bytes(),
		)
		.unwrap();
		let later_root = later_root.to_der().unwrap();
		for verification_time in [T0, T0 + 2] {
			assert!(matches!(
				VerifiedAttestationDocument::verify_at(
					original.clone(),
					&later_root,
					&inputs,
					verification_time * 1000
				),
				Err(Error::NotYetValid)
			));
		}
		let mut doc = unsafe_attestation_doc_from_der(&original).unwrap();
		doc.timestamp = (T0 + 1) * 1000;
		VerifiedAttestationDocument::verify_at(
			signed_with_mock_key(&doc),
			&later_root,
			&inputs,
			(T0 + 1) * 1000,
		)
		.unwrap();

		doc.timestamp = T0 * 1000;
		doc.cabundle[1] = ByteBuf::from(signed_certificate(
			MOCK_INTERMEDIATE_CERT_DER,
			&intermediate_key,
			&root_key,
			Some(T0 + 60),
		));
		let document = signed_with_mock_key(&doc);
		VerifiedAttestationDocument::verify_at(
			document.clone(),
			root,
			&inputs,
			(T0 + 59) * 1000,
		)
		.unwrap();
		assert!(
			VerifiedAttestationDocument::verify_at(
				document,
				root,
				&inputs,
				(T0 + 60) * 1000
			)
			.is_err()
		);
	}

	#[tokio::test(start_paused = true)]
	async fn verified_provider_root_limits_cache_lifetime() {
		let mut nsm = TestNsm::new(Reply::Doc {
			not_after: T0 + LIFETIME.as_secs(),
			id: 1,
		});
		let root = SigningKey::from_slice(&[1; 48]).unwrap();
		Arc::get_mut(&mut nsm).unwrap().root =
			signed_certificate(MOCK_ROOT_CERT_DER, &root, &root, Some(T0 + 60));
		let running = start(&nsm).await.unwrap();
		assert_eq!(running.cache.expiry(), T0 + 60);
		assert_eq!(running.cache.valid_for(), Duration::from_secs(60));
		assert_eq!(running.cache.latest().unwrap().not_after_unix(), T0 + 60);
	}

	#[tokio::test(start_paused = true)]
	async fn aws_fixture_is_rejected_for_incompatible_boot_inputs() {
		let nsm = Arc::new(ReplyNsm(NsmResponse::Attestation {
			document: MOCK_NSM_ATTESTATION_DOCUMENT.to_vec(),
		}));
		assert!(matches!(
			AttestationCache::start(nsm, sample_inputs(8)).await,
			Err(Error::Binding(_))
		));
	}
}
