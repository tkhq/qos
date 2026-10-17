use std::sync::{
	Barrier,
	atomic::{AtomicU64, AtomicUsize},
};

use qos_nsm::{
	mock::MockNsm,
	nitro::AttestError,
	types::{NsmErrorCode, NsmRequest, NsmResponse},
};
use qos_p256::P256Pair;

use super::*;
use crate::{
	ManifestOnlyCommitment,
	test_support::{
		FixedDocNsm, RecordingNsm, TempDir, enclave_mock_nsm,
		qemu_shaped_document, sample_inputs, v2_envelope_with_nonce, write_key,
		write_manifest,
	},
};

const NOT_CHECKED: VerifyPolicy =
	VerifyPolicy { manifest_only: ManifestOnlyCommitment::NotChecked };
const REQUIRED: VerifyPolicy =
	VerifyPolicy { manifest_only: ManifestOnlyCommitment::Required };

/// Unix seconds at which every fake test starts.
const T0: u64 = 1_800_000_000;
const HOUR: Duration = Duration::from_secs(60 * 60);
const BACKOFF: Duration = Duration::from_secs(60);
/// From attesting a 3 hour doc to the start of its refresh margin.
const UNTIL_MARGIN: Duration = Duration::from_secs(3 * 3600 - 30 * 60);

fn before_expiry() -> CacheConfig {
	CacheConfig::default()
}

fn attest_once() -> CacheConfig {
	CacheConfig { refresh: RefreshPolicy::AttestOnce, ..CacheConfig::default() }
}

/// How the fake NSM answers the next attestation request.
#[derive(Clone)]
enum Reply {
	/// A document whose chain expires at `not_after`, with a leaf id.
	Doc { not_after: u64, leaf: Leaf },
	/// An NSM error.
	Fail,
	/// Block until the barrier is released, then answer with the reply set
	/// at that point.
	Hang(Arc<Barrier>),
}

#[derive(Clone, Copy)]
enum Leaf {
	Fixed(u8),
	/// A new leaf on every call.
	PerCall,
}

/// An NSM whose documents only the fake verifier understands. Lets tests
/// pick expiry and leaf reuse, and move the NSM clock with tokio's.
struct FakeNsm {
	reply: Mutex<Reply>,
	calls: AtomicUsize,
	now_ms: AtomicU64,
}

impl FakeNsm {
	fn new(reply: Reply) -> Arc<Self> {
		Arc::new(Self {
			reply: Mutex::new(reply),
			calls: AtomicUsize::new(0),
			now_ms: AtomicU64::new(T0 * 1000),
		})
	}

	fn doc(not_after: u64, leaf: u8) -> Arc<Self> {
		Self::new(Reply::Doc { not_after, leaf: Leaf::Fixed(leaf) })
	}

	fn set(&self, reply: Reply) {
		*lock(&self.reply) = reply;
	}

	fn calls(&self) -> usize {
		self.calls.load(Ordering::SeqCst)
	}

	fn document(&self, reply: &Reply, call: usize) -> NsmResponse {
		match *reply {
			Reply::Doc { not_after, leaf } => {
				let leaf = match leaf {
					Leaf::Fixed(leaf) => leaf,
					Leaf::PerCall => u8::try_from(call % 256).unwrap(),
				};
				let mut document = vec![leaf];
				document.extend(not_after.to_be_bytes());
				document
					.extend(self.now_ms.load(Ordering::SeqCst).to_be_bytes());
				NsmResponse::Attestation { document }
			}
			Reply::Fail | Reply::Hang(_) => {
				NsmResponse::Error(NsmErrorCode::InternalError)
			}
		}
	}
}

impl NsmProvider for FakeNsm {
	fn nsm_process_request(&self, request: NsmRequest) -> NsmResponse {
		let NsmRequest::Attestation { .. } = request else {
			return NsmResponse::Error(NsmErrorCode::InvalidOperation);
		};
		let call = self.calls.fetch_add(1, Ordering::SeqCst) + 1;
		let reply = lock(&self.reply).clone();
		if let Reply::Hang(release) = reply {
			release.wait();
			let after = lock(&self.reply).clone();
			return self.document(&after, call);
		}
		self.document(&reply, call)
	}

	fn timestamp_ms(&self) -> Result<u64, AttestError> {
		Ok(self.now_ms.load(Ordering::SeqCst))
	}
}

/// Reads what [`FakeNsm`] encoded, standing in for chain and binding checks.
fn fake_verify() -> Arc<FakeVerify> {
	Arc::new(|document: &[u8], inputs: &AttestationInputs| {
		let leaf = document[0];
		let not_after = u64::from_be_bytes(document[1..9].try_into().unwrap());
		let timestamp_ms =
			u64::from_be_bytes(document[9..17].try_into().unwrap());
		Ok(VerifiedAttestation {
			document: document.to_vec(),
			inputs: inputs.clone(),
			timestamp_ms,
			not_after_unix: not_after,
			leaf_fingerprint: [leaf; 32],
		})
	})
}

#[derive(Clone)]
enum Mode {
	Inputs(AttestationInputs),
	ReadError,
	Changed,
	Block(Arc<Barrier>, AttestationInputs),
}

/// A loader whose behaviour tests switch between calls.
#[derive(Clone)]
struct TestLoader {
	mode: Arc<Mutex<Mode>>,
	calls: Arc<AtomicUsize>,
}

impl TestLoader {
	fn new(inputs: AttestationInputs) -> Self {
		Self {
			mode: Arc::new(Mutex::new(Mode::Inputs(inputs))),
			calls: Arc::new(AtomicUsize::new(0)),
		}
	}

	fn set(&self, mode: Mode) {
		*lock(&self.mode) = mode;
	}

	fn calls(&self) -> usize {
		self.calls.load(Ordering::SeqCst)
	}
}

impl InputLoader for TestLoader {
	fn load(&self) -> Result<AttestationInputs, Error> {
		self.calls.fetch_add(1, Ordering::SeqCst);
		let mode = lock(&self.mode).clone();
		match mode {
			Mode::Inputs(inputs) => Ok(inputs),
			Mode::ReadError => {
				Err(Error::EphemeralKey("transient".to_string()))
			}
			Mode::Changed => Err(Error::InputsChanged),
			Mode::Block(release, inputs) => {
				release.wait();
				Ok(inputs)
			}
		}
	}
}

fn fake_cache(
	nsm: &Arc<FakeNsm>,
	loader: &TestLoader,
	config: CacheConfig,
) -> AttestationCache<FakeNsm> {
	AttestationCache::with_fake_verifier(
		Arc::clone(nsm),
		loader.clone(),
		NOT_CHECKED,
		config,
		fake_verify(),
	)
}

/// Move tokio's paused clock and the fake NSM's clock together.
async fn advance(nsm: &FakeNsm, by: Duration) {
	tokio::time::advance(by).await;
	let by_ms = u64::try_from(by.as_millis()).unwrap();
	nsm.now_ms.fetch_add(by_ms, Ordering::SeqCst);
}

/// `healthy()` and `latest()` must always agree.
fn assert_serving<P: NsmProvider + 'static>(
	cache: &AttestationCache<P>,
	serving: bool,
) {
	assert_eq!(cache.latest().is_some(), serving, "latest");
	assert_eq!(cache.healthy(), serving, "healthy");
}

async fn release(barrier: &Arc<Barrier>) {
	let barrier = Arc::clone(barrier);
	tokio::task::spawn_blocking(move || barrier.wait()).await.unwrap();
}

async fn wait_until(mut condition: impl FnMut() -> bool) {
	for _ in 0..500 {
		if condition() {
			return;
		}
		tokio::time::sleep(Duration::from_millis(10)).await;
	}
	panic!("condition never became true");
}

// Wiring: production constructors use the real verifier and the NSM's root.

#[tokio::test]
async fn new_verifies_and_binds_with_the_real_verifier() {
	let inputs = sample_inputs(1);
	let nsm = Arc::new(enclave_mock_nsm(&inputs, true));
	let loader = TestLoader::new(inputs.clone());
	let cache = AttestationCache::new(nsm, loader, REQUIRED, before_expiry());

	let attestation = cache.get().await.unwrap();
	assert_eq!(attestation.inputs, inputs);
	assert_serving(&cache, true);
}

#[tokio::test]
async fn mismatched_doc_is_never_cached() {
	// A genuine mock document that attests none of our inputs.
	let inputs = sample_inputs(1);
	let nsm = Arc::new(MockNsm::new());
	let loader = TestLoader::new(inputs);
	let cache =
		AttestationCache::new(nsm, loader, NOT_CHECKED, before_expiry());

	assert!(matches!(cache.get().await, Err(Error::Binding(_))));
	assert_serving(&cache, false);
	assert_eq!(cache.stats().failures, 1);
}

#[tokio::test]
async fn new_uses_the_nsm_root() {
	// Mock documents only chain to the mock root, so a provider that
	// trusts the AWS root must reject them.
	struct AwsRoot(RecordingNsm);
	impl NsmProvider for AwsRoot {
		fn nsm_process_request(&self, request: NsmRequest) -> NsmResponse {
			self.0.nsm_process_request(request)
		}
		fn timestamp_ms(&self) -> Result<u64, AttestError> {
			self.0.timestamp_ms()
		}
	}
	let inputs = sample_inputs(1);
	let nsm =
		Arc::new(AwsRoot(RecordingNsm::new(enclave_mock_nsm(&inputs, false))));
	let cache = AttestationCache::new(
		nsm,
		TestLoader::new(inputs),
		NOT_CHECKED,
		before_expiry(),
	);
	assert!(matches!(cache.get().await, Err(Error::Document(_))));
	assert_serving(&cache, false);
}

#[tokio::test]
async fn pcr18_required_without_commitment_is_unhealthy() {
	let inputs = sample_inputs(1);
	let nsm = Arc::new(enclave_mock_nsm(&inputs, false));
	let cache = AttestationCache::new(
		nsm,
		TestLoader::new(inputs),
		REQUIRED,
		before_expiry(),
	);
	assert!(matches!(cache.get().await, Err(Error::ManifestOnlyCommitment(_))));
	assert_serving(&cache, false);
	assert_eq!(cache.stats().policy, REQUIRED);
}

#[tokio::test]
async fn get_sends_hash_and_key_and_no_nonce() {
	let inputs = sample_inputs(1);
	let nsm = Arc::new(RecordingNsm::new(enclave_mock_nsm(&inputs, false)));
	let cache = AttestationCache::new(
		Arc::clone(&nsm),
		TestLoader::new(inputs.clone()),
		NOT_CHECKED,
		before_expiry(),
	);
	cache.get().await.unwrap();

	let requests = nsm.requests();
	assert_eq!(
		requests,
		vec![NsmRequest::Attestation {
			user_data: Some(inputs.manifest_hash.to_vec()),
			nonce: None,
			public_key: Some(inputs.ephemeral_public_key),
		}]
	);
}

// Single-flight and hung calls.

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_gets_on_a_cold_cache_make_one_nsm_call() {
	let nsm = FakeNsm::doc(T0 + 3 * 3600, 1);
	let loader = TestLoader::new(sample_inputs(1));
	let cache = Arc::new(fake_cache(&nsm, &loader, before_expiry()));

	let gets: Vec<_> = (0..8)
		.map(|_| {
			let cache = Arc::clone(&cache);
			tokio::spawn(async move { cache.get().await.unwrap() })
		})
		.collect();
	let mut docs = Vec::new();
	for get in gets {
		docs.push(get.await.unwrap());
	}

	assert_eq!(nsm.calls(), 1);
	assert!(docs.iter().all(|d| Arc::ptr_eq(d, &docs[0])));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn hung_nsm_call_does_not_pile_up_threads() {
	let hang = Arc::new(Barrier::new(2));
	let nsm = FakeNsm::new(Reply::Hang(Arc::clone(&hang)));
	let loader = TestLoader::new(sample_inputs(1));
	let config = CacheConfig {
		call_timeout: Duration::from_millis(50),
		..before_expiry()
	};
	let cache = fake_cache(&nsm, &loader, config);

	assert!(matches!(cache.get().await, Err(Error::Timeout)));
	assert_serving(&cache, false);
	for _ in 0..3 {
		assert!(matches!(cache.get().await, Err(Error::InFlight)));
	}
	assert_eq!(nsm.calls(), 1, "no new NSM call while one is stuck");
	assert_eq!(cache.stats().in_flight_rejections, 3);

	nsm.set(Reply::Doc { not_after: T0 + 3 * 3600, leaf: Leaf::Fixed(1) });
	release(&hang).await;
	wait_until(|| !cache.in_flight.load(Ordering::Acquire)).await;

	cache.get().await.unwrap();
	assert_serving(&cache, true);
}

// Expiry.

#[tokio::test(start_paused = true)]
async fn expired_doc_is_never_served() {
	let nsm = FakeNsm::doc(T0 + 3 * 3600, 1);
	let loader = TestLoader::new(sample_inputs(1));
	let cache = fake_cache(&nsm, &loader, before_expiry());
	cache.get().await.unwrap();

	advance(&nsm, 3 * HOUR).await;
	assert_serving(&cache, false);
	assert_eq!(nsm.calls(), 1, "expiry alone makes no NSM call");

	nsm.set(Reply::Fail);
	assert!(matches!(cache.get().await, Err(Error::Nsm(_))));
	assert_serving(&cache, false);
}

#[tokio::test(start_paused = true)]
async fn served_deadline_never_outlives_not_after() {
	// The doc is signed 1 ms into T0, so only 99 whole seconds remain
	// before its chain expires at T0 + 100.
	let nsm = FakeNsm::doc(T0 + 100, 1);
	nsm.now_ms.store(T0 * 1000 + 1, Ordering::SeqCst);
	let loader = TestLoader::new(sample_inputs(1));
	let cache = fake_cache(&nsm, &loader, before_expiry());
	cache.get().await.unwrap();

	advance(&nsm, Duration::from_secs(98)).await;
	assert_serving(&cache, true);
	advance(&nsm, Duration::from_secs(1)).await;
	assert_serving(&cache, false);
}

// BeforeExpiry refresh triggers.

#[tokio::test(start_paused = true)]
async fn refreshes_at_the_margin_and_hits_before_it() {
	let nsm = FakeNsm::doc(T0 + 3 * 3600, 1);
	let loader = TestLoader::new(sample_inputs(1));
	let cache = fake_cache(&nsm, &loader, before_expiry());
	let first = cache.get().await.unwrap();

	advance(&nsm, UNTIL_MARGIN.checked_sub(Duration::from_secs(1)).unwrap())
		.await;
	assert!(Arc::ptr_eq(&cache.get().await.unwrap(), &first));
	assert_eq!(nsm.calls(), 1, "outside the margin: a hit");

	nsm.set(Reply::Doc { not_after: T0 + 6 * 3600, leaf: Leaf::Fixed(2) });
	advance(&nsm, Duration::from_secs(1)).await;
	let refreshed = cache.get().await.unwrap();
	assert_eq!(nsm.calls(), 2, "at the margin: a refresh");
	assert_eq!(refreshed.not_after_unix, T0 + 6 * 3600);
	assert_eq!(cache.stats().near_expiry_refreshes, 1);
}

#[tokio::test(start_paused = true)]
async fn refreshes_when_inputs_change() {
	let nsm = FakeNsm::doc(T0 + 3 * 3600, 1);
	let loader = TestLoader::new(sample_inputs(1));
	let cache = fake_cache(&nsm, &loader, before_expiry());
	cache.get().await.unwrap();

	loader.set(Mode::Inputs(sample_inputs(2)));
	let refreshed = cache.get().await.unwrap();
	assert_eq!(refreshed.inputs, sample_inputs(2));
	assert_eq!(nsm.calls(), 2);
	assert_eq!(cache.stats().inputs_changed_refreshes, 1);
}

#[tokio::test(start_paused = true)]
async fn failed_refresh_after_input_change_drops_the_doc() {
	let nsm = FakeNsm::doc(T0 + 3 * 3600, 1);
	let loader = TestLoader::new(sample_inputs(1));
	let cache = fake_cache(&nsm, &loader, before_expiry());
	cache.get().await.unwrap();

	loader.set(Mode::Inputs(sample_inputs(2)));
	nsm.set(Reply::Fail);
	assert!(matches!(cache.get().await, Err(Error::Nsm(_))));
	assert_serving(&cache, false);
}

// Backoff after a refresh that didn't help.

#[tokio::test(start_paused = true)]
async fn same_leaf_keeps_the_doc_and_backs_off() {
	let nsm = FakeNsm::doc(T0 + 3 * 3600, 1);
	let loader = TestLoader::new(sample_inputs(1));
	let cache = fake_cache(&nsm, &loader, before_expiry());
	let first = cache.get().await.unwrap();

	// Inside the margin the NSM keeps returning the same leaf.
	advance(&nsm, UNTIL_MARGIN).await;
	assert!(Arc::ptr_eq(&cache.get().await.unwrap(), &first));
	assert_eq!(nsm.calls(), 2);
	for _ in 0..5 {
		advance(&nsm, Duration::from_secs(10)).await;
		assert!(Arc::ptr_eq(&cache.get().await.unwrap(), &first));
	}
	assert_eq!(nsm.calls(), 2, "no NSM call during the backoff");

	nsm.set(Reply::Doc { not_after: T0 + 6 * 3600, leaf: Leaf::Fixed(2) });
	advance(&nsm, BACKOFF).await;
	let renewed = cache.get().await.unwrap();
	assert_eq!(nsm.calls(), 3);
	assert_eq!(renewed.not_after_unix, T0 + 6 * 3600);
	let stats = cache.stats();
	assert_eq!((stats.not_extended, stats.same_leaf), (1, 1));
}

#[tokio::test(start_paused = true)]
async fn failed_near_expiry_refresh_is_counted_and_keeps_the_doc() {
	let nsm = FakeNsm::doc(T0 + 3 * 3600, 1);
	let loader = TestLoader::new(sample_inputs(1));
	let cache = fake_cache(&nsm, &loader, before_expiry());
	let first = cache.get().await.unwrap();

	nsm.set(Reply::Fail);
	advance(&nsm, UNTIL_MARGIN).await;
	assert!(Arc::ptr_eq(&cache.get().await.unwrap(), &first));
	assert_serving(&cache, true);
	let stats = cache.stats();
	assert_eq!(stats.refresh_failures, 1);
	assert!(stats.last_error.is_some());
}

// AttestOnce.

#[tokio::test(start_paused = true)]
async fn attest_once_makes_one_call_then_hits_forever() {
	let nsm = FakeNsm::doc(T0 + 3 * 3600, 1);
	let loader = TestLoader::new(sample_inputs(1));
	let cache = fake_cache(&nsm, &loader, attest_once());
	let first = cache.get().await.unwrap();

	advance(&nsm, 10 * HOUR).await;
	for _ in 0..3 {
		assert!(Arc::ptr_eq(&cache.get().await.unwrap(), &first));
	}
	assert_serving(&cache, true);
	assert_eq!(nsm.calls(), 1);
}

#[tokio::test(start_paused = true)]
async fn attest_once_failure_before_first_doc_is_unhealthy() {
	let nsm = FakeNsm::new(Reply::Fail);
	let loader = TestLoader::new(sample_inputs(1));
	let cache = fake_cache(&nsm, &loader, attest_once());
	assert!(cache.get().await.is_err());
	assert_serving(&cache, false);
}

// Watcher.

#[tokio::test(start_paused = true)]
async fn watcher_attests_and_follows_input_changes_without_requests() {
	let nsm = FakeNsm::doc(T0 + 3 * 3600, 1);
	let loader = TestLoader::new(sample_inputs(1));
	let cache = Arc::new(fake_cache(&nsm, &loader, before_expiry()));
	let watcher = cache.spawn_watcher(Duration::from_secs(10));

	// The watcher's job runs on a blocking thread, so wait for its result.
	wait_until(|| cache.healthy()).await;
	assert_eq!(nsm.calls(), 1);

	loader.set(Mode::Inputs(sample_inputs(2)));
	advance(&nsm, Duration::from_secs(10)).await;
	wait_until(|| cache.latest().is_some_and(|a| a.inputs == sample_inputs(2)))
		.await;
	assert_eq!(nsm.calls(), 2);
	assert!(!watcher.is_finished());
	watcher.abort();
}

// Tier 2. A: input drift.

#[tokio::test(start_paused = true)]
async fn transient_read_error_keeps_the_doc_and_is_not_drift() {
	let nsm = FakeNsm::doc(T0 + 3 * 3600, 1);
	let loader = TestLoader::new(sample_inputs(1));
	let cache = fake_cache(&nsm, &loader, before_expiry());
	let first = cache.get().await.unwrap();

	loader.set(Mode::ReadError);
	assert!(Arc::ptr_eq(&cache.get().await.unwrap(), &first));
	assert_serving(&cache, true);
	assert!(!cache.inputs_changed());
	let stats = cache.stats();
	assert_eq!(stats.refresh_failures, 1);
	assert!(stats.last_error.unwrap().contains("transient"));
}

#[tokio::test]
async fn pin_mismatch_stops_serving_at_once_and_for_good() {
	let dir = TempDir::new("pinned");
	let pair = P256Pair::generate().unwrap();
	let original = v2_envelope_with_nonce(1);
	let key_path = write_key(&dir, &pair);
	let manifest_path = write_manifest(&dir, &original);
	let (inputs, _) =
		AttestationInputs::load(&key_path, &manifest_path).unwrap();
	let nsm = Arc::new(enclave_mock_nsm(&inputs, false));
	let pinned = PinnedInputs::new(inputs, &key_path, &manifest_path);
	let cache = Arc::new(AttestationCache::new(
		nsm,
		pinned,
		NOT_CHECKED,
		before_expiry(),
	));
	cache.get().await.unwrap();

	// Waiting starts before the change, the other order is checked below.
	let waiter = tokio::spawn({
		let cache = Arc::clone(&cache);
		async move { cache.wait_inputs_changed().await }
	});

	write_manifest(&dir, &v2_envelope_with_nonce(2));
	assert!(matches!(cache.get().await, Err(Error::InputsChanged)));
	// Immediately, not when the cached doc would have expired.
	assert_serving(&cache, false);
	assert!(cache.inputs_changed());
	assert!(cache.stats().inputs_changed);
	tokio::time::timeout(Duration::from_secs(1), waiter)
		.await
		.unwrap()
		.unwrap();

	write_manifest(&dir, &original);
	assert!(matches!(cache.get().await, Err(Error::InputsChanged)));
	assert_serving(&cache, false);
	tokio::time::timeout(Duration::from_secs(1), cache.wait_inputs_changed())
		.await
		.expect("resolves when already set");
}

#[tokio::test(start_paused = true)]
async fn loader_inputs_changed_error_marks_drift() {
	let nsm = FakeNsm::doc(T0 + 3 * 3600, 1);
	let loader = TestLoader::new(sample_inputs(1));
	let cache = fake_cache(&nsm, &loader, before_expiry());
	cache.get().await.unwrap();

	loader.set(Mode::Changed);
	assert!(matches!(cache.get().await, Err(Error::InputsChanged)));
	loader.set(Mode::Inputs(sample_inputs(1)));
	assert!(matches!(cache.get().await, Err(Error::InputsChanged)));
	assert_serving(&cache, false);
	assert_eq!(nsm.calls(), 1);
}

// Tier 2. B: lock-free snapshot.

#[tokio::test(start_paused = true)]
async fn latest_follows_get() {
	let nsm = FakeNsm::doc(T0 + 3 * 3600, 1);
	let loader = TestLoader::new(sample_inputs(1));
	let cache = fake_cache(&nsm, &loader, before_expiry());
	assert_serving(&cache, false);

	let first = cache.get().await.unwrap();
	assert!(Arc::ptr_eq(&cache.latest().unwrap(), &first));
	assert_serving(&cache, true);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn latest_serves_the_valid_doc_while_a_near_expiry_refresh_hangs() {
	// A margin longer than the doc's life makes every get a refresh.
	let config = CacheConfig {
		refresh: RefreshPolicy::BeforeExpiry {
			margin: 4 * HOUR,
			same_leaf_backoff: BACKOFF,
		},
		call_timeout: Duration::from_secs(30),
	};
	let nsm = FakeNsm::doc(T0 + 3 * 3600, 1);
	let loader = TestLoader::new(sample_inputs(1));
	let cache = Arc::new(fake_cache(&nsm, &loader, config));
	let first = cache.get().await.unwrap();

	let hang = Arc::new(Barrier::new(2));
	nsm.set(Reply::Hang(Arc::clone(&hang)));
	let refreshing = tokio::spawn({
		let cache = Arc::clone(&cache);
		async move { cache.get().await.map(|_| ()) }
	});
	wait_until(|| nsm.calls() == 2).await;

	assert!(Arc::ptr_eq(&cache.latest().unwrap(), &first));
	assert_serving(&cache, true);

	nsm.set(Reply::Doc { not_after: T0 + 6 * 3600, leaf: Leaf::Fixed(2) });
	release(&hang).await;
	refreshing.await.unwrap().unwrap();
	assert_eq!(cache.latest().unwrap().not_after_unix, T0 + 6 * 3600);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn input_change_withdraws_the_old_doc_before_refreshing() {
	let nsm = FakeNsm::doc(T0 + 3 * 3600, 1);
	let loader = TestLoader::new(sample_inputs(1));
	let config = CacheConfig {
		call_timeout: Duration::from_secs(30),
		..before_expiry()
	};
	let cache = Arc::new(fake_cache(&nsm, &loader, config));
	cache.get().await.unwrap();

	let hang = Arc::new(Barrier::new(2));
	nsm.set(Reply::Hang(Arc::clone(&hang)));
	loader.set(Mode::Inputs(sample_inputs(2)));
	let refreshing = tokio::spawn({
		let cache = Arc::clone(&cache);
		async move { cache.get().await.map(|_| ()) }
	});
	wait_until(|| nsm.calls() == 2).await;

	// Fail closed while the new inputs are being attested.
	assert_serving(&cache, false);

	nsm.set(Reply::Doc { not_after: T0 + 3 * 3600, leaf: Leaf::Fixed(2) });
	release(&hang).await;
	refreshing.await.unwrap().unwrap();
	assert_eq!(cache.latest().unwrap().inputs, sample_inputs(2));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn timeout_during_input_change_never_serves_the_old_doc() {
	let nsm = FakeNsm::doc(T0 + 3 * 3600, 1);
	let loader = TestLoader::new(sample_inputs(1));
	let config = CacheConfig {
		call_timeout: Duration::from_millis(50),
		..before_expiry()
	};
	let cache = fake_cache(&nsm, &loader, config);
	cache.get().await.unwrap();

	let hang = Arc::new(Barrier::new(2));
	nsm.set(Reply::Hang(Arc::clone(&hang)));
	loader.set(Mode::Inputs(sample_inputs(2)));
	assert!(matches!(cache.get().await, Err(Error::Timeout)));
	assert_serving(&cache, false);

	nsm.set(Reply::Fail);
	release(&hang).await;
}

// Tier 2. C: back off when notAfter doesn't improve.

#[tokio::test(start_paused = true)]
async fn new_leaf_without_later_not_after_still_backs_off() {
	// An intermediate expiring first caps notAfter while the NSM issues a
	// new leaf on every call.
	let nsm = FakeNsm::new(Reply::Doc {
		not_after: T0 + 3 * 3600,
		leaf: Leaf::PerCall,
	});
	let loader = TestLoader::new(sample_inputs(1));
	let cache = fake_cache(&nsm, &loader, before_expiry());
	cache.get().await.unwrap();

	advance(&nsm, UNTIL_MARGIN).await;
	cache.get().await.unwrap();
	assert_eq!(nsm.calls(), 2);
	for _ in 0..5 {
		advance(&nsm, Duration::from_secs(10)).await;
		cache.get().await.unwrap();
	}
	assert_eq!(nsm.calls(), 2, "one attempt per backoff, not every tick");
	advance(&nsm, BACKOFF).await;
	cache.get().await.unwrap();
	assert_eq!(nsm.calls(), 3);
	let stats = cache.stats();
	assert_eq!((stats.not_extended, stats.same_leaf), (2, 0));
}

#[tokio::test(start_paused = true)]
async fn input_change_bypasses_the_backoff() {
	let nsm = FakeNsm::doc(T0 + 3 * 3600, 1);
	let loader = TestLoader::new(sample_inputs(1));
	let cache = fake_cache(&nsm, &loader, before_expiry());
	cache.get().await.unwrap();
	advance(&nsm, UNTIL_MARGIN).await;
	cache.get().await.unwrap();
	assert_eq!(nsm.calls(), 2, "backoff started");

	loader.set(Mode::Inputs(sample_inputs(2)));
	advance(&nsm, Duration::from_secs(1)).await;
	assert_eq!(cache.get().await.unwrap().inputs, sample_inputs(2));
	assert_eq!(nsm.calls(), 3);
}

// Tier 2. D: load and attest run as one guarded job.

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn stuck_loader_times_out_and_blocks_new_jobs_until_it_returns() {
	let nsm = FakeNsm::doc(T0 + 3 * 3600, 1);
	let block = Arc::new(Barrier::new(2));
	let loader = TestLoader::new(sample_inputs(1));
	loader.set(Mode::Block(Arc::clone(&block), sample_inputs(1)));
	let config = CacheConfig {
		call_timeout: Duration::from_millis(50),
		..before_expiry()
	};
	let cache = fake_cache(&nsm, &loader, config);

	assert!(matches!(cache.get().await, Err(Error::Timeout)));
	for _ in 0..3 {
		assert!(matches!(cache.get().await, Err(Error::InFlight)));
	}
	assert_eq!(loader.calls(), 1, "no new load while one is stuck");
	assert_eq!(nsm.calls(), 0);
	assert_eq!(cache.stats().timeouts, 1);

	loader.set(Mode::Inputs(sample_inputs(1)));
	release(&block).await;
	wait_until(|| !cache.in_flight.load(Ordering::Acquire)).await;
	cache.get().await.unwrap();
	assert_serving(&cache, true);
}

// unsafe-verifier.

#[tokio::test]
async fn new_rejects_a_qemu_shaped_doc() {
	let inputs = sample_inputs(1);
	let nsm = Arc::new(FixedDocNsm(qemu_shaped_document(&inputs, true)));
	let cache = AttestationCache::new(
		nsm,
		TestLoader::new(inputs),
		REQUIRED,
		before_expiry(),
	);
	assert!(matches!(cache.get().await, Err(Error::Document(_))));
	assert_serving(&cache, false);
}

#[cfg(feature = "unsafe-verifier")]
#[tokio::test(start_paused = true)]
async fn skip_chain_cache_serves_a_qemu_shaped_doc_once() {
	let inputs = sample_inputs(1);
	let nsm = Arc::new(FixedDocNsm(qemu_shaped_document(&inputs, true)));
	let loader = TestLoader::new(inputs.clone());
	let cache = AttestationCache::unsafe_new_skip_chain_verification(
		nsm,
		loader.clone(),
		REQUIRED,
		Duration::from_secs(5),
	);
	assert_eq!(cache.get().await.unwrap().inputs, inputs);
	tokio::time::advance(10 * HOUR).await;
	assert_serving(&cache, true);
	assert_eq!(cache.stats().refresh, RefreshPolicy::AttestOnce);

	// Binding still applies: a doc for other inputs is refused.
	loader.set(Mode::Inputs(sample_inputs(2)));
	assert!(cache.get().await.is_err());
	assert_serving(&cache, false);
}
