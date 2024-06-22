//! n choose k helper

/// Computes n choose k combinations over a vector of elements of type T.
///
/// # Arguments
///
/// * `input` - A reference to a vector of elements of type T.
/// * `k` - The number of elements to choose in each combination.
///
/// # Examples
///
/// ```
/// use qos_crypto::n_choose_k::combinations;
///
/// let input = vec![1, 2, 3, 4];
/// let k = 2;
/// let combinations = combinations(&input, k);
///
/// // Verify that the computed combinations match the expected result
/// assert_eq!(combinations, vec![
///     vec![1, 2],
///     vec![1, 3],
///     vec![1, 4],
///     vec![2, 3],
///     vec![2, 4],
///     vec![3, 4],
/// ]);
/// ```
#[must_use]
pub fn combinations<T: Clone>(input: &[T], k: usize) -> Vec<Vec<T>> {
	let n = input.len();

	if k > n || k == 0 {
		return Vec::new();
	}

	let mut combos =
		Vec::with_capacity(expected_combinations_count(input.len(), k));
	let mut indices: Vec<_> = (0..k).collect();

	// Generate combinations
	while indices[0] <= n - k {
		// Create a combination by mapping indices to corresponding elements in
		// the input
		let combination: Vec<_> =
			indices.iter().map(|&i| input[i].clone()).collect();
		combos.push(combination);

		let mut i = k;
		while i > 1 && indices[i - 1] == n - k + i - 1 {
			i -= 1;
		}

		indices[i - 1] += 1;

		for j in i..k {
			indices[j] = indices[j - 1] + 1;
		}
	}

	combos
}

fn expected_combinations_count(n: usize, k: usize) -> usize {
	factorial(n) / (factorial(k) * factorial(n - k))
}

fn factorial(n: usize) -> usize {
	if n == 0 || n == 1 {
		1
	} else {
		(2..=n).product()
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn normal_cases() {
		// n = 4, k = 2
		let byte_input = vec![b'a', b'b', b'c', b'd'];
		let k1 = 2;
		let byte_result = combinations(&byte_input, k1);
		assert_eq!(
			byte_result.len(),
			expected_combinations_count(byte_input.len(), k1)
		);
		assert!(byte_result.contains(&vec![b'a', b'b']));
		assert!(byte_result.contains(&vec![b'a', b'c']));
		assert!(byte_result.contains(&vec![b'a', b'd']));
		assert!(byte_result.contains(&vec![b'b', b'c']));
		assert!(byte_result.contains(&vec![b'b', b'd']));
		assert!(byte_result.contains(&vec![b'c', b'd']));

		// n = 3, k = 3
		let char3_input = vec!['x', 'y', 'z'];
		let k2 = 3;
		let char3_result = combinations(&char3_input, k2);
		assert_eq!(
			char3_result.len(),
			expected_combinations_count(char3_input.len(), k2)
		);
		assert_eq!(char3_result, vec![vec!['x', 'y', 'z']]);

		// n = 2, k = 1
		let char2_input = vec!['p', 'q'];
		let k3 = 1;
		let char2_result = combinations(&char2_input, k3);
		assert_eq!(
			char2_result.len(),
			expected_combinations_count(char2_input.len(), k3)
		);
		assert_eq!(char2_result, vec![vec!['p'], vec!['q']]);
	}

	#[test]
	fn edge_cases() {
		// empty input
		let empty_input: Vec<usize> = Vec::new();
		let empty_result = combinations(&empty_input, 0);
		assert_eq!(empty_result.len(), 0);

		// k = 0
		let input = vec![1, 2, 3, 4, 5];
		let k = 0;
		let result = combinations(&input, k);
		assert_eq!(result.len(), 0);
	}

	#[test]
	fn factorial_works() {
		assert_eq!(factorial(0), 1);
		assert_eq!(factorial(1), 1);
		assert_eq!(factorial(5), 120);
		assert_eq!(factorial(10), 3_628_800);
		assert_eq!(factorial(20), 2_432_902_008_176_640_000);
	}
}
