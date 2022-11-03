#pragma once
#include <qpl/qpl.hpp>

template<typename T>
using mat = std::vector<std::vector<T>>;

namespace galois {
	constexpr auto add(int x, int y) {
		return x ^ y;
	}

	constexpr auto mul(int x, int y) {
		int z = 0;
		for (int i = 0; i < 8; ++i) {
			z ^= x & -(y & 1);
			y >>= 1;
			x <<= 1;
			x ^= (0x11B & -(x >> 8));
		}
		return z;
	}

	template<typename T>
	constexpr auto inverse(T x) {
		T z = x;
		for (int i = 0; i < 6; ++i) {
			z = galois::mul(z, z);
			z = galois::mul(z, x);
		}
		return galois::mul(z, z);
	}

	template<typename T>
	constexpr auto divide(T x, T y) {
		return galois::mul(x, galois::inverse(y));
	}
}

template<typename T>
void print_matrix(mat<T> m) {
	for (auto& i : m) {
		qpl::print("[");
		for (auto& i : i) {
			qpl::print(qpl::str_spaced((int)i, 3), " ");
		}
		qpl::println("]");
	}
}

template<typename T>
mat<T> galois_matrix_inverse(mat<T> M) {
	auto N = M.size();
	mat<T> R(N, std::vector<T>(N, T{}));
	for (qpl::size i = 0; i < M.size(); ++i) {
		R[i][i] = 1;
	}
	for (qpl::size i = 0; i < M.size(); ++i) {

		auto diagonal = M[i][i];
		auto inv = galois::inverse(diagonal);
		for (qpl::size row = 0; row < N; ++row) {
			M[i][row] = galois::mul(inv, M[i][row]);
			R[i][row] = galois::mul(inv, R[i][row]);
		}

		for (qpl::size col = 0; col < M.size(); ++col) {
			if (col == i) continue;

			auto n = M[col][i];
			for (qpl::size row = 0; row < M.size(); ++row) {
				M[col][row] = galois::add(galois::mul(n, M[i][row]), M[col][row]);
				R[col][row] = galois::add(galois::mul(n, R[i][row]), R[col][row]);
			}
		}
	}
	return R;
}

template<typename T>
mat<T> galois_matrix_multiply(const mat<T>& a, const mat<T>& b) {
	auto N = a.size();
	mat<T> result(N, std::vector<T>(N));
	for (qpl::size i = 0u; i < N; ++i) {
		std::array<T, N> sum{};
		for (qpl::size j = 0u; j < N; ++j) {
			for (qpl::size k = 0u; k < N; ++k) {
				sum[k] ^= galois::mul(a[j][k], b[i][j]);
			}
		}
		result[i] = sum;
	}
	return result;
}

template<typename T>
constexpr T matrix_determinant(mat<T> mat, qpl::size n = qpl::size_max) {
	T num1, num2, det = 1, total = 1; // Initialize result
	n = (n == qpl::size_max ? mat.size() : n);

	qpl::size index;

	std::vector<T> temp(n + 1);

	for (qpl::size i = 0u; i < n; ++i) {
		index = i;

		while (index < n && mat[index][i] == 0) {
			index++;
		}
		if (index == n) {
			continue;
		}
		if (index != i) {
			for (qpl::size j = 0u; j < n; ++j) {
				std::swap(mat[index][j], mat[i][j]);
			}
			det = det * std::pow(-1, index - i);
		}

		// storing the values of diagonal row elements
		for (qpl::size j = 0; j < n; ++j) {
			temp[j] = mat[i][j];
		}
		// traversing every row below the diagonal element
		for (qpl::size j = i + 1; j < n; ++j) {
			num1 = temp[i]; // value of diagonal element
			num2 = mat[j][i]; // value of next row element

			// traversing every column of row
			// and multiplying to every row
			for (qpl::size k = 0; k < n; ++k) {
				// multiplying to make the diagonal
				// element and next row element equal
				mat[j][k] = (num1 * mat[j][k]) - (num2 * temp[k]);
			}
			total = total * num1; // Det(kA)=kDet(A);
		}
	}

	// multiplying the diagonal elements to get determinant
	for (qpl::size i = 0; i < n; ++i) {
		det = det * mat[i][i];
	}
	return (det / total); // Det(kA)/k=Det(A);
}

template<typename T>
constexpr T galois_matrix_determinant(mat<T> mat, qpl::size n = qpl::size_max) {
	T num1, num2, det = 1, total = 1; // Initialize result

	n = (n == qpl::size_max ? mat.size() : n);

	// temporary array for storing row
	std::vector<T> temp(n + 1);

	// loop for traversing the diagonal elements
	for (qpl::size i = 0u; i < n; ++i) {
		// storing the values of diagonal row elements
		for (qpl::size j = 0; j < n; ++j) {
			temp[j] = mat[i][j];
		}
		// traversing every row below the diagonal element
		for (qpl::size j = i + 1; j < n; ++j) {
			num1 = temp[i]; // value of diagonal element
			num2 = mat[j][i]; // value of next row element

			for (qpl::size k = 0; k < n; ++k) {
				mat[j][k] = galois::mul(num1, mat[j][k]) ^ galois::mul(num2, temp[k]);
			}
			total = galois::mul(total, num1);
		}
	}

	// multiplying the diagonal elements to get determinant
	for (qpl::size i = 0; i < n; ++i) {
		det = galois::mul(det, mat[i][i]);
	}
	//return (det / total); // Det(kA)/k=Det(A);
	return galois::divide(det, total); // Det(kA)/k=Det(A);
}


auto apply_mds(std::vector<qpl::u8> state, const mat<qpl::u8>& mat) {
	auto N = mat.size();
	std::vector<qpl::u8> result(N * N);
	for (qpl::size col = 0u; col < N; ++col) {

		for (qpl::size m = 0u; m < N; ++m) {
			qpl::u8 byte = 0;
			for (qpl::size row = 0u; row < N; ++row) {
				auto index = col * N + row;
				byte ^= galois::mul(mat[m][row], state[index]);
			}
			result[col * N + m] = byte;
		}
	}
	return result;
}

template<bool print = false>
bool test_mds(const mat<qpl::u8>& m) {

	auto N = m.size();
	std::vector<qpl::u8> state(N * N);
	for (auto& i : state) {
		i = qpl::random(0, 255);
	}

	auto diffused = apply_mds(state, m);
	auto m_inv = galois_matrix_inverse(m);

	auto reverse = apply_mds(diffused, m_inv);

	if constexpr (print) {
		if (reverse != state) {
			qpl::println(qpl::hex_string(qpl::container_memory_to_string(state)));
			qpl::println(qpl::hex_string(qpl::container_memory_to_string(reverse)));
		}
	}

	return (reverse == state);
}

template<bool print>
bool check_if_mds(const mat<qpl::u8>& m, qpl::size S) {
	auto N = m.size();
	mat<qpl::u8> submatrix(S, std::vector<qpl::u8>(S));
	for (qpl::size y = 0u; y < N - S; ++y) {
		for (qpl::size x = 0u; x < N - S; ++x) {

			for (qpl::size sy = 0u; sy < S; ++sy) {
				for (qpl::size sx = 0u; sx < S; ++sx) {
					submatrix[sy][sx] = m[sy + y][sx + x];
				}
			}
			auto det = galois_matrix_determinant(submatrix);
			if (det == 0) {
				if constexpr (print) {
					print_matrix(submatrix);
					qpl::println("is not invertible : ", (int)det);
					auto inverse = galois_matrix_inverse(submatrix);
					print_matrix(inverse);
				}
				return false;
			}
		}
	}
	return true;
}

template<bool print = false>
bool check_if_mds(const mat<qpl::u8>& m) {
	for (qpl::isize i = m.size() - 1; i >= 0; --i) {
		if (!check_if_mds<print>(m, i)) {
			return false;
		}
	}
	return true;
}
bool check_if_nonzero(const mat<qpl::u8>& m) {
	auto i = galois_matrix_inverse(m);
	for (auto& i : i) {
		for (auto& i : i) {
			if (i == 0) {
				return false;
			}
		}
	}
	return true;
}

std::vector<qpl::size> find_common_mds_bytes(qpl::size N, qpl::size generate_1_n, qpl::size stop) {
	mat<qpl::u8> m(N, std::vector<qpl::u8>(N));

	qpl::size valid_ctr = 0u;
	qpl::small_clock clock;

	std::vector<qpl::u8> row(N);

	std::unordered_map<qpl::size, qpl::u8> common_map;

	std::array<std::pair<qpl::size, qpl::size>, 256> byte_counts;
	for (auto& i : byte_counts) {
		i = std::make_pair(0, 0);
	}
	for (qpl::size i = 0u; i < byte_counts.size(); ++i) {
		byte_counts[i].second = i;
		byte_counts[i].first = 0;
	}

	qpl::size total_founds = 0u;

	for (qpl::size ctr = 0u;; ++ctr) {
		for (auto& i : row) {
			i = qpl::u8_cast(qpl::random(1ull, generate_1_n));
		}

		for (qpl::size c = 0u; c < N; ++c) {
			for (qpl::size r = 0u; r < N; ++r) {
				m[c][r] = row[((N - r - 1) + c) % N];
			}
		}

		auto inv = galois_matrix_inverse(m);

		if (qpl::find(inv[0], 0)) {
			continue;
		}

		for (auto& i : inv[0]) {
			if (i > generate_1_n) {
				++byte_counts[i].first;
				++total_founds;
			}
		}

		if (ctr > stop) {

			auto sorted = byte_counts;
			qpl::sort(sorted, [](auto a, auto b) {
				return a.first > b.first;
			});
			
			std::vector<qpl::size> search(generate_1_n);
			for (qpl::size i = 0u; i < search.size(); ++i) {
				search[i] = sorted[i].second;
			}
			return search;
		}
	}
	return {};
}

void test(qpl::size N) {
	mat<qpl::u8> m(N, std::vector<qpl::u8>(N));

	std::vector<qpl::u8> row(N);
	qpl::size valid = 0u;
	for (qpl::size ctr = 0u;; ++ctr) {

		for (auto& i : row) {
			i = qpl::random(1, 255);
		}

		for (qpl::size c = 0u; c < N; ++c) {
			for (qpl::size r = 0u; r < N; ++r) {
				m[c][r] = row[((N - r - 1) + c) % N];
			}
		}
		auto is_nonzero = check_if_nonzero(m);
		auto is_mds = is_nonzero && check_if_mds(m);
		auto check = test_mds(m);

		if (is_mds && check) {
			print_matrix(m);
			++valid;
		}
		if (qpl::get_time_signal(1.0)) {
			auto rate = valid / qpl::f64_cast(ctr);
			qpl::println(qpl::big_number_string(ctr), " - ", qpl::percentage_string(rate), " valid");
		}
	}
}

std::vector<std::vector<std::vector<qpl::size>>> find_mds(qpl::size N, qpl::size generate_1_n, qpl::size find_target, std::vector<qpl::size> common_bytes) {
	mat<qpl::u8> m(N, std::vector<qpl::u8>(N));

	qpl::size valid_ctr = 0u;
	qpl::small_clock clock;

	std::vector<std::vector<qpl::size>> findings;
	std::vector<std::vector<qpl::size>> findings_inv;

	std::vector<qpl::u8> row(N);

	std::unordered_map<qpl::size, qpl::u8> common_map;

	for (qpl::size i = 0u; i < generate_1_n; ++i) {
		common_map.insert(std::make_pair(i + 1, qpl::u8_cast(i)));
	}
	for (qpl::size i = 0u; i < common_bytes.size(); ++i) {
		common_map.insert(std::make_pair(common_bytes[i], qpl::u8_cast(i + 16)));
	}

	std::array<bool, 256> common_inverts_table{};
	for (auto& i : common_bytes) {
		common_inverts_table[i] = true;
	}
	for (qpl::size i = 1; i <= generate_1_n; ++i) {
		common_inverts_table[i] = true;
	}

	std::array<std::pair<qpl::size, qpl::size>, 256> byte_counts{};
	for (qpl::size i = 0u; i < byte_counts.size(); ++i) {
		byte_counts[i].second = i;
		byte_counts[i].first = 0;
	}

	qpl::size total_founds = 0u;

	for (qpl::size ctr = 0u;; ++ctr) {
		for (auto& i : row) {
			i = qpl::u8_cast(qpl::random(1ull, generate_1_n));
		}

		for (qpl::size c = 0u; c < N; ++c) {
			for (qpl::size r = 0u; r < N; ++r) {
				m[c][r] = row[((N - r - 1) + c) % N];
			}
		}

		auto inv = galois_matrix_inverse(m);

		if (qpl::find(inv[0], 0)) {
			continue;
		}

		for (auto& i : inv[0]) {
			if (i > generate_1_n) {
				++byte_counts[i].first;
				++total_founds;
			}
		}

		bool valid = true;
		for (auto& i : inv[0]) {
			if (!common_inverts_table[i]) {
				valid = false;
				break;
			}
		}
		if (valid) {
			auto is_mds = check_if_mds(m);
			auto check = test_mds(m);

			if (false && is_mds && check) {
				++valid_ctr;

				findings.push_back({});
				findings.back().resize(N * N);
				for (qpl::size i = 0u; i < N * N; ++i) {
					findings.back()[i] = m[i / N][i % N];
				}

				findings_inv.push_back({});
				findings_inv.back().resize(N * N);
				for (qpl::size i = 0u; i < N * N; ++i) {
					findings_inv.back()[i] = inv[i / N][i % N];
				}

				auto valid_rate = (qpl::f64_cast(valid_ctr) / clock.elapsed_f());

				if (findings.size() == find_target) {
					std::vector<std::vector<std::vector<qpl::size>>> result{ findings, findings_inv };
					return result;
				}
			}
		}
	}
	return {};
}

std::vector<std::vector<std::vector<qpl::size>>> find_mds(qpl::size N, qpl::size generate_1_n, qpl::size find_target) {
	auto common_bytes = find_common_mds_bytes(N, generate_1_n, 100'000);
	qpl::println("common bytes : ", common_bytes);
	return find_mds(N, generate_1_n, find_target, common_bytes);
}