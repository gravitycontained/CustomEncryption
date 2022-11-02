#pragma once
#include <qpl/qpl.hpp>

template<typename T, qpl::size N>
using mat = std::array<std::array<T, N>, N>;

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

template<typename T, qpl::size N>
void print_matrix(mat<T, N> m) {
	for (auto& i : m) {
		qpl::print("[");
		for (auto& i : i) {
			qpl::print(qpl::str_spaced((int)i, 3), " ");
		}
		qpl::println("]");
	}
}

template<typename T, qpl::size N>
mat<T, N> galois_matrix_inverse(mat<T, N> M) {
	mat<T, N> R{}; //fills R with 0s
	for (unsigned i = 0; i < N; ++i) {
		R[i][i] = 1; //makes the matrix the identity matrix
	}
	for (unsigned i = 0; i < N; ++i) {

		//sets M[i][i] to 1, divide by row by inverse
		auto diagonal = M[i][i];
		auto inv = galois::inverse(diagonal);
		for (unsigned row = 0; row < N; ++row) {
			M[i][row] = galois::mul(inv, M[i][row]);
			R[i][row] = galois::mul(inv, R[i][row]);
		}

		//pivots the column
		for (unsigned col = 0; col < N; ++col) {
			if (col == i) continue;

			auto n = M[col][i];
			for (unsigned row = 0; row < N; ++row) {
				M[col][row] = galois::add(galois::mul(n, M[i][row]), M[col][row]);
				R[col][row] = galois::add(galois::mul(n, R[i][row]), R[col][row]);
			}
		}
	}
	return R;
}

template<typename T, qpl::size N>
mat<T, N> galois_matrix_multiply(const mat<T, N>& a, const mat<T, N>& b) {
	mat<T, N> result;
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

template<typename T, qpl::size N>
constexpr T matrix_determinant(mat<T, N> mat, qpl::size n = N) {
	T num1, num2, det = 1, total = 1; // Initialize result

	qpl::size index;

	// temporary array for storing row
	std::vector<T> temp(n + 1);

	// loop for traversing the diagonal elements
	for (qpl::size i = 0u; i < n; ++i) {
		index = i; // initialize the index

		// finding the index which has non zero value
		while (index < n && mat[index][i] == 0) {
			index++;
		}
		if (index == n) {
			// if there is non zero element
			// the determinant of matrix as zero
			continue;
		}
		if (index != i) {
			// loop for swapping the diagonal element row and
			// index row
			for (qpl::size j = 0u; j < n; ++j) {
				std::swap(mat[index][j], mat[i][j]);
			}
			// determinant sign changes when we shift rows
			// go through determinant properties
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

template<typename T, qpl::size N>
constexpr T galois_matrix_determinant(mat<T, N> mat, qpl::size n = N) {
	T num1, num2, det = 1, total = 1; // Initialize result

	qpl::size index;

	// temporary array for storing row
	std::vector<T> temp(n + 1);

	// loop for traversing the diagonal elements
	for (qpl::size i = 0u; i < n; ++i) {
		index = i; // initialize the index

		// finding the index which has non zero value
		//while (index < n && mat[index][i] == 0) {
		//	index++;
		//}
		//if (index == n) {
		//	// if there is non zero element
		//	// the determinant of matrix as zero
		//	continue;
		//}
		//if (index != i) {
		//	// loop for swapping the diagonal element row and
		//	// index row
		//	for (qpl::size j = 0u; j < n; ++j) {
		//		std::swap(mat[index][j], mat[i][j]);
		//	}
		//	// determinant sign changes when we shift rows
		//	// go through determinant properties
		//	//det = det * std::pow(-1, index - i);
		//}

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
				//mat[j][k] = (num1 * mat[j][k]) - (num2 * temp[k]);
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


template<qpl::size N>
auto apply_mds(std::array<qpl::u8, N* N> state, const mat<qpl::u8, N>& mat) {
	std::array<qpl::u8, N* N> result;
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

template<qpl::size N, bool print = false>
bool test_mds(const mat<qpl::u8, N>& m) {

	std::array<qpl::u8, N* N> state;
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

template<qpl::size N, qpl::size S, bool print>
bool check_if_mds(const mat<qpl::u8, N>& m) {
	mat<qpl::u8, S> submatrix;
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

template<qpl::size N, bool print = false>
bool check_if_mds(const mat<qpl::u8, N>& m) {

	bool result = true;
	qpl::constexpr_iterate<N - 1>([&](auto i) {
		constexpr auto s = (N - 1) - i;
		result = result && check_if_mds<N, s, print>(m);
		});
	return result;
}
template<qpl::size N>
bool check_if_nonzero(const mat<qpl::u8, N>& m) {
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

void print_galois_mul() {
	std::array<qpl::size, 16> common_inverts = { 199, 141, 87, 43, 196, 164, 245, 180, 153, 49, 83, 82, 86, 116, 70, 156 };

	auto print_mul = [](qpl::u8 n) {
		bool first = true;
		qpl::print("std::array<qpl::u8, 256>{ ");
		for (qpl::size i = 0u; i < 256; ++i) {
			if (!first) {
				qpl::print(", ");
			}
			first = false;
			auto result = qpl::u8_cast(galois::mul(i, n));
			qpl::print(qpl::hex_string(result, "0x", qpl::base_format::base36l, true), 'u');
		}
		qpl::println("},");
	};

	for (qpl::size i = 0u; i < 16; ++i) {
		print_mul(i + 1);
	}
	for (qpl::size i = 0u; i < 16; ++i) {
		print_mul(common_inverts[i]);
	}
}

template<qpl::size N>
void find_mds() {

	mat<qpl::u8, N> m;

	qpl::size valid_ctr = 0u;
	qpl::small_clock clock;

	std::vector<std::array<qpl::size, N>> findings;
	std::vector<std::array<qpl::size, N>> findings_inv;
	std::unordered_set<qpl::size> total_uniques;

	std::array<qpl::u8, N> row;

	constexpr qpl::size common_search_size = 16;
	std::array<qpl::size, 16> common_inverts = { 199, 141, 87, 43, 196, 164, 245, 180, 153, 49, 83, 82, 86, 116, 70, 156 };
	std::unordered_map<qpl::size, qpl::u8> common_map;

	for (qpl::size i = 0u; i < 16; ++i) {
		common_map.insert(std::make_pair(i + 1, i));
	}
	for (qpl::size i = 0u; i < 16; ++i) {
		common_map.insert(std::make_pair(common_inverts[i], i + 16));
	}

	qpl::println(common_map);

	std::array<bool, 256> common_inverts_table{};
	for (auto& i : common_inverts) {
		common_inverts_table[i] = true;
	}
	for (qpl::size i = 1; i <= common_search_size; ++i) {
		common_inverts_table[i] = true;
	}

	std::array<std::pair<qpl::size, qpl::size>, 256> byte_counts{};
	for (qpl::size i = 0u; i < byte_counts.size(); ++i) {
		byte_counts[i].second = i;
		byte_counts[i].first = 0;
	}

	qpl::println("- - - ");
	qpl::size total_founds = 0u;

	for (qpl::size ctr = 0u;; ++ctr) {
		for (auto& i : row) {
			i = qpl::random(1ull, common_search_size);
		}

		for (qpl::size c = 0u; c < N; ++c) {
			for (qpl::size r = 0u; r < N; ++r) {
				m[c][r] = row[(r + c) % N];
			}
		}

		//bool valid = true;
		auto inv = galois_matrix_inverse(m);

		if (qpl::find(inv[0], 0)) {
			continue;
		}

		for (auto& i : inv[0]) {
			if (i > common_search_size) {
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

			if (is_mds && check) {
				++valid_ctr;

				findings.push_back({});
				for (qpl::size i = 0u; i < N; ++i) {
					findings.back()[i] = m[0][i];
				}

				findings_inv.push_back({});
				for (qpl::size i = 0u; i < N; ++i) {
					findings_inv.back()[i] = inv[0][i];
				}


				auto valid_rate = (qpl::f64_cast(valid_ctr) / clock.elapsed_f());

				qpl::println(findings.size(), " (", valid_rate, " / sec)");

				if (findings.size() == 64) {

					auto print = [&]() {
						qpl::print("std::array<qpl::u8, 256>{ ");
						bool first = true;
						for (qpl::size c = 0u; c < N; ++c) {
							for (qpl::size r = 0u; r < N; ++r) {
								if (!first) {
									qpl::print(", ");
								}
								first = false;

								auto row_value = row[(c + r) % N];
								auto map_value = common_map[row_value];

								qpl::print(qpl::hex_string(map_value, "0x", qpl::base_format::base36l, true), 'u');
							}
						}
						qpl::println("},");
					};

					for (qpl::size f = 0u; f < findings.size(); ++f) {
						for (qpl::size i = 0u; i < N; ++i) {
							row[i] = findings[f][i];
						}
						print();
					}
					qpl::println("\n\n");

					for (qpl::size f = 0u; f < findings.size(); ++f) {
						for (qpl::size i = 0u; i < N; ++i) {
							row[i] = findings_inv[f][i];
						}
						print();
					}
					qpl::system_pause();
				}
			}
		}

		if (qpl::get_time_signal(2.0)) {

			//auto sorted = byte_counts;
			//qpl::sort(sorted, [](auto a, auto b) {
			//	return a.first > b.first;
			//});
			//
			//for (qpl::size i = 0u; i < 4; ++i) {
			//	auto percentage = (sorted[i].first / (total_founds / 256.0));
			//	qpl::println(sorted[i].first, " - ", sorted[i].second, " : ", qpl::percentage_string(percentage));
			//}
			//
			//std::array<qpl::size, 16> search;
			//for (qpl::size i = 0u; i < 16; ++i) {
			//	search[i] = sorted[i].second;
			//}
			//qpl::println(search);
			//
			//auto rate = findings.size() / clock.elapsed_f();
			//qpl::println(qpl::big_number_string(findings.size()), " (", qpl::big_number_string(rate), " / sec)");
		}
	}
}
