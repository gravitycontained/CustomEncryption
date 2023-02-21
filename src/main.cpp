#include <qpl/qpl.hpp>



namespace crypto {
	constexpr qpl::cipher_config config{
		.N = 4,
		.cipher_rounds = 3,
		.key_size = 64,
		.table_size = 64,
		.skip_rotation_chance = 0.0,
		.bidirectional = true,
		.initialization_vector = true
	};
	qpl::cipherN<config> cipher;
	qpl::cipherN<config> cipher2;
}

std::string encrypted(const std::string& message, const std::string& key) {
	return crypto::cipher.encrypted(message, key);
}
std::string aes_encrypted(const std::string& message, const std::string& key) {
	return qpl::encrypted_keep_size(message, key);
}

void check_encryption(std::string& message, std::string key) {
	auto before = message;
	qpl::begin_benchmark("encrypt");

	crypto::cipher.encrypt(message, key);


	//if (encrypted != message) {
	//	//qpl::println("message   : ", qpl::hex_string(before));
	//	qpl::println("encrypted : ", qpl::hex_string(encrypted));
	//	qpl::println("decrypted : ", qpl::hex_string(message));
	//	qpl::println();
	//}


	qpl::begin_benchmark_end_previous("decrypt");
	//auto decrypted = crypto::cipher.decrypted(encrypted, key);
	crypto::cipher.decrypt(message, key);
	qpl::end_benchmark();

	if (before != message) {
		qpl::println("message   : ", qpl::hex_string(before));
		//qpl::println("encrypted : ", qpl::hex_string(encrypted));
		qpl::println("decrypted : ", qpl::hex_string(message));
		qpl::println();
	}
}

void check_mistakes() {
	qpl::small_clock clock;

	qpl::size bytes = 0u;

	auto key = qpl::get_random_string_full_range(crypto::cipher.key_size);

	std::string message;
	for (qpl::size i = 0u;; ++i) {
		//auto l = 64 * 2;
		constexpr auto l = qpl::mebibyte(16);
		message = qpl::get_random_string_with_repetions(l, 64);

		check_encryption(message, key);
		//check_encryption2(message, key);
		bytes += message.length();

		if (qpl::get_time_signal(0.5)) {
			auto byte_rate = qpl::size_cast(qpl::f64_cast(bytes) / clock.elapsed_f());
			qpl::println(qpl::memory_size_string(bytes), " (", qpl::memory_size_string(byte_rate), " / sec)");
			qpl::print_benchmark();
		}
	}

}

template<qpl::size N, qpl::size M>
void make_tables() {
	auto print = [](std::array<qpl::u8, N> state) {
		std::ostringstream stream;
		stream << qpl::to_string("std::array<qpl::u8, ", N, "> { ");
		for (qpl::size i = 0u; i < state.size(); ++i) {
			if (i) {
				stream << ", ";
			}
			stream << qpl::to_string(qpl::hex_string(state[i], "0x", qpl::base_format::base36l, true), 'u');
		}
		stream << qpl::to_string(" },\n");
		return stream.str();
	};

	std::set<std::array<qpl::u8, N>> seen;

	std::string string;
	std::string inv_string;
	for (qpl::size generated = 0u; generated < M; ) {

		std::array<qpl::u8, N> state;
		std::array<qpl::u8, N> inverse;
		std::iota(state.begin(), state.end(), 0u);

		while (true) {
			qpl::shuffle(state);
			bool valid = true;
			for (qpl::size i = 0u; i < state.size(); ++i) {
				if (state[i] == i) {
					valid = false;
					break;
				}
			}
			if (valid) {
				break;
			}
		}

		if (seen.find(state) != seen.cend()) {
			qpl::println("already seen ", state);
			continue;
		}
		seen.insert(state);

		for (qpl::size i = 0u; i < state.size(); ++i) {
			inverse[state[i]] = i;
		}

		string += print(state);
		inv_string += print(inverse);

		for (qpl::size i = 0u; i < state.size(); ++i) {
			auto n = state[i];
			auto reverse = inverse[n];

			if (reverse != i) {
				qpl::println("invalid table");
			}
		}
		++generated;
	}

	qpl::println(string);
	qpl::println();
	qpl::println();
	qpl::println(inv_string);
}

void create_output() {
	//auto key = "21q1aN4TrJU5XOPF4YE532H10FD03I8F";
	auto key = qpl::get_random_string_full_range(64);
	constexpr auto l = qpl::gebibyte(1);

	auto message = qpl::get_random_string_full_range_with_repetions(l, 10000);

	qpl::small_clock clock;
	auto encrypted = ::encrypted(message, key);
	auto rate = encrypted.length() / clock.elapsed_f();

	qpl::write_data_file(encrypted, "binary.dat");
	qpl::println(qpl::memory_size_string(qpl::size_cast(rate)), " / sec (", qpl::size_cast(rate), " bytes)");
}

int main() try {

	std::string string = "hello world 123125678 hello world 123125678 hello world 123125678";
	check_encryption(string, "123456");

	check_mistakes();
}
catch (std::exception& any) {
	qpl::println("caught exception:\n", any.what());
	qpl::system_pause();
}