#include <qpl/qpl.hpp>

qpl::size get_flipped_bits(const std::string& a, const std::string& b) {
	qpl::size result = 0u;
	for (qpl::size i = 0u; i < a.length(); ++i) {
		result += qpl::number_of_set_bits(qpl::u8_cast(a[i]) ^ qpl::u8_cast(b[i]));
	}
	return result;
}

qpl::f64 get_bits_avalance(const std::string& a, const std::string& b) {
	auto flipped = get_flipped_bits(a, b);
	auto total_bits = a.length() * qpl::bits_in_type<qpl::char_type>();

	auto rate = flipped / qpl::f64_cast(total_bits);
	return rate;
}

namespace crypto {
	constexpr qpl::cipher_config config{
		.N = 4,
		.cipher_rounds = 1,
		.key_size = 64,
		.table_size = 64,
	};
	qpl::cipherN<config> cipher;
}
namespace crypto2 {
	constexpr qpl::cipher_config config{
		.N = 4,
		.cipher_rounds = 1,
		.key_size = 64,
		.table_size = 64,
	};
	qpl::cipherN<config> cipher;
}

std::string encrypted(const std::string& message, const std::string& key) {
	return crypto::cipher.encrypt(message, key);
}
std::string aes_encrypted(const std::string& message, const std::string& key) {
	return qpl::encrypted_keep_size(message, key);
}

struct avalanche {
	void update(std::string message, std::string key, bool use_aes) {
		qpl::f64 sum_a = 0.0;

		auto encrypt = use_aes ? aes_encrypted : encrypted;

		auto encrypted = encrypt(message, key);
		this->encrypted_sum += get_bits_avalance(message, encrypted);

		{
			auto key1 = key;
			qpl::toggle_bit(key1[0], qpl::bits_in_type<qpl::char_type>() - 1);
		
			auto key1_encrypted = encrypt(message, key1);
			this->key1_sum += get_bits_avalance(key1_encrypted, encrypted);
		}
		
		{
			auto key2 = key;
			qpl::toggle_bit(key2[key.length() / 2], qpl::bits_in_type<qpl::char_type>() / 2);
		
			auto key2_encrypted = encrypt(message, key2);
			this->key2_sum += get_bits_avalance(key2_encrypted, encrypted);
		}
		
		{
			auto key3 = key;
			qpl::toggle_bit(key3[key.length() - 1], 0u);
		
			auto key3_encrypted = encrypt(message, key3);
			this->key3_sum += get_bits_avalance(key3_encrypted, encrypted);
		}

		{
			auto msg1 = message;
			qpl::toggle_bit(msg1[0], qpl::bits_in_type<qpl::char_type>() - 1);

			auto msg1_encrypted = encrypt(msg1, key);
			this->msg1_sum += get_bits_avalance(msg1_encrypted, encrypted);
		}
		{
			auto msg2 = message; 
			qpl::toggle_bit(msg2[msg2.length() / 2], qpl::bits_in_type<qpl::char_type>() / 2);

			auto msg2_encrypted = encrypt(msg2, key);
			this->msg2_sum += get_bits_avalance(msg2_encrypted, encrypted);
		}
		{
			auto msg3 = message;
			qpl::toggle_bit(msg3[msg3.length() - 1], 0u);

			auto msg3_encrypted = encrypt(msg3, key);
			this->msg3_sum += get_bits_avalance(msg3_encrypted, encrypted);
		}

		++this->ctr;
	}

	void print(bool use_aes) {
		qpl::println(use_aes ? "AES " : "MY  ", "msg vs encrypted : ", qpl::percentage_string_precision(this->encrypted_sum / this->ctr, 2));
		qpl::println(use_aes ? "AES " : "MY  ", "key[<] flipped   : ", qpl::percentage_string_precision(this->key1_sum / this->ctr, 2));
		qpl::println(use_aes ? "AES " : "MY  ", "key[m] flipped   : ", qpl::percentage_string_precision(this->key2_sum / this->ctr, 2));
		qpl::println(use_aes ? "AES " : "MY  ", "key[>] flipped   : ", qpl::percentage_string_precision(this->key3_sum / this->ctr, 2));
		qpl::println(use_aes ? "AES " : "MY  ", "msg[<] flipped   : ", qpl::percentage_string_precision(this->msg1_sum / this->ctr, 2));
		qpl::println(use_aes ? "AES " : "MY  ", "msg[m] flipped   : ", qpl::percentage_string_precision(this->msg2_sum / this->ctr, 2));
		qpl::println(use_aes ? "AES " : "MY  ", "msg[>] flipped   : ", qpl::percentage_string_precision(this->msg3_sum / this->ctr, 2));
		qpl::println();
	}

	qpl::f64 encrypted_sum = 0.0;
	qpl::f64 key1_sum = 0.0;
	qpl::f64 key2_sum = 0.0;
	qpl::f64 key3_sum = 0.0;
	qpl::f64 msg1_sum = 0.0;
	qpl::f64 msg2_sum = 0.0;
	qpl::f64 msg3_sum = 0.0;
	qpl::size ctr = 0u;
};

namespace aval {
	avalanche mine;
	//avalanche aes;
}

void check_avalanche(const std::string& message, const std::string& key) {
	aval::mine.update(message, key, false);
	//aval::aes.update(message, key, true);
}


void check_encryption(std::string message, std::string key) {
	qpl::begin_benchmark("encrypt");
	auto encrypted = crypto::cipher.encrypt(message, key);
	qpl::begin_benchmark_end_previous("decrypt");
	auto decrypted = crypto2::cipher.decrypt(encrypted, key);
	qpl::end_benchmark();

	if (decrypted != message) {
		qpl::println("message   : ", qpl::hex_string(message));
		qpl::println("encrypted : ", qpl::hex_string(encrypted));
		qpl::println("decrypted : ", qpl::hex_string(decrypted));
		qpl::println();
	}

	//qpl::begin_benchmark("AES");
	//encrypted = qpl::encrypted_keep_size(message, key);
	//decrypted = qpl::decrypted_keep_size(encrypted, key);
	//qpl::end_benchmark();
}

void check_mistakes() {
	qpl::small_clock clock;

	qpl::size bytes = 0u;

	auto key = qpl::get_random_string_full_range(crypto::cipher.key_size);
	//for (qpl::size i = 10; i < key.length(); ++i) {
	//	key[i] = 0u;
	//}

	for (qpl::size i = 0u;; ++i) {
		auto l = 64 * 2;
		auto message = qpl::get_random_string_with_repetions(l, 64);

		check_encryption(message, key);
		//check_avalanche(message, key);
		bytes += message.length();

		if (qpl::get_time_signal(0.5)) {
			auto byte_rate = qpl::size_cast(qpl::f64_cast(bytes) / clock.elapsed_f());
			qpl::println(qpl::memory_size_string(bytes), " (", qpl::memory_size_string(byte_rate), " / sec)");
			//aval::mine.print(false);
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
	//mds();
	//create_output();
	check_mistakes();
}
catch (std::exception& any) {
	qpl::println("caught exception:\n", any.what());
	qpl::system_pause();
}