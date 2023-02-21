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


qpl::size get_random_prime(qpl::size min, qpl::size max) {
    while (true) {
        auto number = qpl::random(min / 6, max / 6) * 6u + 1;
        if (qpl::is_prime(number)) {
            return number;
        }
    }
}

template<typename T>
constexpr T mod_pow(T base, T exp, T mod) {
    using long_u = qpl::ubit<qpl::bits_in_type<T>() * 2>;
    T result = 1;
    T power = base % mod;

    for (qpl::size i = 0; i < qpl::bits_in_type<T>(); ++i) {
        T least_sig_bit = T{ 0x1 } &(exp >> i);
        if (least_sig_bit) {
            result = (long_u{ result } *power) % mod;
        }
        power = (long_u{ power } *power) % mod;
    }

    return result;
}

template<typename T>
constexpr T mod_inverse(T a, T m) {
    T m0 = m;
    T y = 0;
    T x = 1;

    if (m == 1)
        return T{ 0u };

    while (a > 1) {
        T q = static_cast<T>(a / m);
        T t = m;

        m = static_cast<T>(a % m);
        a = t;
        t = y;

        y = static_cast<T>(x - q * y);
        x = t;
    }
    if (x < 0) {
        x += m0;
    }
    return x;
}

template<typename T>
constexpr qpl::size count_trailing_zeroes(T n) {
    qpl::size bits = 0;
    auto x = n;

    if (x) {
        while ((x & 1) == 0) {
            ++bits;
            x >>= 1;
        }
    }
    return bits;
}

template<typename T>
constexpr T gcd(T a, T b) {
    if constexpr (qpl::bits_in_type<T>() <= 64) {
        return std::gcd(a, b);
    }
    else {
        if (a == 0) {
            return b;
        }
        if (b == 0) {
            return a;
        }
        auto shift = count_trailing_zeroes(a | b);
        a >>= count_trailing_zeroes(a);
        do {
            b >>= count_trailing_zeroes(b);
            if (a > b) {
                std::swap(a, b);
            }
            b -= a;
        } while (b != 0);
        return a << shift;
    }
}

template<typename T>
constexpr T lcm(T a, T b) {
    if constexpr (qpl::bits_in_type<T>() <= 64) {
        return std::lcm(a, b);
    }
    else {
        return (a / gcd(a, b)) * b;
    }
}

template<typename T>
constexpr T mulmod(T a, T b, T mod) {
    qpl::ubit<qpl::bits_in_type<T>() * 2> long_a = a;
    auto result = (long_a * b) % mod;
    return static_cast<T>(result);
}

template<typename T>
bool miller_rabin_primality_test(T n, qpl::size rounds = qpl::bits_in_type<T>() / 2) {
    if (n < 2) {
        return false;
    }
    if (n != 2 && n & 0x1 == 0) {
        return false;
    }
    auto ctz = count_trailing_zeroes(n - 1);
    T d = (n - 1) / (T{ 1 } << ctz);

    //qpl::println("checking ", n);
    //qpl::println("ctz = ", ctz);
    //qpl::println("d = ", d);

    for (qpl::size i = 0; i < rounds; ++i) {
        T a;
        if constexpr (qpl::bits_in_type<T>() <= 64u) {
            a = qpl::random(T{ 2 }, n - 2);
        }
        else {
            a = T::random(T{ 2 }, n - 2);
        }
        //qpl::println("a = ", a);
        //qpl::println("d = ", d);
        //qpl::println("n = ", n);
        T x = mod_pow(a, d, n);
        //qpl::println("x = ", x);
        //qpl::println();

        if (x == 1 || x == (n - 1))
            continue;

        for (size_t r = 0; r < (ctz - 1); ++r) {
            x = mod_pow(x, T{ 2 }, n);
            if (x == 1) {
                return false;
            }
            if (x == n - 1) {
                break;
            }
        }

        if (x != (n - 1)) {
            return false;
        }
    }
    return true;
}

template<qpl::size prime_stop = 50000ull>
struct RSA {

    constexpr static qpl::size prime_square = prime_stop * prime_stop;
    constexpr static qpl::size prime_square_bits = qpl::significant_bit(prime_square) + 1;
    constexpr static qpl::size mod_pow_bits = qpl::significant_bit(prime_square) * 2 + 1;

    using utype = qpl::ubit<(((prime_square_bits - 1) / 32) + 1) * 32>;
    using itype = qpl::ibit<(((prime_square_bits - 1) / 32) + 1) * 32>;
    using umod_type = qpl::ubit<(((mod_pow_bits - 1) / 32) + 1) * 32>;

    utype prime1;
    utype prime2;
    utype mod;
    utype lambda;
    utype private_key;
    utype public_key;
    utype coprime;

    void print() {
        qpl::println("     prime1 = ", this->prime1);
        qpl::println("     prime2 = ", this->prime2);
        qpl::println("        mod = ", this->mod);
        qpl::println("     lambda = ", this->lambda);
        qpl::println(" public key = ", this->public_key);
        qpl::println("private key = ", this->private_key);
    }

    auto random_prime() const {
        return get_random_prime(prime_stop / 2, prime_stop);
    }

    void randomize() {
        this->prime1 = this->random_prime();

        this->prime2 = this->prime1;
        while (true) {
            this->prime2 = this->random_prime();

            auto p1 = this->prime1 - 1;
            auto p2 = this->prime2 - 1;
            this->lambda = lcm(p1, p2);

            if (this->lambda == p1 || this->lambda == p2) {
                this->prime1 = this->random_prime();
                continue;
            }
            if (this->prime1 != this->prime2) {
                break;
            }
        }
    }

    void create_keys() {
        this->mod = this->prime1 * this->prime2;
        for (this->coprime = 3u; this->coprime < this->lambda; ++this->coprime) {
            if (gcd(this->coprime, this->lambda) == 1) {

                this->private_key = mod_inverse(static_cast<itype>(this->coprime), static_cast<itype>(this->lambda));
                if (this->private_key != this->coprime) {
                    this->public_key = this->coprime;
                    break;
                }
            }
        }
    }

    auto encrypt(utype message) const {
        return mod_pow<umod_type>(message, this->public_key, this->mod);
    }
    auto decrypt(utype message) const {
        return mod_pow<umod_type>(message, this->private_key, this->mod);
    }
};


void find_primes() {
    qpl::clock clock;
    qpl::size primes = 0u;

    using type = qpl::integer<32 * 32, false>;

    std::vector<std::thread> threads;
    std::atomic_bool writing = true;

    auto find = [&](qpl::size thread) {
        for (qpl::size i = 0u;; ++i) {
            type n;
            n.randomize();

            n = n / 6;
            n = n * 6 + 1;
            auto check = miller_rabin_primality_test(n, 64);

            if (check) {
                ++primes;

                while (!writing.load()) {}

                writing = false;
                qpl::println("thread #", qpl::str_spaced(thread, 2), " found a random ", qpl::bits_in_type<type>(), " bit prime! ", n.hex_string());
                writing = true;
            }

            if (thread == 0u && qpl::get_time_signal(180.0)) {
                auto rate = primes / qpl::f64_cast(i);

                while (!writing.load()) {}
                writing = false;
                qpl::println();
                qpl::println("finding ", qpl::big_number_string(primes / clock.elapsed_f()), " primes / sec.");
                qpl::println();
                writing = true;
            }
        }
    };

    for (qpl::size i = 0u; i < 12u; ++i) {
        threads.emplace_back(find, i);
    }
    for (auto& i : threads) {
        i.join();
    }
}

void check_RSA() {
    constexpr auto prime = 5000'000ull;
    RSA<prime> rsa;
    RSA<prime>::utype;
    RSA<prime>::umod_type;
    RSA<prime>::itype;
    RSA<prime>::prime_square;
    RSA<prime>::prime_square_bits;


    qpl::size gen = 0u;

    qpl::size success = 0u;
    qpl::clock clock;
    while (true) {

        //rsa.prime1 = 61;
        //rsa.prime2 = 53;

        //auto message = 65ull;
        rsa.randomize();
        rsa.create_keys();

        auto message = qpl::random(0ull, rsa.mod);
        auto encrypted = rsa.encrypt(message);
        auto decrypted = rsa.decrypt(encrypted);

        if (decrypted != message) {
            rsa.print();
            qpl::println("  message = ", qpl::light_red, message);
            qpl::println("encrypted = ", encrypted);
            qpl::println("decrypted = ", qpl::light_red, decrypted);
            qpl::println("\n");
        }
        else {
            ++success;
        }

        ++gen;
        if (qpl::get_time_signal(0.5)) {
            auto rate = qpl::f64_cast(success) / gen;
            qpl::println(qpl::green, "successes = ", qpl::big_number_string(success));
            qpl::println(qpl::light_red, "    fails = ", qpl::big_number_string(gen - success));
            qpl::println(qpl::big_number_string(qpl::f64_cast(gen) / clock.elapsed_f()), " / sec");
            qpl::println();
        }
    }
}

int main() try {
    find_primes();

	std::string string = "hello world 123125678 hello world 123125678 hello world 123125678";
	check_encryption(string, "123456");

	check_mistakes();
}
catch (std::exception& any) {
	qpl::println("caught exception:\n", any.what());
	qpl::system_pause();
}