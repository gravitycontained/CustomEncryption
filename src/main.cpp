#include <qpl/qpl.hpp>

std::mutex mu;

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

namespace maths {
    template<typename T>
    constexpr qpl::size count_trailing_zeroes(T n) {
        qpl::size bits = 0;
        if (n != 0) {
            while ((n & 1) == 0) {
                ++bits;
                n >>= 1;
            }
        }
        return bits;
    }

    template<typename T>
    constexpr qpl::size count_trailing_zeroes_and_reduce(T& n) {
        qpl::size bits = 0;
        if (n != 0) {
            while ((n & 1) == 0) {
                ++bits;
                n >>= 1;
            }
        }
        return bits;
    }

    template<typename T>
    constexpr T gcd(T a, T b) {
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

    template<typename T>
    constexpr T lcm(T a, T b) {
        return (a / gcd(a, b)) * b;
    }

    auto primes = qpl::generate_primes<qpl::u32, 1024>();
}

namespace random {
    gmp_randclass engine(gmp_randinit_default);

    void init() {
        std::string str = "";

        for (qpl::size i = 0u; i < 10u; ++i) {
            qpl::detail::rng.engine.engine.shuffle();
        }
        for (qpl::size i = 0u; i < 1024u; ++i) {
            str += qpl::hex_string(qpl::random(), "");
        }
        mpz_class seed;
        mpz_set_str(seed.get_mpz_t(), str.c_str(), 16);

        engine.seed(seed);
    }
}

template<typename T>
auto get_random_number(qpl::size bits) {
    T n;
    if constexpr (qpl::is_same<T, mpz_class>()) {
        n = random::engine.get_z_bits(qpl::u32_cast(bits));
    }
    else if constexpr (qpl::is_qpl_integer<T>()) {
        n.randomize_bits(bits);
    }
    return n;
}

template<typename T>
auto get_random_range(T start, T end) {
    T r;
    if constexpr (qpl::is_same<T, mpz_class>()) {
        r = random::engine.get_z_range(end - start) + start;
    }
    else if constexpr (qpl::is_qpl_integer<T>()) {
        r = T::random(start, end);
    }
    else if constexpr (qpl::bits_in_type<T>() <= 64u) {
        r = qpl::random(start, end);
    }
    return r;
}

template<typename T>
bool miller_rabin_primality_test(T n, qpl::size bits, qpl::size rounds = qpl::size_max) {
    if (rounds == qpl::size_max) {
        rounds = bits / 2;
    }
    if (n < T{ 2 }) {
        return false;
    }
    if (n != 2 && n % 2 == 0) {
        return false;
    }

    T d = (n - 1);
    auto ctz = maths::count_trailing_zeroes_and_reduce(d);


    for (qpl::size k = 0; k < rounds; ++k) {
        T a = get_random_range(T{ 2 }, T{ n - 2 });
        T x;
        mpz_powm(x.get_mpz_t(), a.get_mpz_t(), d.get_mpz_t(), n.get_mpz_t());

        if (x == 1 || x == (n - 1)) {
            continue;
        }

        if (ctz) {
            for (qpl::size i = 0u; i < (ctz - 1); ++i) {
                //x = maths::mod_mul(x, x, n);

                T mul = 2;
                mpz_powm(x.get_mpz_t(), x.get_mpz_t(), mul.get_mpz_t(), n.get_mpz_t());

                if (x == 1) {
                    return false;
                }
                if (x == T{ n - 1 }) {
                    break;
                }
            }
        }
        if (x != T{ n - 1 }) {
            return false;
        }
    }
    return true;
}

template<typename T>
bool is_prime(T n, qpl::size bits, qpl::size rounds = qpl::size_max) {
    //for (auto& i : maths::primes) {
    //    if (n % i == 0) {
    //        return false;
    //    }
    //}
    return miller_rabin_primality_test(n, bits, rounds);
}

template<typename T>
auto get_random_prime(qpl::size bits, qpl::size rounds = qpl::size_max) {
    if (rounds == qpl::size_max) {
        rounds = bits / 2;
    }

    T divide;
    divide = 6 * 5 * 7 * 11 * 13 * 17 * 19 * 23u;
    //divide = 6 * 5u;
    //divide = 2u;
    T n;
    while (true) {
        //constexpr auto divide = T{ 6 };
        //divide = 6u;

        n = get_random_number<T>(bits);
        n = (n / divide) * divide + 1;

        if (n == 0) {
            continue;
        }

        if (n.get_str(2u).length() == bits) {
            auto check = is_prime(n, bits, rounds);
            if (check) {
                return n;
            }
        }
    }
    return T{};
}

template<typename T, qpl::size threads = 1u>
auto get_two_strong_primes(qpl::size bits, qpl::size sub_bits, qpl::size rounds = qpl::size_max) {
    std::atomic_size_t found_primes = 0;

    T result1;
    T result2;

    auto find = [&](qpl::size thread_index) {
        while (true) {
            if (rounds == qpl::size_max) {
                rounds = bits / 2;
            }
            T prime = get_random_prime<T>(bits - sub_bits, rounds);
            T search;
            T k;

            for (qpl::size j = 0u; j < 2u; ++j) {
                k = 64u;

                for (qpl::size i = 0u;; ++i) {
                    search = T{ prime * k + 1 };
                    auto prime_check = is_prime(search, bits, rounds);
                    if (prime_check) {
                        prime = search;
                        break;
                    }
                    k += 2;

                    if (found_primes.load() >= 2u) {
                        return;
                    }
                }
            }

            if (found_primes.load() >= 2u) {
                return;
            }

            ++found_primes;
            if (found_primes.load() == 1u) {
                result1 = prime;
            }
            else {
                result2 = prime;
            }
            //qpl::println("found a prime ");
            //qpl::println("\"", prime.get_str(16), "\",");
        }
    };


    std::vector<std::thread> threads_collection;
    for (qpl::size i = 0u; i < threads; ++i) {
        threads_collection.emplace_back(find, i);
    }
    for (auto& i : threads_collection) {
        i.join();
    }

    //qpl::println("closed all threads, found ", found_primes.load(), " primes");
    return std::pair(result1, result2);
}

template<typename T, qpl::size threads = 1u>
auto get_strong_prime(qpl::size bits, qpl::size sub_bits, qpl::size rounds = qpl::size_max) {
    if (rounds == qpl::size_max) {
        rounds = bits / 2;
    }
    T prime = get_random_prime<T>(bits - sub_bits, rounds);
    T search;
    T k;

    for (qpl::size j = 0u; j < 2u; ++j) {
        k = 64u;
        //k = 128u;

        for (qpl::size i = 0u;; ++i) {
            search = T{ prime * k + 1 };
            auto check_prime = is_prime(search, bits, rounds);
            if (check_prime) {

                mu.lock();
                qpl::println("found k", j + 1, ": ", k);
                mu.unlock();
                prime = search;
                break;
            }
            k += 2;
        }
    }

    return prime;
}

constexpr static auto RSA_subs = std::array{
    /* 0 */ 2u,
    /* 1 */ 2u,
    /* 2 */ 4u,
    /* 3 */ 6u,
    /* 4 */ 8u,
    /* 5 */ 9u,
    /* 6 */ 10u,
    /* 7 */ 11u,
    /* 8 */ 12u,
    /* 9 */ 13u,
    /*10 */ 16u,
    /*11 */ 17u,
    /*12 */ 20u,
    /*13 */ 24u,
    /*14 */ 24u,
};
template<qpl::size bits>
constexpr auto get_sub() {
    return RSA_subs[qpl::log2(bits)];
}

template<typename T, qpl::size bits>
void find_primes() {
    qpl::clock clock;

    std::vector<std::thread> threads;

    std::vector<T> primes;
    std::map<qpl::u32, qpl::size> factors;

    qpl::size print_ctr = 0u;

    auto find = [&](qpl::size thread) {
        for (qpl::size i = 0u;; ++i) {

            //auto prime1 = get_strong_prime<qpl::integer<bits, false>>(bits, 64);

            auto rounds = 1u;

            auto prime = get_strong_prime<T>(bits, get_sub<bits>(), rounds);


            //auto prime = get_strong_prime<T>(bits, 8u, rounds);

            //auto prime = std::get<0u>(result);
            //auto i1 = std::get<1u>(result);
            //auto i2 = std::get<2u>(result);

            std::lock_guard lock{ mu };

            if (prime != 0) {
                qpl::println("thread #", qpl::str_spaced(thread, 2), " found a prime with ", prime.get_str(2u).length(), " bits");
                primes.push_back(prime);

                ++print_ctr;

                if (print_ctr % 1u == 0u) {
                    auto rate = clock.elapsed_f() / primes.size();

                    qpl::size sum = 0u;

                    //qpl::size exact_primes = 0u;
                    for (auto& i : primes) {
                        auto str = i.get_str(2);
                        qpl::println(i.get_str(16));
                        sum += str.length();
                    }
                    //auto exact_rate = clock.elapsed_f() / exact_primes;
                    qpl::println("rate is 1 prime every ", qpl::secs(rate).small_descriptive_string(), ". (", primes.size(), " found so far)");
                    qpl::println("bits average is ", qpl::f64_cast(sum) / primes.size());
                    //qpl::println("exra is 1 prime every ", qpl::secs(exact_rate).small_descriptive_string(), ". (", exact_primes, " found so far)");
                }
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

void check_RSA_load() {
    qpl::size success = 0u;
    qpl::clock clock;

    //auto primes = qpl::string_split(qpl::filesys::read_file("secret/8192.txt"), '\n');
    //auto primes = qpl::string_split(qpl::filesys::read_file("secret/4096.txt"), '\n');
    auto primes = qpl::string_split(qpl::filesys::read_file("secret/2048.txt"), '\n');

    qpl::RSA rsa;

    while (true) {
        qpl::size i1 = qpl::random(0ull, primes.size() - 1);
        qpl::size i2 = i1;
        while (i2 == i1) {
            i2 = qpl::random(0ull, primes.size() - 1);
        }

        if (rsa.check(primes[i1], primes[i2])) {
            mpz_class p1;
            p1.set_str(primes[i1], 16);
            mpz_class p2;
            p2.set_str(primes[i2], 16);

            qpl::println("is prime: ", is_prime(p1, 4u));
            qpl::println("is prime: ", is_prime(p2, 4u));
            
            break;
        }
    }

    qpl::println("RSA ", rsa.get_bits());
    auto public_key = rsa.get_public_key();
    auto private_key = rsa.get_private_key();

    qpl::println("public  = ", public_key.string());
    qpl::println("private = ", private_key.string());

    while (true) {
        auto sign = qpl::RSASSA_PSS_sign("test", private_key);
        if (qpl::RSASSA_PSS_verify(sign, "test", public_key)) {
            qpl::println(qpl::green, "verified!");
        }
        else {
            qpl::println(qpl::red, "not verified!");
        }
    }

    while (true) {
        //auto message = qpl::get_random_string_full_range(rsa.get_max_message_length(qpl::sha512_object));
        //auto e = rsa.encrypt_hex_OAEP(message, qpl::sha512_object).value();
        //auto d = rsa.decrypt_hex_OAEP(e, qpl::sha512_object).value();
        auto message = qpl::get_random_string_full_range(qpl::random(1, 10000));

        auto e = qpl::RSA_encrypt(message, private_key);
        //auto e = rsa.encrypt(message);
        if (!e.has_value()) {
            qpl::println(qpl::light_red, " encryption failed!");
            qpl::system_pause();
        }
        auto d = qpl::RSA_decrypt(e.value(), public_key);
        if (!d.has_value()) {
            qpl::println(qpl::light_red, " decryption failed!");
            qpl::system_pause();
        }

        if (d.value() != message) {
            qpl::println("message = ", qpl::hex_string(message));
            qpl::println("e = ", e.value());
            qpl::println("d = ", qpl::hex_string(d.value()));
            qpl::println(qpl::red, "wtf");
        }
        else {
            qpl::println("ok");
        }

    }

    qpl::system_pause();

    for (qpl::size gen = 0u;;) {

        auto message = get_random_number<mpz_class>(rsa.get_bits() - 1);
        auto encrypted = rsa.encrypt_integer(message);
        auto decrypted = rsa.decrypt_integer(encrypted);

        if (decrypted != message) {
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

template<qpl::size bits>
void find_prime_pair() {
    while (true) {
        auto primes = qpl::string_split(qpl::filesys::read_file(qpl::to_string("secret/", bits, ".txt")), '\n');
        qpl::RSA rsa;

        while (true) {
            qpl::size i1 = qpl::random(0ull, primes.size() - 1);
            qpl::size i2 = i1;
            while (i2 == i1) {
                i2 = qpl::random(0ull, primes.size() - 1);
            }

            if (rsa.check(primes[i1], primes[i2])) {
                mpz_class p1;
                p1.set_str(primes[i1], 16);
                mpz_class p2;
                p2.set_str(primes[i2], 16);

                qpl::println("is prime: ", is_prime(p1, 4u));
                qpl::println("is prime: ", is_prime(p2, 4u));

                qpl::println("p1 = ", p1, " (length = ", p1.get_str(10).length(), ")");
                qpl::println("p2 = ", p2, " (length = ", p2.get_str(10).length(), ")");

                break;
            }
        }

        qpl::println("RSA ", rsa.get_bits());
        auto public_key = rsa.get_public_key();
        auto private_key = rsa.get_private_key();

        qpl::println("public  = ", public_key.string());
        qpl::println("private = ", private_key.string());
    }
}

void check_RSA_verify() {

    qpl::RSA_verifier sign;
    sign.cipher_key.create(
        "9701a5c1a68b3f8d6b34d41dca39c5e0ce131c93e474286e1c3f71858b5edafb636f5b19e6965763278d2130a1e569b02eeb7059fd75817d40f90ee19d6bca9764d944070a5749f990973f430f648059c237cb15d6865194b21652291b9d47433224fd63cb2befb0dd52efaa378c5fa94f14d437e3c19501c9b39615bb08931820960c5c38ebc0342056ae3ba2357ea904b6bf63b25c62b39f7552ff0a4089791fec768206fb8e80936495a905002589cfd93e9f779d00968002df368abe5097ef9ee0be118881d345105f26e333231ac0b41a0f2fdf735e7b7d305ac4b16ee29e1a0482cb1b0fe41dd539aac06933bab5ffcd602964e3c6ec118583467b860095e38efa48e2cf2bc4d00b4af7d8451e188dcd1fa642e81b72d0640dc966c1c36db32bca1fb530076756d3c6fc0dcf7b7a6e3a993d88ad874d84ed2cb162c3827bd2283827b5440754686b318d10ffa7e10987f98f8c285ef59d465a5f7b980a22723d92a4e35859648c7a7f5be91ca51bf0fb5a472ed420f9663a5aa2813f14be4855d126d7784d7dd017b2cdd38ce1ef956d31982b7adf5954b7da48287b826e3e87b1dd0a26df1d08b0b567c36062bc9d234cc0c6e818c88884fd3009a9f1c39c6e57708ff3f62e5e7695dd9b4965884fd15380d9f5e53edb4deca658abd717a78ab48180437c12e3d14a0c1aafc70f0cdfe68bdce6c75e12f876cf347367cf",
        "8003"
    );
    sign.signature_key.create(
        "de4077fafaaa8c2da7f0729edc021fdae93ed9e4fcca1ceb954a6bf1489f34d48669f87a2e27b17662824c46254383921c76cda47726c5433505de0608a52b1487d23aa266d306843bf6c7239a60fa670bc8e7f1246035c52c710590c5f75d35ebfc3ebede4d71368962c409b382e8676b27ac5ae6832a3f189d080576e534548f7cdcae11c740793cb721524f828d4b29b15d9e2cc5cf9e5c69954d384248939f819112b33dcf3803ab2d99d6a237c47645eeeb8ccf312ddad844b5cdbbce50bc0a4e9854dd53b6f1ee1867a5d8d14f857f6d0d8a912fb6b617c5507570cf291e56233c90493ba2c9c11f33d369505de38abf1d5c68cfc9bf73811ca90bde4585506c0d56fa25b4681f95b084931e2852a2616bc54193526b3c540f3a6d67ec4b69a1f8aea5b084c1e81fadfc8226a21487159b171f5cb21f2c9f8d39520b43d68fc9b61caa254b8cb215767ffa2ce01bd817679440650343cc38383e8a6e8f979f4fa2ca840525a30a16195752325af679671c39f44c7181f1d4d73ef5f76ad1cbda5c50240754a3c65644824c39d980868012fc629c6a15fa9dd51c68a37f995bfc9159472b9c20e6ae54a499981ccf22d76cdd902eee517118f169bbfe4bd217896aa2e679830c82c99fd37ca971ba35b7564323dd287ccd4acfb29bd0398d91d14230df400c46da317f26e0351d905c6a2437ab4e81e29d7fd1929037dd",
        "8001"
    );

    qpl::RSA_verifier verifier;
    verifier.cipher_key.create(
        "9701a5c1a68b3f8d6b34d41dca39c5e0ce131c93e474286e1c3f71858b5edafb636f5b19e6965763278d2130a1e569b02eeb7059fd75817d40f90ee19d6bca9764d944070a5749f990973f430f648059c237cb15d6865194b21652291b9d47433224fd63cb2befb0dd52efaa378c5fa94f14d437e3c19501c9b39615bb08931820960c5c38ebc0342056ae3ba2357ea904b6bf63b25c62b39f7552ff0a4089791fec768206fb8e80936495a905002589cfd93e9f779d00968002df368abe5097ef9ee0be118881d345105f26e333231ac0b41a0f2fdf735e7b7d305ac4b16ee29e1a0482cb1b0fe41dd539aac06933bab5ffcd602964e3c6ec118583467b860095e38efa48e2cf2bc4d00b4af7d8451e188dcd1fa642e81b72d0640dc966c1c36db32bca1fb530076756d3c6fc0dcf7b7a6e3a993d88ad874d84ed2cb162c3827bd2283827b5440754686b318d10ffa7e10987f98f8c285ef59d465a5f7b980a22723d92a4e35859648c7a7f5be91ca51bf0fb5a472ed420f9663a5aa2813f14be4855d126d7784d7dd017b2cdd38ce1ef956d31982b7adf5954b7da48287b826e3e87b1dd0a26df1d08b0b567c36062bc9d234cc0c6e818c88884fd3009a9f1c39c6e57708ff3f62e5e7695dd9b4965884fd15380d9f5e53edb4deca658abd717a78ab48180437c12e3d14a0c1aafc70f0cdfe68bdce6c75e12f876cf347367cf",
        "fa1e4ded44616fad9454b8a244feb5607319d5ebb81859a6cbc2116fde8e994674bfe9591f70ad7d9ec27f3ba3c83eb0f0933d58a156adc778c3bba035131fd4a9822d32da6019b95cbb5dd6d2a67af5cd85bab67c64f525a15e514350ba537dca4da82b2dba655d896df98d0d55a7347a5492ce63e083a13066e963e6ca7b6a42fcfbeb9c8459f83d0027fcb8766a595c46cec03d22ba6f4cb87c78ae17732c81669aa723c63d186d953ca9dedd54fe9ae52bed00857fa84f7ae4feeb3a5e027a4f404d571b24eb2a147223ade4d1f994fcd87db54ad54ab2aedfd01c917f55480548f932ba53a4d9cdea02ed48b48c3dd1993a83329c60092b8f3469b68361fc5af53b8c76f1aac3249ab8d3ec1567b7736de27bb64935c9f26dcf2c890c47c7614c24551665e0e433e6975cbeff6149fb2e4bec858176e50968c4a4cf6507c0b3fc54a2f662728927aa3fcb2ff56e1664c05cc37152ac1cbadaade0a5531d246f674440caf5fec7a92df3756c0a2685225025503b70e772061003010b2993e24069bb40e556762207da46f724ba26a4016a6510c8fc9a7acdc284ad465cdfc2771137d7b6886c0bb9bd6a58e631b18ca70c3ba7356dcfd656b94645bb42ec47a26c9af263e10b4a9ab62341b71bc2de521bae66855542c3e3b87dfee9a6fc1de1cae6ca674c7ad53ec4da3840b1f6aa3fbb0d3fb1111812be35df55dfa9abf"
    );
    verifier.signature_key.create(
        "de4077fafaaa8c2da7f0729edc021fdae93ed9e4fcca1ceb954a6bf1489f34d48669f87a2e27b17662824c46254383921c76cda47726c5433505de0608a52b1487d23aa266d306843bf6c7239a60fa670bc8e7f1246035c52c710590c5f75d35ebfc3ebede4d71368962c409b382e8676b27ac5ae6832a3f189d080576e534548f7cdcae11c740793cb721524f828d4b29b15d9e2cc5cf9e5c69954d384248939f819112b33dcf3803ab2d99d6a237c47645eeeb8ccf312ddad844b5cdbbce50bc0a4e9854dd53b6f1ee1867a5d8d14f857f6d0d8a912fb6b617c5507570cf291e56233c90493ba2c9c11f33d369505de38abf1d5c68cfc9bf73811ca90bde4585506c0d56fa25b4681f95b084931e2852a2616bc54193526b3c540f3a6d67ec4b69a1f8aea5b084c1e81fadfc8226a21487159b171f5cb21f2c9f8d39520b43d68fc9b61caa254b8cb215767ffa2ce01bd817679440650343cc38383e8a6e8f979f4fa2ca840525a30a16195752325af679671c39f44c7181f1d4d73ef5f76ad1cbda5c50240754a3c65644824c39d980868012fc629c6a15fa9dd51c68a37f995bfc9159472b9c20e6ae54a499981ccf22d76cdd902eee517118f169bbfe4bd217896aa2e679830c82c99fd37ca971ba35b7564323dd287ccd4acfb29bd0398d91d14230df400c46da317f26e0351d905c6a2437ab4e81e29d7fd1929037dd",
        "1870b8104a864243d4cb3894651af598e0aaa712ef62bf2eadda866fc8d3e8607a531cabfe5162d2362ad5db9f0bd19563348e2e34b9fb0770fad637cf6dc30448f31d8a76e7d10cd29a7b2b44f896383e8c47e125f4c4a038a5b0884da49b97e1d6c69ce22a91d912a39635c0b128fa6584dedb75588be93e7b6fd5f22a4a4fa3f43c402ff6207bd4249f41d5b8b8e64d3625d64451ec341ad36ac35b641b40fd6d7dc029f3bd2d3794d8e7141b48996aaad5737e62202d41917b53638c1b150cb3acc348f690f2a16fa311c7ca6b57bf07c84787a8ee0464b78dc4c090b9b69b27d4aa54ad54533b376566a13777669463ae42f70e9c947f83cdb0327aa828e3611e77952b15eab09d10df9d5d6321200d786919cf12d79b987fa5a16d2ba1e6ddee013f22fb879937bdca79ad5da561d547e78ec47e2de03337621f54f194420f2f008d8db24360b8b5cfea8a342514ba9fe6b3360b6647eea438a31c475f037ce2d5dc5f5cf4b0dc976da90f0120eba9f76b4e4af95742bda7d2a0e2ab56a4de79af80e6f3c5827aa2bd466838147aac1275218b91f94ef73d6025ae283b02d58d3f552de8f7300e6ffb87024737b8c2eb69b13848d2374f4448cc462ac6d75a10df703db821497a1c5f7becefab4143fd28bd1c2c9d118a84dbb4d988adedb798a5e8afaedcc074c89a170e6fceb2132b4d1e5487ee3099b9753945e3b1"
    );

    while (true) {
        auto message = qpl::get_random_lowercase_uppercase_number_string(qpl::random(1'000, 10'000));
        auto result = sign.sign_and_encrypt(message, "signature");
        auto back = verifier.verify_and_decrypt(result.value(), "signature");

        if (back.has_value() && back.value() == message) {
            qpl::println("worked! - all ", message.length(), " bytes matched & are verified");
        }
        else {
            qpl::println("didn't work!");
        }
    }
}

template<qpl::size bits>
void check_RSA() {
    qpl::RSA rsa;

    qpl::size success = 0u;

    auto get = get_two_strong_primes<mpz_class, 12u>(bits, get_sub<bits>(), 1u);
    while (!rsa.check(get.first, get.second)) {
        get = get_two_strong_primes<mpz_class, 12u>(bits, get_sub<bits>(), 1u);
    }
    rsa.create(get.first, get.second);

    qpl::clock clock;
    for (qpl::size gen = 0u;;) {

        //rsa.prime1 = 61;
        //rsa.prime2 = 53;

        //auto message = 65ull;


        auto message = get_random_number<mpz_class>(rsa.get_bits());
        auto encrypted = rsa.encrypt_integer(message);
        auto decrypted = rsa.decrypt_integer(encrypted);
        
        if (decrypted != message) {
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

void test_sha256() {
    std::string text = qpl::get_random_string(128);

    qpl::println("text = ", text);
    qpl::println("sha512   = ", qpl::sha512_hash(text));

    while (true) {
        qpl::print("input > ");
        auto input = qpl::get_input();
        qpl::println(qpl::mgf1(input, 16u, qpl::sha512_object));
    }
}

void test_RSA() {
    random::init();
    check_RSA_load();
}

int main() try {
    find_prime_pair<2048>();

    //find_primes<mpz_class, 2048u * 1u>();
    //test_sha256(); 
    //test_RSA();
    //check_RSA_verify();
}
catch (std::exception& any) {
    qpl::println("caught exception:\n", any.what());
    qpl::system_pause();
}