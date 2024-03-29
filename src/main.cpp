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

    auto message = qpl::get_random_string_full_range_with_repetitions(l, 10000);

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

template<typename T, qpl::size N, qpl::size threads = 1u>
auto get_n_strong_primes(qpl::size bits, qpl::size sub_bits, qpl::size rounds = qpl::size_max) {
    std::atomic_size_t found_primes = 0;

    std::array<T, N> result;

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

                    if (found_primes.load() >= N) {
                        return;
                    }
                }
            }

            if (found_primes.load() >= N) {
                return;
            }

            result[found_primes] = prime;
            ++found_primes;

            if (found_primes.load() >= N) {
                return;
            }
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
    return result;
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

                qpl::println("is prime: ", is_prime(p1, 32u));
                qpl::println("is prime: ", is_prime(p2, 32u));

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

template<qpl::size bits>
void find_two_prime_pairs() {

    std::vector<mpz_class> primes;
    std::vector<qpl::RSA_key_pair> key_pairs;
    for (qpl::size i = 0u; i < 2u; ++i) {
        qpl::RSA rsa;
        bool found = false;
        while (!found) {
            qpl::println("searching for 4 new primes with ", bits, " bits");
            auto get = get_n_strong_primes<mpz_class, 4u, 12u>(bits, get_sub<bits>(), 6u);
            for (auto& i : get) {
                primes.push_back(i);
            }

            for (qpl::size f = 0u; primes.size() >= 4u && f < 10u; ++f) {
                qpl::size i1 = qpl::random(0ull, primes.size() - 1);
                qpl::size i2 = i1;
                while (i2 == i1) {
                    i2 = qpl::random(0ull, primes.size() - 1);
                }

                if (rsa.check(primes[i1], primes[i2])) {

                    if (!is_prime(primes[i1], 32u)) {
                        qpl::println(primes[i1]);
                        qpl::println("it's actually not a prime!");
                        qpl::system_pause();
                    }
                    if (!is_prime(primes[i2], 32u)) {
                        qpl::println(primes[i2]);
                        qpl::println("it's actually not a prime!");
                        qpl::system_pause();
                    }

                    qpl::remove_index(primes, qpl::max(i1, i2));
                    qpl::remove_index(primes, qpl::min(i1, i2));
                    found = true;
                    break;
                }
            }
        }

        qpl::println("RSA ", rsa.get_bits());
        auto public_key = rsa.get_public_key();
        auto private_key = rsa.get_private_key();

        key_pairs.push_back(public_key);
        key_pairs.push_back(private_key);
    }
    qpl::println("encryption & signature-");
    qpl::println((key_pairs[0].mod.get_str(16)));
    qpl::println((key_pairs[0].key.get_str(16)));
    qpl::println();
    qpl::println((key_pairs[3].mod.get_str(16)));
    qpl::println((key_pairs[3].key.get_str(16)));
    qpl::println();
    
    qpl::println("decryption & verify -");
    qpl::println((key_pairs[1].mod.get_str(16)));
    qpl::println((key_pairs[1].key.get_str(16)));
    qpl::println();
    qpl::println((key_pairs[2].mod.get_str(16)));
    qpl::println((key_pairs[2].key.get_str(16)));
    qpl::println();
}

void check_RSA_cipher() {

    qpl::RSASSA_PSS_OAEP_CIPHER<qpl::cipher_secure> encrypter;
    qpl::RSASSA_PSS_OAEP_CIPHER<qpl::cipher_secure> decrypter;
    encrypter.rsa.load_keys_from_file("secret/sign.txt");
    decrypter.rsa.load_keys_from_file("secret/verify.txt");

    while (true) {
        //auto message = qpl::get_random_string_full_range_with_repetions(qpl::random(1, 1000), 10);
        //auto message = qpl::get_random_lowercase_uppercase_number_string(qpl::random(1, 1000));
        auto message = qpl::get_random_string_full_range_with_repetitions(qpl::random(100'000, 10'000'000), 10);

        auto encrypted = encrypter.encrypt(message, "secret cipher key", "signature");

        if (!encrypted.has_value()) {
            qpl::println("couldn't encrypt the text");
        }
        auto decrypted = decrypter.decrypt(encrypted.value(), "signature");


        if (!decrypted.has_value()) {
            qpl::println("couldn't decrypt the text");
        }

        if (message == decrypted.value()) {
            qpl::println(qpl::aqua, "worked! - all ", message.length(), " bytes matched");
        }
        else {
            qpl::println(qpl::red, message.length(), " doesn't match!");
        }
    }
}

void check_RSA_verify() {

    qpl::RSASSA_PSS_OAEP sign;
    sign.load_keys_from_file("secret/sign.txt");


    qpl::println(sign.cipher_key.string());
    qpl::println(sign.signature_key.string());

    qpl::RSASSA_PSS_OAEP verify;
    verify.load_keys_from_file("secret/verify.txt");

    qpl::println(verify.cipher_key.string());
    qpl::println(verify.signature_key.string());

    while (true) {
        auto message = qpl::get_random_lowercase_uppercase_number_string(qpl::random(1'000, 10'000));
        auto result = sign.add_signature_and_encrypt(message, "signature", "123");
        auto back = verify.verify_and_decrypt(result.value(), "signature", "123");

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

    find_two_prime_pairs<1024 * 4>();

    //check_RSA_verify();
    //check_RSA_cipher();
}
catch (std::exception& any) {
    qpl::println("caught exception:\n", any.what());
    qpl::system_pause();
}