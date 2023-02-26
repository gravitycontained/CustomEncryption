#include <qpl/qpl.hpp>

#pragma warning (disable : 4146)
#include <gmpxx.h>
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

template<typename T>
using double_precision_type =
qpl::conditional<
    qpl::if_true<qpl::is_same<T, mpz_class>()>, mpz_class,
    qpl::if_true<qpl::is_qpl_integer<T>()>, qpl::integer<qpl::bits_in_type<T>() * 2, false>,
    qpl::if_true<qpl::is_qpl_x64_integer<T>()>, qpl::x64_integer<qpl::bits_in_type<T>() * 2, false>,
    qpl::if_true<qpl::is_integer<T>()>, qpl::ubit<qpl::bits_in_type<T>() * 2>,
    qpl::default_error>;

namespace maths {

    template<typename T>
    constexpr T mod_mul(T a, T b, T mod) {
        using long_u = double_precision_type<T>;
        T result = (long_u(a) * b) % mod;

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
    /*13 */ 22u,
    /*14 */ 24u,
};
template<qpl::size bits>
constexpr auto get_sub() {
    return RSA_subs[qpl::log2(bits)];
}

struct RSA {
    mpz_class mod;
    mpz_class private_key;
    mpz_class public_key;
    qpl::size bits = 0;

    void set_private_key(mpz_class key, mpz_class mod) {
        this->private_key = key;
        this->mod = mod;

        this->bits = this->mod.get_str(2).length();
    }
    void set_public_key(mpz_class key, mpz_class mod) {
        this->public_key = key;
        this->mod = mod;

        this->bits = this->mod.get_str(2).length();
    }
    qpl::size get_bits() const {
        return this->bits;
    }

    bool check(std::string prime1, std::string prime2) {
        mpz_class p1;
        p1.set_str(prime1, 16);
        mpz_class p2;
        p2.set_str(prime2, 16);
        return this->check(p1, p2);
    }
    void create(std::string prime1, std::string prime2) {
        mpz_class p1;
        p1.set_str(prime1, 16);
        mpz_class p2;
        p2.set_str(prime2, 16);
        this->create(p1, p2);
    }
    void create(mpz_class prime1, mpz_class prime2, mpz_class lambda = 0) {
        if (lambda == 0) {
            auto p1 = mpz_class{ prime1 - 1 };
            auto p2 = mpz_class{ prime2 - 1 };
            lambda = mpz_class{ lcm(p1, p2) };
        }

        this->mod = mpz_class{ prime1 * prime2 };
        this->bits = this->mod.get_str(2).length();

        mpz_class e = (1 << 15) + 1u;
        for (; e < lambda; ++e) {
            if (gcd(e, lambda) == 1) {

                this->private_key = maths::mod_inverse(e, lambda);
                if (this->private_key != e) {
                    this->public_key = e;
                    break;
                }
            }
        }
    }

    bool check(mpz_class prime1, mpz_class prime2) {

        auto p1 = mpz_class{ prime1 - 1 };
        auto p2 = mpz_class{ prime2 - 1 };
        auto lambda = mpz_class{ lcm(p1, p2) };

        if (lambda == p1 || lambda == p2) {
            return false;
        }
        if (prime1 == prime2) {
            return false;
        }
        auto mod = mpz_class{ prime1 * prime2 };
        if (mod.get_str(2u).length() % 8u) {
            return false;
        }

        this->create(prime1, prime2, lambda);
        return true;
    }

    auto encrypt_integer(mpz_class message) const {
        mpz_class result;
        mpz_powm(result.get_mpz_t(), message.get_mpz_t(), this->public_key.get_mpz_t(), this->mod.get_mpz_t());
        return result;
    }
    auto decrypt_integer(mpz_class message) const {
        mpz_class result;
        mpz_powm(result.get_mpz_t(), message.get_mpz_t(), this->private_key.get_mpz_t(), this->mod.get_mpz_t());
        return result;
    }

    void pad_string(std::string& string) const {
        auto diff = qpl::signed_cast(this->get_bits() / 4) - qpl::signed_cast(string.length());
        if (diff > 0) {
            string = qpl::to_string(qpl::to_string_repeat("0", diff), string);
        }
    }

    auto encrypt_single_hex(const std::string& message) const {
        mpz_class n;
        n.set_str(message, 16);
        auto str = this->encrypt_integer(n).get_str(16);
        this->pad_string(str);
        return str;
    }
    auto decrypt_single_hex(const std::string& message) const {
        mpz_class n;
        n.set_str(message, 16);
        auto str = this->decrypt_integer(n).get_str(16);
        this->pad_string(str);
        return str;
    }

    template<typename Hash>
    std::optional<std::string> encrypt_hex_OAEP(const std::string_view& message, Hash hash_object = qpl::sha512_object, std::string label = "") const {
        auto hash_size = hash_object.second / 8u;
        auto k = this->get_bits() / 4;
        auto lhash = hash_object.first(label);
        
        auto ps_length = qpl::signed_cast(k) - 2 * qpl::signed_cast(message.length()) - 4 * qpl::signed_cast(hash_size) - 4;

        if (ps_length < 0) {
            return std::nullopt;
        }
        std::string ps;
        ps.resize(ps_length, '0');

        auto seed = qpl::get_random_string_full_range(hash_size);

        std::string db;
        db.append(lhash);
        db.append(ps);
        db.append("01");
        db.append(qpl::hex_string(message));

        auto db_mask_size = k - 2 * hash_size - 2;
        auto db_mask = qpl::mgf1(seed, db_mask_size, hash_object);
        auto masked_db = qpl::hex_string_xor(db, db_mask);
        auto seed_mask = qpl::mgf1(qpl::from_hex_string(masked_db), hash_size * 2, hash_object);
        auto masked_seed = qpl::hex_string_xor(seed_mask, qpl::hex_string(seed));

        std::string em;
        em.append("00");
        em.append(masked_seed);
        em.append(masked_db);

        //qpl::println("E em = ", em);
        //qpl::println("E db = ", db);
        //qpl::println("E db = ", db.length());
        //qpl::println("E db_mask = ", db_mask.length());
        //qpl::println("E masked_db = ", masked_db.length());
        return this->encrypt_single_hex(em);
    }

    template<typename Hash>
    std::optional<std::string> decrypt_hex_OAEP(const std::string_view& message, Hash hash_object = qpl::sha512_object, std::string label = "") const {

        auto em = this->decrypt_single_hex(std::string{ message });
        auto hash_size = hash_object.second / 8u;
        auto k = this->get_bits() / 4;
        auto lhash = hash_object.first(label);
        auto db_mask_size = k - 2 * hash_size - 2;
        auto masked_seed = em.substr(2u, hash_size * 2);
        auto masked_db = em.substr(hash_size * 2 + 2u);
        auto seed_mask = qpl::mgf1(qpl::from_hex_string(masked_db), hash_size * 2, hash_object);
        auto seed = qpl::from_hex_string(qpl::hex_string_xor(seed_mask, masked_seed));
        auto db_mask = qpl::mgf1(seed, db_mask_size, hash_object);
        auto db = qpl::hex_string_xor(db_mask, masked_db);
        auto check_lhash = db.substr(0u, lhash.length());

        if (check_lhash != lhash) {
            return std::nullopt;
        }
        qpl::size ps_index = lhash.length();
        while (db[ps_index] == '0') {
            ++ps_index;
        }
        if (db[ps_index] != '1') {
            return std::nullopt;
        }

        return qpl::from_hex_string(db.substr(ps_index + 1u));
    }

    template<typename Hash>
    qpl::size get_max_message_length(Hash hash_object = qpl::sha512_object) const {
        auto hash_size = hash_object.second / 8u;
        auto k = this->get_bits() / 8;
        auto message_length = (k - hash_size * 2 - 2u);
        return message_length;
    }

    template<typename Hash>
    std::optional<std::string> encrypt(const std::string_view& message, Hash hash_object = qpl::sha512_object, std::string label = "") const {
        auto message_length = this->get_max_message_length(hash_object);
        auto message_blocks = qpl::signed_cast(message.length() - 1) / qpl::signed_cast(message_length) + 1;

        std::string result;
        result.reserve(message_blocks * message_length);

        for (qpl::isize i = 0; i < message_blocks; ++i) {
            auto sub = message.substr(i * message_length, message_length);
            auto e = this->encrypt_hex_OAEP(sub, hash_object, label);
            if (!e.has_value()) {
                return std::nullopt;
            }
            result.append(e.value());
        }
        return result;
    }

    template<typename Hash>
    std::optional<std::string> decrypt(const std::string_view& message, Hash hash_object = qpl::sha512_object, std::string label = "") const {
        auto block_length = this->get_bits() / 4;
        auto blocks = (message.length()) / block_length;

        if (message.length() % block_length) {
            qpl::println(qpl::yellow, "message.length() = ", message.length());
            return std::nullopt;
        }

        std::string result;
        result.reserve((block_length / 2) * blocks);

        for (qpl::size i = 0u; i < blocks; ++i) {
            auto sub = message.substr(i * block_length, block_length);
            auto d = this->decrypt_hex_OAEP(sub, hash_object, label);

            if (!d.has_value()) {
                return std::nullopt;
            }
            result.append(d.value());
        }
        return result;
    }

};

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
    auto primes = qpl::string_split(qpl::filesys::read_file("secret/4096.txt"), '\n');

    RSA rsa;

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

    while (true) {
        //auto message = qpl::get_random_string_full_range(rsa.get_max_message_length(qpl::sha512_object));
        //auto e = rsa.encrypt_hex_OAEP(message, qpl::sha512_object).value();
        //auto d = rsa.decrypt_hex_OAEP(e, qpl::sha512_object).value();
        auto message = qpl::get_random_string_full_range(qpl::random(1, 1000));


        auto e = rsa.encrypt(message, qpl::sha512_object);
        if (!e.has_value()) {
            qpl::println(qpl::light_red, " encryption failed!");
            qpl::system_pause();
        }

        auto d = rsa.decrypt(e.value(), qpl::sha512_object);
        if (!d.has_value()) {
            qpl::println(qpl::light_red, " decryption failed!");
            qpl::system_pause();
        }

        if (d.value() != message) {
            qpl::println("message = ", qpl::hex_string(message));
            //qpl::println("e = ", qpl::hex_string(e));
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
void check_RSA() {
    RSA rsa;

    qpl::size success = 0u;

    auto get = get_two_strong_primes<mpz_class, 12u>(bits, get_sub<bits>(), 1u);
    while (!rsa.check(get.first, get.second)) {
        qpl::println("rolling");
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
    //find_primes<mpz_class, 4096u * 2>();
    check_RSA_load();
}

int main() try {
    //test_sha256(); 
    test_RSA();
}
catch (std::exception& any) {
    qpl::println("caught exception:\n", any.what());
    qpl::system_pause();
}