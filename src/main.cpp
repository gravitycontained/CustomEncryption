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

                        mu.lock();
                        qpl::println("thread #", thread_index, " found k", j + 1, ": ", k);
                        mu.unlock();

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
            qpl::println("found a prime ");
            qpl::println("\"", prime.get_str(16), "\",");
        }
    };


    std::vector<std::thread> threads_collection;
    for (qpl::size i = 0u; i < threads; ++i) {
        threads_collection.emplace_back(find, i);
    }
    for (auto& i : threads_collection) {
        i.join();
    }

    qpl::println("closed all threads, found ", found_primes.load(), " primes");
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

qpl::f64 bit_sum = 0.0;
qpl::f64 mod_sum = 0.0;

template<qpl::size bits, qpl::size threads = 12>
struct RSA {
    mpz_class mod;
    mpz_class private_key;
    mpz_class public_key;
    mpz_class coprime;

    constexpr static auto subs = std::array{
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
    };

    constexpr static auto get_sub() {
        return subs[qpl::log2(bits)];
    }

    void print(mpz_class prime1, mpz_class prime2, mpz_class lambda) {
        qpl::println("     prime1 = bits = ", prime1.get_str(2u).length());
        qpl::println("     prime2 = bits = ", prime2.get_str(2u).length());
        qpl::println("     lambda = bits = ", lambda.get_str(2u).length());
        qpl::println("        mod = bits = ", this->mod.get_str(2u).length());
        qpl::println(" public key = ", this->public_key);
        qpl::println("private key = ", this->private_key);
    }

    auto get_random_strong_prime() const {
        return get_two_strong_primes<mpz_class, threads>(bits, this->get_sub(), 1u);
    }

    void create(mpz_class prime1, mpz_class prime2, mpz_class lambda = 0) {
        if (lambda == 0) {
            auto p1 = mpz_class{ prime1 - 1 };
            auto p2 = mpz_class{ prime2 - 1 };
            lambda = mpz_class{ lcm(p1, p2) };
        }

        this->mod = mpz_class{ prime1 * prime2 };

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
        bit_sum += prime1.get_str(2u).length() / 2.0;
        bit_sum += prime2.get_str(2u).length() / 2.0;
        mod_sum += this->mod.get_str(2u).length();

        //this->print(prime1, prime2, lambda);
    }

    void randomize() {
        auto result = this->get_random_strong_prime();

        mpz_class prime1 = result.first;
        mpz_class prime2 = result.second;
        mpz_class lambda;

        while (true) {
            auto p1 = mpz_class{ prime1 - 1 };
            auto p2 = mpz_class{ prime2 - 1 };
            lambda = mpz_class{ lcm(p1, p2) };

            if (lambda == p1 || lambda == p2) {
                //qpl::println("lambda was p1 or p2");
                continue;
            }
            if (prime1 != prime2) {
                //qpl::println("prime1 != prime2, so found it");
                break;
            }

            result = this->get_random_strong_prime();
            mpz_class prime1 = result.first;
            mpz_class prime2 = result.second;
        }

        this->create(prime1, prime2, lambda);
    }

    void create_keys() {
        this->mod = this->prime1 * this->prime2;
        this->coprime = (1 << 15 + 1u);
        for (; this->coprime < this->lambda; ++this->coprime) {
            if (gcd(this->coprime, this->lambda) == 1) {

                this->private_key = maths::mod_inverse(this->coprime, this->lambda);
                if (this->private_key != this->coprime) {
                    this->public_key = this->coprime;
                    break;
                }
            }
        }
    }

    auto encrypt(mpz_class message) const {
        mpz_class result;
        mpz_powm(result.get_mpz_t(), message.get_mpz_t(), this->public_key.get_mpz_t(), this->mod.get_mpz_t());
        return result;
    }
    auto decrypt(mpz_class message) const {
        mpz_class result;
        mpz_powm(result.get_mpz_t(), message.get_mpz_t(), this->private_key.get_mpz_t(), this->mod.get_mpz_t());
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

            constexpr auto sub = RSA<bits>::get_sub();
            auto prime = get_strong_prime<T>(bits, sub, rounds);


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
                        qpl::println("\"", i.get_str(16), "\", ");
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

void check_RSA() {
    constexpr auto bits = 1024u * 8;
    RSA<bits, 10> rsa;

    qpl::size success = 0u;
    qpl::clock clock;

    for (qpl::size gen = 0u;; ++gen) {

        //rsa.prime1 = 61;
        //rsa.prime2 = 53;

        //auto message = 65ull;

        rsa.randomize();

        if ((gen + 1) % 2 == 0u) {
            qpl::println("for bits = ", bits, " (sub = ", rsa.get_sub(), ")");
            qpl::println("prime bits average: ", bit_sum / (gen + 1));
            qpl::println("mod bits average:   ", mod_sum / (gen + 1));
            qpl::println("rate = 1 every ", qpl::secs((clock.elapsed_f() / (gen + 1)) / 2).small_descriptive_string());
            qpl::println();
        }

        //auto message = get_random_number<mpz_class>(bits);
        //auto encrypted = rsa.encrypt(message);
        //auto decrypted = rsa.decrypt(encrypted);
        //
        //if (decrypted != message) {
        //    qpl::println("  message = ", qpl::light_red, message);
        //    qpl::println("encrypted = ", encrypted);
        //    qpl::println("decrypted = ", qpl::light_red, decrypted);
        //    qpl::println("\n");
        //}
        //else {
        //    ++success;
        //}
        //
        //++gen;
        //if (qpl::get_time_signal(0.5)) {
        //    auto rate = qpl::f64_cast(success) / gen;
        //    qpl::println(qpl::green, "successes = ", qpl::big_number_string(success));
        //    qpl::println(qpl::light_red, "    fails = ", qpl::big_number_string(gen - success));
        //    qpl::println(qpl::big_number_string(qpl::f64_cast(gen) / clock.elapsed_f()), " / sec");
        //    qpl::println();
        //}
    }
}

int main() try {
    //test();

    random::init();
    
    //find_primes<mpz_class>(2048);
    find_primes<mpz_class, 4096u>();
    //find_primes<mpz_class>(4096);
    //check_RSA();

    //std::string string = "hello world 123125678 hello world 123125678 hello world 123125678";
    //check_encryption(string, "123456");
    //
    //check_mistakes();
}
catch (std::exception& any) {
    qpl::println("caught exception:\n", any.what());
    qpl::system_pause();
}