#include <qpl/qpl.hpp>

#pragma warning (disable : 4146)
#include <gmpxx.h>

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
    constexpr T mod_pow(T a, T b, T mod, qpl::size bits) {
        using long_u = double_precision_type<T>;
        T result = 1;
        T power = a % mod;

        for (qpl::size i = 0; i < bits; ++i) {
            T least_sig_bit = T{ 0x1 } &(b >> i);
            if (least_sig_bit != 0) {
                result = (long_u{ result } *power) % mod;
            }
            power = (long_u{ power } *power) % mod;
        }

        return result;
    }
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

    auto primes = qpl::generate_primes<qpl::u32>(1024 * 4);
    template<typename T>
    constexpr T gpf(T n) {

        for (auto& prime : primes) {
            T p;
            p = prime;

            if (n % p == 0) {
                T result = (n / p);
                return ::gcd(n, result);
            }
        }
        return 0;
    }
}

namespace random {
    gmp_randclass engine(gmp_randinit_default);

    void init() {
        engine.seed(time(NULL));
    }
}

template<typename T>
auto get_random_number(qpl::size bits) {
    T n;
    if constexpr (qpl::is_same<T, mpz_class>()) {
        n = random::engine.get_z_bits(bits);
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

template<typename T, bool print = false>
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
    auto ctz = maths::count_trailing_zeroes(T{ n - 1 });
    T d = (n - 1);
    d >>= ctz;


    for (qpl::size k = 0; k < rounds; ++k) {
        T a = get_random_range(T{ 2 }, T{ n - 2 });
        T x = maths::mod_pow(a, d, n, bits);
        //T x;    
        //mpz_t tmp;
        //mpz_init(tmp);
        //mpz_powm(tmp, a, d, n);
        //mpz_clear(tmp);

        if (x == 1 || x == (n - 1)) {
            continue;
        }

        if (ctz) {
            for (qpl::size i = 0u; i < (ctz - 1); ++i) {
                x = maths::mod_mul(x, x, n);

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
auto get_random_prime(qpl::size bits, qpl::size rounds = qpl::size_max) {
    if (rounds == qpl::size_max) {
        rounds = bits / 2;
    }

    T divide;
    divide = 6 * 5 * 7 * 11 * 13 * 17 * 19 * 23u;
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
            auto check = miller_rabin_primality_test(n, bits, rounds);
            if (check) {
                return n;
            }
        }
    }
    return T{};
}

template<typename T>
auto get_strong_prime(qpl::size bits, qpl::size delta, qpl::size rounds = qpl::size_max) {
    if (rounds == qpl::size_max) {
        rounds = bits / 2;
    }

    T prime;
    while (true) {
        prime = get_random_prime<T>(bits, rounds);

        auto largest_factor = maths::gpf(T{ prime - 1 });
        if (largest_factor == 0) {
            continue;
        }

        auto bits = largest_factor.get_str(2u).length();
        if (bits > (bits - delta)) {
            auto largest_factor2 = maths::gpf(T{ largest_factor - 1 });
            if (largest_factor2 == 0) {
                continue;
            }

            bits = largest_factor2.get_str(2u).length();
            if (bits > (bits - delta * 2)) {

                qpl::println("found ", prime);
                qpl::println("with factor ", largest_factor);
                qpl::println(", and factor ", largest_factor2);
                return prime;
            }
        }
    }



    return prime;
}

template<qpl::size bits>
struct RSA {

    mpz_class prime1;
    mpz_class prime2;
    mpz_class mod;
    mpz_class lambda;
    mpz_class private_key;
    mpz_class public_key;
    mpz_class coprime;

    void print() {
        qpl::println("     prime1 = ", this->prime1);
        qpl::println("     prime2 = ", this->prime2);
        qpl::println("        mod = ", this->mod);
        qpl::println("     lambda = ", this->lambda);
        qpl::println(" public key = ", this->public_key);
        qpl::println("private key = ", this->private_key);
    }

    auto get_random_prime() const {
        return get_strong_prime<mpz_class>(bits, bits / 16, 1u);
    }

    void randomize() {
        this->prime1 = this->get_random_prime();

        this->prime2 = this->prime1;
        while (true) {
            this->prime2 = this->get_random_prime();

            auto p1 = mpz_class{ this->prime1 - 1 };
            auto p2 = mpz_class{ this->prime2 - 1 };
            this->lambda = mpz_class{ lcm(p1, p2) };

            if (this->lambda == p1 || this->lambda == p2) {
                this->prime1 = this->get_random_prime();
                continue;
            }
            if (this->prime1 != this->prime2) {
                break;
            }
        }
    }

    void create_keys() {
        this->mod = this->prime1 * this->prime2;
        this->coprime = 3u;
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
        return maths::mod_pow<mpz_class>(message, this->public_key, this->mod, bits);
    }
    auto decrypt(mpz_class message) const {
        return maths::mod_pow<mpz_class>(message, this->private_key, this->mod, bits);
    }
};

std::mutex mu;

template<typename T>
void find_primes(qpl::size bits) {
    qpl::clock clock;

    std::vector<std::thread> threads;

    std::vector<T> primes;
    std::map<qpl::u32, qpl::size> factors;

    qpl::size print_ctr = 0u;

    auto find = [&](qpl::size thread) {
        for (qpl::size i = 0u;; ++i) {

            //auto prime1 = get_strong_prime<qpl::integer<bits, false>>(bits, 64);

            auto rounds = 1u;

            auto prime = get_strong_prime<T>(bits, 20, rounds);


            //auto prime = get_strong_prime<T>(bits, 8u, rounds);

            //auto prime = std::get<0u>(result);
            //auto i1 = std::get<1u>(result);
            //auto i2 = std::get<2u>(result);

            std::lock_guard lock{ mu };



            if (prime != 0) {
                qpl::println("thread #", qpl::str_spaced(thread, 2), " found a prime with ", prime.get_str(2u).length(), " bits");
                primes.push_back(prime);

                ++print_ctr;

                if (print_ctr % 5u == 0u) {
                    auto rate = clock.elapsed_f() / primes.size();

                    qpl::size sum = 0u;

                    qpl::size exact_primes = 0u;
                    for (auto& i : primes) {
                        auto str = i.get_str(2);
                        if (str.length() == bits) {
                            ++exact_primes;
                            qpl::println("\"", i.get_str(16), "\", ");
                        }
                        sum += str.length();
                    }
                    auto exact_rate = clock.elapsed_f() / exact_primes;
                    qpl::println("rate is 1 prime every ", qpl::secs(rate).small_descriptive_string(), ". (", primes.size(), " found so far)");
                    qpl::println("exra is 1 prime every ", qpl::secs(exact_rate).small_descriptive_string(), ". (", exact_primes, " found so far)");
                    qpl::println("bits average = ", qpl::f64_cast(sum) / primes.size());
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

    constexpr auto bits = 32u;
    RSA<bits> rsa;


    qpl::size gen = 0u;

    qpl::size success = 0u;
    qpl::clock clock;
    while (true) {

        //rsa.prime1 = 61;
        //rsa.prime2 = 53;

        //auto message = 65ull;
        rsa.randomize();
        rsa.create_keys();

        auto message = get_random_number<mpz_class>(bits);
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
    random::init();

    //auto is_prime = miller_rabin_primality_test(c, 16);
    //qpl::println("is_prime: ", is_prime);

    //test();
    //constexpr auto bits = 32 * 16;
    //using type = qpl::integer<bits, false>;
    //
    //find_primes<mpz_class>(2048);
    //find_primes<mpz_class>(4096);
    //find_primes<mpz_class>(128);
    check_RSA();

    //std::string string = "hello world 123125678 hello world 123125678 hello world 123125678";
    //check_encryption(string, "123456");
    //
    //check_mistakes();
}
catch (std::exception& any) {
    qpl::println("caught exception:\n", any.what());
    qpl::system_pause();
}