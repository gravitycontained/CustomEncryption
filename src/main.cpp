#include <qpl/qpl.hpp>



struct encryption {
	constexpr static auto state_size = 12u;

	std::vector<qpl::u8> message;
	std::vector<qpl::u8> key;
	std::vector<qpl::u8> output;
	std::array<qpl::u8, state_size> state;
	qpl::size states = 0u;
	qpl::size state_ctr = 0u;

	void cipher_state() {
		auto index = this->state_ctr * this->state_size;
		for (qpl::size i = 0u; i < this->state_size; ++i) {

			//this->state[i] = qpl::rotate_left(this->state[i], 1);

			this->output[index + i] = this->state[i];
		}
	}
	void decipher_state() {
		auto index = this->state_ctr * this->state_size;
		for (qpl::size i = 0u; i < this->state_size; ++i) {

			//this->state[i] = qpl::rotate_right(this->state[i], 1);

			this->output[index + i] = this->state[i];
		}
	}

	void cipher() {
		std::array<qpl::u8, this->state_size> last_state{};

		for (this->state_ctr = 0u; this->state_ctr < this->states; ++this->state_ctr) {
			for (qpl::size i = 0u; i < this->state_size; ++i) {
				this->state[i] = this->message[this->state_ctr * this->state_size + i] ^ last_state[i];
			}
			this->cipher_state();
			last_state = this->state;
		}
	}
	void decipher() {
		std::array<qpl::u8, this->state_size> last_state{};

		for (qpl::size i = 0u; i < this->states; ++i) {
			this->state_ctr = i;
			for (qpl::size i = 0u; i < this->state_size; ++i) {
				this->state[i] = this->message[this->state_ctr * this->state_size + i] ^ last_state[i];
			}

			last_state = this->state;
			this->decipher_state();
		}
	}

	void set_input(const std::string_view& message, const std::string_view& key) {
		this->key.resize(key.length());
		std::memcpy(this->key.data(), key.data(), key.length());

		this->states = ((message.length() - 1) / this->state_size + 1);
		auto output_size = this->states * this->state_size;

		this->message.resize(output_size);
		std::memcpy(this->message.data(), message.data(), message.length());

		this->output.resize(output_size);
	}
	std::string encrypt(const std::string_view& message, const std::string_view& key) {
		this->set_input(message, key);
		this->cipher();

		auto output_size = this->states * this->state_size;
		auto delta = output_size - message.length();
		std::string result;
		result.resize(output_size + 1);
		std::memcpy(result.data(), this->output.data(), this->output.size());
		result.back() = qpl::u8_cast(delta);
		return result;
	}

	std::string decrypt(const std::string_view& message, const std::string_view& key) {
		auto delta = qpl::u8_cast(message.back());
		this->set_input(message.substr(0u, message.length() - 1), key);
		this->decipher();

		auto output_size = this->states * this->state_size - delta;
		std::string result;
		result.resize(output_size);
		std::memcpy(result.data(), this->output.data(), output_size);
		return result;
	}
};


void test(std::string message, std::string key) {
	encryption e;

	auto output = e.encrypt(message, key);

	output = e.decrypt(output, key);

	if (output != message) {
		qpl::println(message, " (", message.length(), ")");
		qpl::println(output, " (", output.length(), ")");
		qpl::println();
	}
}
void check_mistakes() {
	qpl::small_clock clock;

	for (qpl::size i = 0u;; ++i) {
		auto l = qpl::random(10, 20);
		auto message = qpl::get_random_uppercase_string(l);
		test(message, "123");

		if (qpl::get_time_signal(0.5)) {
			auto rate = qpl::f64_cast(i) / clock.elapsed_f();
			qpl::println(qpl::big_number_string(i), " checks (", qpl::big_number_string(rate), " / sec)");
		}
	}

}

int main() try {
	check_mistakes();
}
catch (std::exception& any) {
	qpl::println("caught exception:\n", any.what());
	qpl::system_pause();
}