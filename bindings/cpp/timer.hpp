#pragma once

#include <chrono>

namespace ioremap { namespace elliptics { namespace util {

template <typename Clock>
class timer {
public:
	using clock = Clock;
	using time_point = typename clock::time_point;

	timer() { restart(); }

	void restart() { time_point_ = clock::now(); }

	template <typename Duration>
	typename Duration::rep get() const {
		return std::chrono::duration_cast<Duration>(clock::now() - time_point_).count();
	}

#define SPECIALIZE_FOR_DURATION(duration, suffix)                                                                      \
	duration::rep get_##suffix() const { return get<duration>(); }

	SPECIALIZE_FOR_DURATION(std::chrono::seconds, s)
	SPECIALIZE_FOR_DURATION(std::chrono::milliseconds, ms)
	SPECIALIZE_FOR_DURATION(std::chrono::microseconds, us)
	SPECIALIZE_FOR_DURATION(std::chrono::nanoseconds, ns)

private:
	time_point time_point_;
};

typedef timer<std::chrono::system_clock> system_timer;
typedef timer<std::chrono::steady_clock> steady_timer;
typedef timer<std::chrono::high_resolution_clock> high_resolution_timer;

}}} /* namespace ioremap::elliptics::util */
