#include <span>

namespace MathsOperation {
	void cl_multiply(std::span<uint8_t> a, std::span<uint8_t> b, std::span<uint8_t> out);
	void cl_divide(std::span<uint8_t> a, std::span<uint8_t> b, std::span<uint8_t> out);
	void cl_xor(std::span<const uint8_t> a, std::span<const uint8_t> b, std::span<uint8_t> out);
	void cl_add(std::span<uint8_t> a, std::span<uint8_t> b, std::span<uint8_t> out);
	void cl_sub(std::span<uint8_t> a, std::span<uint8_t> b, std::span<uint8_t> out);
};
