#pragma once
#include <boost/beast.hpp>
#include <strstream>
namespace chai {
namespace beast = boost::beast; // from <boost/beast.hpp>
namespace http = beast::http;

namespace detail {

// This helper is needed for C++11.
// When invoked with a buffer sequence, writes the buffers `to the
// std::ostream`.
template <class Serializer> class write_ostream_helper {
  Serializer &sr_;
  std::ostream &os_;

public:
  write_ostream_helper(Serializer &sr, std::ostream &os) : sr_(sr), os_(os) {}

  // This function is called by the serializer
  template <class ConstBufferSequence>
  void operator()(beast::error_code &ec, ConstBufferSequence const &buffers) const {
    // Error codes must be cleared on success
    ec = {};

    // Keep a running total of how much we wrote
    std::size_t bytes_transferred = 0;

    // Loop over the buffer sequence
    for (auto it = boost::asio::buffer_sequence_begin(buffers);
         it != boost::asio::buffer_sequence_end(buffers); ++it) {
      // This is the next buffer in the sequence
      boost::asio::const_buffer const buffer = *it;

      // Write it to the std::ostream
      os_.write(reinterpret_cast<char const *>(buffer.data()), buffer.size());

      // If the std::ostream fails, convert it to an error code
      if (os_.fail()) {
        ec = make_error_code(beast::errc::io_error);
        return;
      }

      // Adjust our running total
      bytes_transferred += buffer_size(buffer);
    }

    // Inform the serializer of the amount we consumed
    sr_.consume(bytes_transferred);
  }
};

} // namespace detail

/** Write a message to a `std::ostream`.

    This function writes the serialized representation of the
    HTTP/1 message to the sream.

    @param os The `std::ostream` to write to.

    @param msg The message to serialize.

    @param ec Set to the error, if any occurred.
*/
template <bool isRequest, class Body, class Fields>
void write_ostream(std::ostream &os, http::message<isRequest, Body, Fields> &msg,
                   beast::error_code &ec) {
  // Create the serializer instance
  http::serializer<isRequest, Body, Fields> sr{msg};

  // This lambda is used as the "visit" function
  detail::write_ostream_helper<decltype(sr)> lambda{sr, os};
  do {
    // In C++14 we could use a generic lambda but since we want
    // to require only C++11, the lambda is written out by hand.
    // This function call retrieves the next serialized buffers.
    sr.next(ec, lambda);
    if (ec)
      return;
  } while (!sr.is_done());
}
} // namespace bingo
