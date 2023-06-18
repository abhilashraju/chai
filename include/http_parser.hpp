
#include <boost/beast.hpp>
#include "buffer.hpp"
#include <istream>
namespace beast = boost::beast;  // from <boost/beast.hpp>
namespace http = boost::beast::http;
namespace chai {

template <typename Stream,class Allocator, bool isRequest, class Body>
void read_istream(
    Stream& is,
    beast::basic_flat_buffer<Allocator>& buffer,
    beast::http::message<isRequest, Body, beast::http::fields>& msg,
    beast::error_code& ec) {
  // Create the message parser
  //
  // Arguments passed to the parser's constructor are
  // forwarded to the message constructor. Here, we use
  // a move construction in case the caller has constructed
  // their message in a non-default way.
  //
  beast::http::parser<isRequest, Body> p{std::move(msg)};

  do {
    // Extract whatever characters are presently available in the istream
    if (is.rdbuf()->in_avail() > 0) {
      // Get a mutable buffer sequence for writing
      auto const b =
          buffer.prepare(static_cast<std::size_t>(is.rdbuf()->in_avail()));

      // Now get everything we can from the istream
      buffer.commit(static_cast<std::size_t>(
          is.readsome(reinterpret_cast<char*>(b.data()), b.size())));
    } else if (buffer.size() == 0) {
      // Our buffer is empty and we need more characters,
      // see if we've reached the end of file on the istream
      if (!is.eof()) {
        // Get a mutable buffer sequence for writing
        auto const b = buffer.prepare(1024);

        // Try to get more from the istream. This might block.
        is.read(reinterpret_cast<char*>(b.data()), b.size());

        // If an error occurs on the istream then return it to the caller.
        if (is.fail() && !is.eof()) {
          // We'll just re-use io_error since std::istream has no error_code
          // interface.
          ec = beast::error::timeout;  //(std::errc::io_error);
          return;
        }

        // Commit the characters we got to the buffer.
        buffer.commit(static_cast<std::size_t>(is.gcount()));
      } else {
        // Inform the parser that we've reached the end of the istream.
        p.put_eof(ec);
        if (ec)
          return;
        break;
      }
    }

    // Write the data to the parser
    auto const bytes_used = p.put(buffer.data(), ec);

    // This error means that the parser needs additional octets.
    if (ec == beast::http::error::need_more)
      ec = {};
    if (ec)
      return;

    // Consume the buffer octets that were actually parsed.
    buffer.consume(bytes_used);
  } while (!p.is_done());

  // Transfer ownership of the message container in the parser to the caller.
  msg = p.release();
}

}  // namespace bingo
