#pragma once
#include <algorithm>
#include <exception>
#include <string>
#include <vector>
namespace chai {
struct NullResizer {
  char *resize(char *data, size_t current, size_t req) {
    throw std::runtime_error("Buffer Cannot be resized");
  }
};
struct VectorResizer {
  std::vector<char> *vec{nullptr};
  VectorResizer() {}
  void set_vector(std::vector<char> &v) { vec = &v; }
  char *resize(char *data, size_t current, size_t req) {
    vec->resize(req);
    return vec->data();
  }
};
struct StringResizer {
  std::string *str{nullptr};
  StringResizer() {}
  void set_string(std::string &s) { str = &s; }
  char *resize(char *data, size_t current, size_t req) {
    str->resize(req);
    return str->data();
  }
};
struct DynamicResizer {
  std::unique_ptr<char[]> bytes;
  size_t length{0};
  DynamicResizer() {}
  char *resize(char *data, size_t current, size_t req) {
    auto buffer = new char[req];
    std::fill_n(buffer, req, 0);
    std::copy_n(data, std::min(current, req), buffer);
    bytes.reset(buffer);
    length = req;
    return bytes.get();
  }
};


class mutable_buffer {
public:
  /// Construct an empty buffer.
  mutable_buffer() : data_(0), size_(0) {}

  /// Construct a buffer to represent a given memory range.
  mutable_buffer(void *data, std::size_t size) : data_(data), size_(size) {}

  /// Get a pointer to the beginning of the memory range.
  void *data() const { return data_; }

  /// Get the size of the memory range.
  std::size_t size() const { return size_; }

  /// Move the start of the buffer by the specified number of bytes.
  mutable_buffer &operator+=(std::size_t n) {
    std::size_t offset = n < size_ ? n : size_;
    data_ = static_cast<char *>(data_) + offset;
    size_ -= offset;
    return *this;
  }

private:
  void *data_;
  std::size_t size_;
};



template <typename Resizer> struct buffer_base {
private:
  char *base{nullptr};
  const char *read_buff{nullptr};
  size_t read_len{0};
  char *write_buff{nullptr};
  size_t write_len{0};
  size_t capacity{0};
  Resizer resizer;
  void intialise(char *p, size_t len) {
    base = p;
    read_buff = p;
    read_len = len;
    write_buff = p;
    write_len = 0;
    capacity = len;
  }

public:
  buffer_base(const char *p, size_t len, NullResizer res = NullResizer())
      : resizer(res) {
    intialise((char *)p, len);
    write_buff = base + len;
  }
  template <size_t size>
  buffer_base(std::array<char, size> &arry, NullResizer res = NullResizer())
      : resizer(res) {
    intialise(arry.data(), arry.length());
  }
  buffer_base(std::vector<char> &v, VectorResizer res = VectorResizer())
      : resizer(res) {
    resizer.set_vector(v);
    intialise(v.data(), v.capacity());
    capacity = v.capacity();
  }
  buffer_base(DynamicResizer res = DynamicResizer()) : resizer(res) {
    intialise(res.bytes.get(), res.length);
    capacity = res.length;
  }
  buffer_base(std::string &v, StringResizer res = StringResizer())
      : resizer(res) {
    resizer.set_string(v);
    intialise(v.data(), v.size());
  }

  const char *data() const { return read_buff; }
  const char *read_begin() const { return read_buff; }
  const char *read_end() const { return read_buff + read_len; }
  size_t read_length() const { return read_len; }
  void consume(size_t n) {
    n = (n > read_len) ? read_len : n;
    std::fill((char *)read_buff, (char *)read_buff + read_len, '\0');
    read_buff += n;
    read_len -= n;
    if (read_buff >= write_buff) {
      read_buff = base;
      write_buff = base;
      read_len = 0;
      write_len = capacity;
    }
  }
  void consume_all() { consume(read_length()); }
  void resize(size_t newsize) {
    auto oldbase = base;
    base = resizer.resize(base, capacity, newsize);
    read_buff = base + (read_buff - oldbase);
    write_buff = base + (write_buff - oldbase);
    std::fill(write_buff, write_buff + write_len, 0);
    capacity = newsize;
  }
  char *prepare(size_t n) {
    auto overshoot = (write_buff + n) - (base + capacity);
    if (overshoot > 0) {
      resize(capacity + overshoot);
    }
    write_len = n;
    return write_buff;
  }
  auto prepare_as_mutable_buffer(size_t n) {
    auto overshoot = (write_buff + n) - (base + capacity);
    if (overshoot > 0) {
      resize(capacity + overshoot);
    }
    write_len = n;
    return mutable_buffer(write_buff,write_len);
  }
  void commit(size_t used) {
    auto usedbuff = write_buff + used;
    auto end = base + capacity;
    write_buff = (usedbuff >= end) ? end : usedbuff;
    read_len += used;
    write_len -= used;
  }
  char *write_begin() const { return write_buff; }
  char *writer_end() const { return write_buff + write_len; }
  size_t write_length() const { return write_len; }
  size_t length() const { return capacity; }
  size_t size() const { return length(); }
  buffer_base<NullResizer> read_view() const {
    return buffer_base<NullResizer>(data(), read_length());
  }
};

using buffer = buffer_base<NullResizer>;
using string_buffer = buffer_base<StringResizer>;
using vector_buffer = buffer_base<VectorResizer>;
using dynamic_buffer = buffer_base<DynamicResizer>;


class const_buffer {
public:
  /// Construct an empty buffer.
  const_buffer() : data_(0), size_(0) {}

  /// Construct a buffer to represent a given memory range.
  const_buffer(const void *data, std::size_t size) : data_(data), size_(size) {}

  /// Construct a non-modifiable buffer from a modifiable one.
  const_buffer(const mutable_buffer &b) : data_(b.data()), size_(b.size()) {}
  const_buffer(const buffer &b) : data_(b.data()), size_(b.size()) {}

  /// Get a pointer to the beginning of the memory range.
  const void *data() const { return data_; }

  /// Get the size of the memory range.
  std::size_t size() const { return size_; }

  /// Move the start of the buffer by the specified number of bytes.
  const_buffer &operator+=(std::size_t n) {
    std::size_t offset = n < size_ ? n : size_;
    data_ = static_cast<const char *>(data_) + offset;
    size_ -= offset;
    return *this;
  }

private:
  const void *data_;
  std::size_t size_;
};

inline mutable_buffer operator+(const mutable_buffer &b, std::size_t n) {
  std::size_t offset = n < b.size() ? n : b.size();
  char *new_data = static_cast<char *>(b.data()) + offset;
  std::size_t new_size = b.size() - offset;
  return mutable_buffer(new_data, new_size);
}

/// Create a new modifiable buffer that is offset from the start of another.
/**
 * @relates mutable_buffer
 */
inline mutable_buffer operator+(std::size_t n, const mutable_buffer &b) {
  return b + n;
}

inline const_buffer operator+(const const_buffer &b, std::size_t n) {
  std::size_t offset = n < b.size() ? n : b.size();
  const char *new_data = static_cast<const char *>(b.data()) + offset;
  std::size_t new_size = b.size() - offset;
  return const_buffer(new_data, new_size);
}

/// Create a new non-modifiable buffer that is offset from the start of another.
/**
 * @relates const_buffer
 */
inline const_buffer operator+(std::size_t n, const const_buffer &b) {
  return b + n;
}

template <typename MutableBuffer>
inline const mutable_buffer *buffer_sequence_begin(
    const MutableBuffer &b,
    typename std::enable_if<std::is_convertible<
        const MutableBuffer *, const mutable_buffer *>::value>::type * = 0) {
  return static_cast<const mutable_buffer *>(std::addressof(b));
}

/// Get an iterator to the first element in a buffer sequence.
template <typename ConstBuffer>
inline const const_buffer *buffer_sequence_begin(
    const ConstBuffer &b,
    typename std::enable_if<std::is_convertible<
        const ConstBuffer *, const const_buffer *>::value>::type * = 0) {
  return static_cast<const const_buffer *>(std::addressof(b));
}

/// Get an iterator to the first element in a buffer sequence.
template <typename ConstBuffer>
inline const vector_buffer *buffer_sequence_begin(
    const ConstBuffer &b,
    typename std::enable_if<std::is_convertible<
        const ConstBuffer *, const vector_buffer *>::value>::type * = 0) {
  return static_cast<const vector_buffer *>(std::addressof(b));
}

/// Get an iterator to the first element in a buffer sequence.
template <typename ConstBuffer>
inline const string_buffer *buffer_sequence_begin(
    const ConstBuffer &b,
    typename std::enable_if<std::is_convertible<
        const ConstBuffer *, const string_buffer *>::value>::type * = 0) {
  return static_cast<const string_buffer *>(std::addressof(b));
}

/// Get an iterator to one past the end element in a buffer sequence.
template <typename ConstBuffer>
inline const const_buffer *buffer_sequence_end(
    const ConstBuffer &b,
    typename std::enable_if<std::is_convertible<
        const ConstBuffer *, const const_buffer *>::value>::type * = 0) {
  return static_cast<const const_buffer *>(std::addressof(b)) + 1;
}

/// Get an iterator to one past the end element in a buffer sequence.
template <typename ConstBuffer>
inline const vector_buffer *buffer_sequence_end(
    const ConstBuffer &b,
    typename std::enable_if<std::is_convertible<
        const ConstBuffer *, const vector_buffer *>::value>::type * = 0) {
  return static_cast<const vector_buffer *>(std::addressof(b)) + 1;
}
/// Get an iterator to one past the end element in a buffer sequence.
template <typename ConstBuffer>
inline const string_buffer *buffer_sequence_end(
    const ConstBuffer &b,
    typename std::enable_if<std::is_convertible<
        const ConstBuffer *, const string_buffer *>::value>::type * = 0) {
  return static_cast<const string_buffer *>(std::addressof(b)) + 1;
}

// namespace detail {
// struct one_buffer {};
// struct multiple_buffers {};
// template <typename BufferSequence>
// struct buffer_sequence_cardinality
//     : std::conditional<std::is_same<BufferSequence, mutable_buffer>::value ||
//                            std::is_same<BufferSequence, const_buffer>::value ||
//                            std::is_same<BufferSequence, vector_buffer>::value ||
//                            std::is_same<BufferSequence, string_buffer>::value,
//                        one_buffer, multiple_buffers>::type {};
// inline std::size_t buffer_copy_1(const mutable_buffer &target,
//                                  const const_buffer &source) {
//   using namespace std; // For memcpy.
//   std::size_t target_size = target.size();
//   std::size_t source_size = source.size();
//   std::size_t n = target_size < source_size ? target_size : source_size;
//   if (n > 0)
//     memcpy(target.data(), source.data(), n);
//   return n;
// }

// template <typename TargetIterator, typename SourceIterator>
// inline std::size_t buffer_copy(one_buffer, one_buffer,
//                                TargetIterator target_begin, TargetIterator,
//                                SourceIterator source_begin, SourceIterator) {
//   return (buffer_copy_1)(*target_begin, *source_begin);
// }

// template <typename TargetIterator, typename SourceIterator>
// inline std::size_t buffer_copy(one_buffer, one_buffer,
//                                TargetIterator target_begin, TargetIterator,
//                                SourceIterator source_begin, SourceIterator,
//                                std::size_t max_bytes_to_copy) {
//   return (buffer_copy_1)(*target_begin,
//                          buffer(*source_begin, max_bytes_to_copy));
// }

// template <typename TargetIterator, typename SourceIterator>
// std::size_t buffer_copy(
//     one_buffer, multiple_buffers, TargetIterator target_begin, TargetIterator,
//     SourceIterator source_begin, SourceIterator source_end,
//     std::size_t max_bytes_to_copy = (std::numeric_limits<std::size_t>::max)()) {
//   std::size_t total_bytes_copied = 0;
//   SourceIterator source_iter = source_begin;

//   for (mutable_buffer target_buffer(buffer(*target_begin, max_bytes_to_copy));
//        target_buffer.size() && source_iter != source_end; ++source_iter) {
//     const_buffer source_buffer(*source_iter);
//     std::size_t bytes_copied = (buffer_copy_1)(target_buffer, source_buffer);
//     total_bytes_copied += bytes_copied;
//     target_buffer += bytes_copied;
//   }

//   return total_bytes_copied;
// }

// template <typename TargetIterator, typename SourceIterator>
// std::size_t buffer_copy(
//     multiple_buffers, one_buffer, TargetIterator target_begin,
//     TargetIterator target_end, SourceIterator source_begin, SourceIterator,
//     std::size_t max_bytes_to_copy = (std::numeric_limits<std::size_t>::max)()) {
//   std::size_t total_bytes_copied = 0;
//   TargetIterator target_iter = target_begin;

//   for (const_buffer source_buffer(buffer(*source_begin, max_bytes_to_copy));
//        source_buffer.size() && target_iter != target_end; ++target_iter) {
//     mutable_buffer target_buffer(*target_iter);
//     std::size_t bytes_copied = (buffer_copy_1)(target_buffer, source_buffer);
//     total_bytes_copied += bytes_copied;
//     source_buffer += bytes_copied;
//   }

//   return total_bytes_copied;
// }

// template <typename TargetIterator, typename SourceIterator>
// std::size_t buffer_copy(multiple_buffers, multiple_buffers,
//                         TargetIterator target_begin, TargetIterator target_end,
//                         SourceIterator source_begin,
//                         SourceIterator source_end) {
//   std::size_t total_bytes_copied = 0;

//   TargetIterator target_iter = target_begin;
//   std::size_t target_buffer_offset = 0;

//   SourceIterator source_iter = source_begin;
//   std::size_t source_buffer_offset = 0;

//   while (target_iter != target_end && source_iter != source_end) {
//     mutable_buffer target_buffer =
//         mutable_buffer(*target_iter) + target_buffer_offset;

//     const_buffer source_buffer =
//         const_buffer(*source_iter) + source_buffer_offset;

//     std::size_t bytes_copied = (buffer_copy_1)(target_buffer, source_buffer);
//     total_bytes_copied += bytes_copied;

//     if (bytes_copied == target_buffer.size()) {
//       ++target_iter;
//       target_buffer_offset = 0;
//     } else
//       target_buffer_offset += bytes_copied;

//     if (bytes_copied == source_buffer.size()) {
//       ++source_iter;
//       source_buffer_offset = 0;
//     } else
//       source_buffer_offset += bytes_copied;
//   }

//   return total_bytes_copied;
// }

// template <typename TargetIterator, typename SourceIterator>
// std::size_t buffer_copy(multiple_buffers, multiple_buffers,
//                         TargetIterator target_begin, TargetIterator target_end,
//                         SourceIterator source_begin, SourceIterator source_end,
//                         std::size_t max_bytes_to_copy) {
//   std::size_t total_bytes_copied = 0;

//   TargetIterator target_iter = target_begin;
//   std::size_t target_buffer_offset = 0;

//   SourceIterator source_iter = source_begin;
//   std::size_t source_buffer_offset = 0;

//   while (total_bytes_copied != max_bytes_to_copy && target_iter != target_end &&
//          source_iter != source_end) {
//     mutable_buffer target_buffer =
//         mutable_buffer(*target_iter) + target_buffer_offset;

//     const_buffer source_buffer =
//         const_buffer(*source_iter) + source_buffer_offset;

//     std::size_t bytes_copied = (buffer_copy_1)(
//         target_buffer,
//         buffer(source_buffer, max_bytes_to_copy - total_bytes_copied));
//     total_bytes_copied += bytes_copied;

//     if (bytes_copied == target_buffer.size()) {
//       ++target_iter;
//       target_buffer_offset = 0;
//     } else
//       target_buffer_offset += bytes_copied;

//     if (bytes_copied == source_buffer.size()) {
//       ++source_iter;
//       source_buffer_offset = 0;
//     } else
//       source_buffer_offset += bytes_copied;
//   }

//   return total_bytes_copied;
// }

// } // namespace detail

// template <typename MutableBufferSequence, typename ConstBufferSequence>
// inline std::size_t buffer_copy(const MutableBufferSequence &target,
//                                const ConstBufferSequence &source) {
//   return detail::buffer_copy(
//       detail::buffer_sequence_cardinality<MutableBufferSequence>(),
//       detail::buffer_sequence_cardinality<ConstBufferSequence>(),
//       bingo::buffer_sequence_begin(target), bingo::buffer_sequence_end(target),
//       bingo::buffer_sequence_begin(source), bingo::buffer_sequence_end(source));
// }
} // namespace bingo
