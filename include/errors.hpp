#pragma once
#include <exception>
#include <stdexcept>
#include <string.h>
namespace chai {
struct socket_exception : std::runtime_error {
  socket_exception(const std::string &message) : runtime_error(message) {}
};
struct application_error:std::runtime_error{
  application_error(const std::string &message) : runtime_error(message) {}
};
} // namespace bingo
