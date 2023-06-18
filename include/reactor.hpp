#pragma once
#include "chaisock.hpp"
#include <functional>
#include <mutex>
#include <stdexec/stop_token.hpp>
#include <vector>
namespace chai {
template <typename NewConnHandler, typename ReadHandler>
struct ConnectionReactor {
  NewConnHandler new_conn_handler;
  ReadHandler read_handler;
  static constexpr int MAXCLIENTS = 100;
  ConnectionReactor(NewConnHandler conn_handler, ReadHandler read_handler)
      : new_conn_handler(std::move(conn_handler)),
        read_handler(std::move(read_handler)) {}
  void run(sock_base &listener) {
    std::array<int, MAXCLIENTS> clientFd{-1};
    std::fill_n(begin(clientFd), MAXCLIENTS, -1);
    int maxSockFd = listener.fd_;
    int maxFdIndex = -1;
    fd_set allset, rset;
    FD_ZERO(&allset);
    FD_SET(listener.fd_, &allset);
    while (true) {
      rset = allset;
      int nready = select(maxSockFd + 1, &rset, nullptr, nullptr, nullptr);
      if (FD_ISSET(listener.fd_, &rset)) {
        auto newsock = accept(listener);
        auto iter = std::find(begin(clientFd), end(clientFd), -1);
        if (iter != std::end(clientFd)) {
          *iter = newsock.fd_;
          if (maxSockFd < newsock.fd_) {
            maxSockFd = newsock.fd_;
          }
          FD_SET(newsock.fd_, &allset);
          auto distance = std::distance(begin(clientFd), iter);
          if (distance >= maxFdIndex) {
            maxFdIndex = distance + 1;
          }
          new_conn_handler(std::move(newsock));
        }
        if (--nready == 0)
          continue; // no more descriptor to handle
      }
      auto replace = [&](auto fd) {
        if (fd >= 0 && FD_ISSET(fd, &rset) && nready > 0) {
          if (!read_handler(fd)) {
            FD_CLR(fd, &allset);
            return true;
          }
          --nready;
        }
        return false;
      };
      std::replace_if(begin(clientFd), begin(clientFd) + maxFdIndex, replace,
                      -1);
    }
  }
};

struct GenericReactor {
  enum class Reason { Trigger, Close };
  struct ReadHandlerBase {
    virtual int get_fd() const = 0;
    virtual bool handle_read(Reason reason) const = 0;
    virtual ~ReadHandlerBase(){};
  };
  template <typename Handler> struct ReadHandler : ReadHandlerBase {
    int fd_{-1};
    Handler handler;
    int get_fd() const { return fd_; }
    bool handle_read(Reason reason) const { return handler(reason); }
    ReadHandler(int fd, Handler h) : fd_(fd), handler(std::move(h)) {}
    ~ReadHandler() {}
  };
  std::vector<std::unique_ptr<ReadHandlerBase>> handlers;
  std::vector<std::unique_ptr<ReadHandlerBase>> pending_handlers;
  fd_set allset;
  int maxfd{-1};
  bool notifying{false};
  std::mutex mut;
  GenericReactor() {
    FD_ZERO(&allset);
    FD_SET(fileno(stdin), &allset);
    maxfd = fileno(stdin);
  }
  template <typename Handler> void add_handler(int fd, Handler h) {
    std::lock_guard guard(mut);

    FD_SET(fd, &allset);

    if (maxfd < fd)
      maxfd = fd;
    if (notifying) {
      add_if_not_present(pending_handlers, fd, std::move(h));
      return;
    }
    add_if_not_present(handlers, fd, std::move(h));
  }
  template <typename Handler>
  void add_if_not_present(auto &range, int fd, Handler h) {
    if (std::find_if(std::begin(range), std::end(range), [&](auto &v) {
          return v->get_fd() == fd;
        }) == std::end(range)) {
      range.emplace_back(new ReadHandler(fd, std::move(h)));
    }
  }
  void run(stdexec::in_place_stop_token stoptoken) {
    while (!stoptoken.stop_requested()) {
      fd_set rset = allset;
      timeval timeout{2, 0};

      int nready = select(maxfd + 1, &rset, nullptr, nullptr, &timeout);
      if (nready == 0)
        continue;

      notifying = true;
      std::vector<int> toberemoved;
      toberemoved.reserve(maxfd);
      // notify all clents waitng for read;
      auto iter = std::begin(handlers);
      while (nready > 0 && iter != std::end(handlers)) {
        iter = std::find_if(iter, std::end(handlers), [&](auto &v) {
          bool set = FD_ISSET(v->get_fd(), &rset);
          return set;
        });

        if (iter != std::end(handlers)) {
          if (!iter->get()->handle_read(Reason::Trigger)) {
            FD_CLR(iter->get()->get_fd(), &allset);
            toberemoved.push_back(iter->get()->get_fd());
          }
          --nready;
        }
      }
      notifying = false;
      std::lock_guard guard(mut);
      // clear all eof clients
      auto search_pred = [&](auto &v) {
        return (std::find_if(begin(toberemoved), end(toberemoved),
                             [&](auto &id) { return v->get_fd() == id; }) !=
                end(toberemoved));
      };

      handlers.erase(
          std::remove_if(begin(handlers), end(handlers), search_pred),
          handlers.end());
      // add new pending handlers to be added
      std::move(begin(pending_handlers), end(pending_handlers),
                std::back_inserter(handlers));
      pending_handlers.clear();
    }
    for (auto &a : handlers) {
      if (!a->handle_read(Reason::Close)) {
        FD_CLR(a->get_fd(), &allset);
      }
    }
  }
  static GenericReactor &get_reactor() {
    static GenericReactor reactor;
    return reactor;
  }
};
} // namespace bingo
