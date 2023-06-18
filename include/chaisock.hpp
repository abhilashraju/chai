#pragma once
#include <arpa/inet.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <stdexcept>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <string>
#include <sys/socket.h>
#include <thread>
#include <unistd.h>
#include <utility>
#include <vector>
#include "buffer.hpp"
#include "errors.hpp"
namespace chai {
struct sock_address {
  struct sockaddr_in address {
    0
  };
  sock_address() {}
  sock_address(std::string addr, int port) {
    address.sin_family = AF_INET;
    address.sin_port = htons(port);
    if (int r = inet_pton(AF_INET, addr.data(), &address.sin_addr) <= 0) {
      throw socket_exception(std::string("address error: ") + strerror(r));
    }
  }
};
struct sock_base {
  int fd_{-1};
  sock_address address;
  bool listening{false};
  bool eof_{false};
  void set_eof(bool f){eof_=f;}
  bool eof()const{return eof_;}
  sock_base() {
    if ((fd_ = ::socket(AF_INET, SOCK_STREAM, 0)) == 0) {
      throw socket_exception(std::string("sock creation error: ") +
                               strerror(errno));
    }
  }
  sock_base(int fd, sock_address addr, bool l)
      : fd_(fd), address(addr), listening(l) {}
  sock_base(const sock_base &other) = delete;
  sock_base &operator=(const sock_base &other) = delete;
  sock_base(sock_base &&other)
      : fd_(other.fd_), address(std::move(other.address)),
        listening(other.listening),eof_(other.eof_) {
    other.fd_ = -1;
    other.listening = false;
  }
  sock_base &bind(sock_address addr) {
    address = addr;
    address.address.sin_addr.s_addr = htonl(INADDR_ANY);
    if (int r = ::bind(fd_, (struct sockaddr *)&address.address,
                       sizeof(addr.address)) < 0) {
      throw socket_exception(std::string("bind error: ") + strerror(r));
    }
    return *this;
  }
  friend void swap(sock_base &t1, sock_base &t2) {
    std::swap(t1.fd_, t2.fd_);
    std::swap(t1.listening, t2.listening);
    std::swap(t1.address, t2.address);
  }
  sock_base &operator=(sock_base &&other) {
    sock_base temp(std::move(other));
    swap(*this, temp);
    return *this;
  }
  ~sock_base() {
    if (listening) {
      shutdown(*this);
      listening = false;
    }
    if (fd_ > 0) {
      ::close(fd_);
      fd_ = -1;
    }
  }
  friend void shutdown(sock_base &stream) { shutdown(stream.fd_, SHUT_RDWR); }
  friend void listen(sock_base &stream) {
    if (::listen(stream.fd_, 3) < 0) {
      throw socket_exception(std::string("listen error: ") + strerror(errno));
    }
  }
  friend void listen(sock_base &stream, const sock_address &addr) {
    stream.bind(addr);
    listen(stream);
  }
  friend void set_blocked(sock_base &stream) {
    if (int r = fcntl(stream.fd_, F_SETFL,
                      fcntl(stream.fd_, F_GETFL) | F_LOCK) < 0) {
      throw socket_exception(std::string("block failed error: ") +
                               strerror(r));
    }
  }
  friend sock_base accept(const sock_base &stream) {

    sock_address address;
    int addrlen{sizeof(address.address)};
    int fd{-1};
    if ((fd = ::accept(stream.fd_, (struct sockaddr *)&address.address,
                       (socklen_t *)&addrlen)) < 0) {
      throw socket_exception(std::string("accept error: ") + strerror(errno));
    }
    sock_base new_socket{fd, address, false};
    set_blocked(new_socket);
    return new_socket;
  }
  template <typename Buffer>
  int read_all(Buffer& buffer){
      return read(*this,buffer);
  }
  template <typename Buffer>
  friend int read(sock_base &stream, Buffer& buff) {
    constexpr int MAXSIZE=1024;
    auto read=0;
    while(true){
       int r = ::read(stream.fd_, buff.prepare(MAXSIZE), MAXSIZE);
       if (r < 0) {
          if(errno==EINTR) continue;
          throw socket_exception(strerror(r));
       }
       if(r==0){
           stream.set_eof(true);
           break;
       }
       read+=r;
       buff.commit(r);
       if(r<MAXSIZE){
        break;
       }
    }
    return read;
  }
  int readsome(char* buff,int size) {


      int r = ::read(fd_, buff, size);
      if (r < 0) {
          if(errno!=EINTR)
              throw socket_exception(strerror(r));
      }
      if(r==0){
          set_eof(true);
      }
      return r;

  }
  template <typename Buffer>
  friend int send(const sock_base &stream, Buffer buff) {
    int r = ::send(stream.fd_, buff.data(), buff.read_length(), MSG_NOSIGNAL);
    if (r < 0) {
      throw socket_exception(strerror(r));
    }
    return r;
  }

  friend sock_base connect(sock_base &stream,
                             const sock_address &serv_addr) {
    sock_base newstream;
    if ((newstream.fd_ =
             ::connect(stream.fd_, (struct sockaddr *)&serv_addr.address,
                       sizeof(serv_addr.address))) < 0) {
      throw socket_exception(std::string("connection error: ") +
                               strerror(errno));
    }
    set_blocked(newstream);
    return newstream;
  }

  friend auto close(sock_base &stream) {
    return ::close(stream.fd_);
  }
};
template<typename Buffer>
struct sock_stream{
    sock_base base_;
    Buffer buff;
    bool failed_{false};
    int gcount_{0};
    sock_stream(sock_base b):base_(std::move(b)){}
    auto rdbuf(){return buff.rdbuf();};
    sock_base& base(){return base_;}
    bool eof()const {return base_.eof();}
    int read(char* buffer, int length){
        try {
            gcount_= base_.readsome(buffer,length);
        } catch (socket_exception& e) {
            failed_=true;
            gcount_=0;
        }
        return gcount_;
    }
    int read(){
        std::string v;
        string_buffer data{v};
        if ((gcount_ = base_.read_all(data)) > 0){
            buff<<data.data();
            data.consume_all();
            return gcount_;
        }
        throw socket_exception("client closed");
    }
    int readsome(char* outbuffer, int length){
        return buff.readsome(outbuffer,length);
    }
    bool fail()const{
        return failed_;
    }
    int gcount()const{
        return gcount_;
    }

};

} // namespace bingo
