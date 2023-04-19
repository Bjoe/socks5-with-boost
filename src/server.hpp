#ifndef SOCKS5_SERVER_HPP
#define SOCKS5_SERVER_HPP

#include <string>
#include <boost/asio.hpp>
#include "session.hpp"

namespace socks5 {

class Server
{
public:
    Server(boost::asio::io_context &io_context,
           const boost::asio::ip::tcp::endpoint &socks5Endpoint,
           std::string natAddress,
           std::size_t buffer_size);

    void start();

private:
    boost::asio::io_context& io_context_;
    boost::asio::ip::tcp::acceptor acceptor_;
    std::size_t buffer_size_;
    std::string nat_address_;
    SessionId session_id_;
};

} // namespace socks5

#endif // SOCKS5_SERVER_HPP
