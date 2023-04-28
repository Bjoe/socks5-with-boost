#ifndef SOCKS5_SERVER_HPP
#define SOCKS5_SERVER_HPP

#include <string>
#include <vector>
#include <memory>
#include <boost/asio.hpp>
#include "session.hpp"
#include "options.hpp"

namespace socks5 {

class Server
{
public:
    Server(boost::asio::io_context &io_context,
           int sock_map,
           const boost::asio::ip::tcp::endpoint &socks5Endpoint,
           std::string natAddress,
           std::size_t buffer_size,
           Options options);

    void start();

    void close();
private:
    boost::asio::io_context& io_context_;
    int sock_map_{};
    boost::asio::ip::tcp::acceptor acceptor_;
    std::size_t buffer_size_{};
    std::string nat_address_{};
    Options options_{};
    SessionId session_id_{};
    std::vector<std::shared_ptr<Session>> sessions_{};
};

} // namespace socks5

#endif // SOCKS5_SERVER_HPP
