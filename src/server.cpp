#include "server.hpp"

#include <memory>
#include <boost/log/trivial.hpp>

namespace socks5 {


Server::Server(boost::asio::io_context &io_context, int sock_map,
               const boost::asio::ip::tcp::endpoint& socks5Endpoint,
               std::string natAddress,
               std::size_t buffer_size)
    : io_context_(io_context),
    sock_map_(sock_map),
    acceptor_(io_context, socks5Endpoint),
    buffer_size_(buffer_size),
    nat_address_(std::move(natAddress)),
    session_id_{}
{}

void Server::start()
{
    const std::shared_ptr<boost::asio::ip::tcp::socket> client_socket = std::make_shared<boost::asio::ip::tcp::socket>(io_context_);
    acceptor_.async_accept(
        *client_socket,
        [this, client_socket](boost::system::error_code error_code)
        {
            if (!error_code)
            {
                BOOST_LOG_TRIVIAL(trace) << "NEW Session id: " << ++session_id_.id  << " Accept connecton from " << client_socket->remote_endpoint() << " on " << acceptor_.local_endpoint();
                std::make_shared<Session>(io_context_, sock_map_, nat_address_, client_socket, session_id_, buffer_size_)->start();
            } else {
                BOOST_LOG_TRIVIAL(error) << "Error: accept connecton from " << client_socket->remote_endpoint() << " on " << acceptor_.local_endpoint() << " fails: " << error_code;
            }

            start();
        });
    BOOST_LOG_TRIVIAL(info) << "Socks5 server started on " << acceptor_.local_endpoint();
}

} // namespace socks5
