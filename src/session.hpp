#ifndef SOCKS5_SESSION_HPP
#define SOCKS5_SESSION_HPP

#include <cstdlib>
#include <string>
#include <memory>
#include <utility>
#include <boost/asio.hpp>
#include <vector>
#include <gsl/gsl>

namespace socks5 {

struct SessionId {
  unsigned long id{};
};

class Session : public std::enable_shared_from_this<Session>
{
public:
    Session(boost::asio::io_context& io_context,
            int sock_map,
            std::string natAddress,
            std::shared_ptr<boost::asio::ip::tcp::socket> in_socket,
            SessionId session_id,
            std::size_t buffer_size);
    void start();

  private:

    void read_socks5_handshake();
    void write_socks5_handshake();
    void read_socks5_request();
    void socks5_command(std::size_t length);
    void socks5_connect(std::size_t length);

    void do_resolve();
    void do_connect(const boost::asio::ip::tcp::resolver::iterator &iter);

    void write_socks5_response();
    void socks5_address_response();

    void do_read(int direction);
    void do_write(int direction, std::size_t Length);

    void bind_listener();
    void read_bind_client(const std::shared_ptr<boost::asio::ip::tcp::socket> &client_socket);
    void interpret_udp_header();
    void sockmap_relay();
    void read_client_udp();
    void read_server_udp();
    void read_client_tcp();
    void read_server_tcp();

    boost::asio::io_context& io_context_;
    int sock_map_{};
    std::shared_ptr<boost::asio::ip::tcp::socket> in_socket_{};
    gsl::owner<boost::asio::ip::udp::socket*> in_udp_sock_{};
    gsl::owner<boost::asio::ip::udp::socket*> nat_udp_socket_{};
    gsl::owner<boost::asio::ip::tcp::acceptor*>  bind_acceptor_{};
    boost::asio::ip::tcp::socket out_socket_;
    boost::asio::ip::tcp::resolver resolver_;
    boost::asio::ip::udp::resolver udp_resolver_;
    boost::asio::ip::udp::endpoint cli_udp_ep_{};
    boost::asio::ip::udp::endpoint receive_endpoint_{};
    boost::asio::ip::udp::endpoint send_to_endpoint_{};

    std::string nat_address_;
    std::string remote_host_{};
    std::string remote_port_{};
    std::string udp_r_host_{};
    std::string udp_r_port_{};
    std::uint8_t skip_n_{};

    std::vector<uint8_t> in_buf_{};
    std::vector<uint8_t> inn_buf_{};
    std::vector<uint8_t> out_buf_{};
    std::vector<uint8_t> bind_buf_{};
    std::uint8_t cmd_{};
    SessionId session_id_{};
};
} // namespace socks5

#endif // SOCKS5_SESSION_HPP
