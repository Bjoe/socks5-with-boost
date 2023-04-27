#include "session.hpp"
#include <iostream>
#include <array>
#include <functional>
#include <string>
#include <cstring>
#include <gsl/gsl>
#include <boost/log/trivial.hpp>
#include <stdexcept>
#include <poll.h>
#include <errno.h>
#include <linux/bpf.h>
#include <fcntl.h> // to add splice()
#include <linux/aio_abi.h> // to add iocb
extern "C" {
  #include "sockmap/tbpf.h"
  #include "iosubmit.h"
};

constexpr std::uint8_t SOCKS_VERSION = 0x05;
constexpr std::uint8_t NO_ACCEPTABLE_METHODS = 0xFF;
constexpr std::uint8_t NO_AUTHENTICATION_REQUIRED = 0x00;
constexpr std::uint8_t SUCCEEDED = 0x00;
constexpr std::uint8_t COMMAND_NOT_SUPPORT_ED = 0x07;
constexpr std::uint8_t RESERVED = 0x00;
constexpr std::uint8_t NO_FRAGMENT = 0x00;
constexpr std::uint8_t IPV4_ADDRESS = 0x01;
constexpr std::uint8_t MIN_REQUEST_LENGTH = 5;
constexpr std::uint8_t BND_ADDR = 4;
constexpr std::uint8_t BND_PORT = 8;
constexpr int RESPONSE_SIZE = 10;
constexpr int SKIP_10_BYTES = 10;
//constexpr int SKIP_22_BYTES = 22;
constexpr int REPLY_SIZE = 10;
constexpr int DOMAINNAME = 5;

namespace socks5 {

Session::Session(boost::asio::io_context &io_context, int sock_map,
  std::string natAddress,
  std::shared_ptr<boost::asio::ip::tcp::socket> in_socket,
  SessionId session_id,
  std::size_t buffer_size)
  : io_context_(io_context),
    sock_map_(sock_map),
    in_socket_(std::move(in_socket)),
    out_socket_(io_context),
    resolver_(io_context),
    udp_resolver_{io_context},
    nat_address_(std::move(natAddress)),
    in_buf_(buffer_size),
    inn_buf_(buffer_size),
    out_buf_(buffer_size),
    bind_buf_(buffer_size),
    session_id_(session_id)
{
}

void Session::start()
{
  read_socks5_handshake();
}

/*
The client connects to the server, and sends a version
identifier/method selection message:

+----+----------+----------+
|VER | NMETHODS | METHODS  |
+----+----------+----------+
| 1  |    1     | 1 to 255 |
+----+----------+----------+

The values currently defined for METHOD are:

o  X'00' NO AUTHENTICATION REQUIRED
o  X'01' GSSAPI
o  X'02' USERNAME/PASSWORD
o  X'03' to X'7F' IANA ASSIGNED
o  X'80' to X'FE' RESERVED FOR PRIVATE METHODS
o  X'FF' NO ACCEPTABLE METHODS

 */
bool verify_socks5_handshake(
  const SessionId& session_id,
  std::vector<uint8_t>& in_buf,
  std::size_t length)
{
  if (length < 3) {
    BOOST_LOG_TRIVIAL(error) << "Session id: " << session_id.id << " SOCKS5 handshake request is invalid because of wrong lenght. Closing session.";
    return false;
  }

  if (in_buf[0] != SOCKS_VERSION) {
    BOOST_LOG_TRIVIAL(error) << "Session id: " << session_id.id << " SOCKS5 handshake request is invalid because of wrong version. Closing session.";
    return false;
  }

  const uint8_t num_methods = in_buf[1];
  // Prepare request
  in_buf[1] = NO_ACCEPTABLE_METHODS;

        // Only 0x00 - 'NO AUTHENTICATION REQUIRED' is now support_ed
  for (uint8_t method = 0; method < num_methods; ++method) {
    if (in_buf[2 + method] == NO_AUTHENTICATION_REQUIRED) { in_buf[1] = NO_AUTHENTICATION_REQUIRED; break; }
  }

  return true;
}

void Session::read_socks5_handshake()
{
  auto self(shared_from_this());

  in_socket_->async_receive(
    boost::asio::buffer(in_buf_),
    [this, self](boost::system::error_code error_code, std::size_t length)
    {
      if (!error_code)
      {
        if(verify_socks5_handshake(session_id_, in_buf_, length)) {
          write_socks5_handshake();
        }
      } else {
        BOOST_LOG_TRIVIAL(error) << "Session id: " << session_id_.id << " SOCKS5 handshake request fails: " << error_code;
      }

    });
}

void Session::write_socks5_handshake()
{
  auto self(shared_from_this());

  boost::asio::async_write(
    *in_socket_, boost::asio::buffer(in_buf_, 2), // Always 2-byte according to RFC1928
    [this, self](boost::system::error_code error_code, std::size_t /*length*/)
    {
      if (!error_code) {
        if (in_buf_[1] == NO_ACCEPTABLE_METHODS) {
          BOOST_LOG_TRIVIAL(error) << "Session id: " << session_id_.id << " SOCKS5 handshake response from " << in_socket_->remote_endpoint() << " No appropriate auth method found. Close session.";
          return; // No appropriate auth method found. Close session.
        }
        BOOST_LOG_TRIVIAL(info) << "Session id: " << session_id_.id << " SOCKS5 handshake successfull with " << in_socket_->remote_endpoint();
        read_socks5_request();
      } else {
        BOOST_LOG_TRIVIAL(error) << "Session id: " << session_id_.id << " SOCKS5 handshake response write fails: " << error_code;
      }

    });
}



void Session::socks5_connect(std::size_t length)
{
  auto self(shared_from_this());

  const std::uint8_t addr_type = in_buf_[3];
  switch (addr_type)
  {
  case 0x01: // IP V4 address
  {
    if (length != REPLY_SIZE) { BOOST_LOG_TRIVIAL(error) << "Session id: " << session_id_.id << " SOCKS5 request length is invalid. Closing session."; return; }
    const std::uint32_t netip = static_cast<std::uint32_t>(in_buf_[4] << 24U) + static_cast<std::uint32_t>(in_buf_[5] << 16U) + static_cast<std::uint32_t>(in_buf_[6] << 8U) + in_buf_[7];
    remote_host_ = boost::asio::ip::address_v4(netip).to_string();
    const std::uint16_t netport = static_cast<std::uint16_t>(in_buf_[8] << 8U) + in_buf_[9];
    remote_port_ = std::to_string(netport);
    break;
  }
  case 0x03: // DOMAINNAME
  {
    const std::size_t host_length = in_buf_[4];
    if (length != static_cast<std::size_t>(DOMAINNAME + host_length + 2)) { BOOST_LOG_TRIVIAL(error) << "Session id: " << session_id_.id << " SOCKS5 request length is invalid. Closing session."; return; }
    std::ostringstream convert;
    for (std::size_t i = DOMAINNAME; i < (DOMAINNAME + host_length); i++) {
      convert << in_buf_[i];
    }
    remote_host_ = convert.str();
    const std::uint16_t netport = static_cast<std::uint16_t>(in_buf_[DOMAINNAME + host_length] << 8U) + in_buf_[DOMAINNAME + host_length + 1];
    remote_port_ = std::to_string(netport);
    break;
  }
  // TODO case 0x04 // IP V6 address
  default:
    BOOST_LOG_TRIVIAL(error) << "Session id: " << session_id_.id << " Unsupport_ed address type in SOCKS5 request. Closing session.";
    break;
  }
  BOOST_LOG_TRIVIAL(info) << "Session id: " << session_id_.id << " SOCKS5 CONNECT request from " << in_socket_->remote_endpoint() << " to " << remote_host_ << ":" << remote_port_;

  do_resolve();

}

/*
The SOCKS request is formed as follows:

+----+-----+-------+------+----------+----------+
|VER | CMD |  RSV  | ATYP | DST.ADDR | DST.PORT |
+----+-----+-------+------+----------+----------+
| 1  |  1  | X'00' |  1   | Variable |    2     |
+----+-----+-------+------+----------+----------+

 Where:

o  VER    protocol version: X'05'
o  CMD
    o  CONNECT X'01'
    o  BIND X'02'
    o  UDP ASSOCIATE X'03'
o  RSV    RESERVED
o  ATYP   address type of following address
    o  IP V4 address: X'01'
    o  DOMAINNAME: X'03'
    o  IP V6 address: X'04'
o  DST.ADDR       desired destination address
o  DST.PORT desired destination port_ in network octet
order

 The SOCKS server will typically evaluate the request based on source
 and destination addresses, and return one or more reply messages, as
 appropriate for the request type.
 */
void Session::socks5_command(std::size_t length)
{
  auto self(shared_from_this());
  cmd_ = in_buf_[1];
  switch (cmd_)
  {
  case 0x01: // CONNECT
  {
    socks5_connect(length);
  }
  break;
  case 0x02: // BIND
  {
    BOOST_LOG_TRIVIAL(info) << "Session id: " << session_id_.id << " SOCKS5 BIND request from " << in_socket_->remote_endpoint();
    write_socks5_response();
  }
  break;
  case 0x03: // UDP
  {
    BOOST_LOG_TRIVIAL(info) << "Session id: " << session_id_.id << " SOCKS5 UDP request from " << in_socket_->remote_endpoint();
    write_socks5_response();
  }
  break;
  default:
    BOOST_LOG_TRIVIAL(error) << "Session id: " << session_id_.id << " Unsupport_ed command in SOCKS5 request. Closing session.";
    break;
  }
}


void Session::read_socks5_request()
{
  auto self(shared_from_this());

  in_socket_->async_receive(
    boost::asio::buffer(in_buf_),
    [this, self](boost::system::error_code error_code, std::size_t length)
    {
      if (!error_code)
      {
        if (length < MIN_REQUEST_LENGTH || in_buf_[0] != SOCKS_VERSION || in_buf_[2] != RESERVED)
        {
          BOOST_LOG_TRIVIAL(error) << "Session id: " << session_id_.id << " SOCKS5 request is invalid. Closing session.";
          return;
        }

        socks5_command(length);
      }
    });
}

void Session::do_resolve()
{
  auto self(shared_from_this());

  resolver_.async_resolve(boost::asio::ip::tcp::resolver::query({ remote_host_, remote_port_ }),
    [this, self](const boost::system::error_code& error_code, const boost::asio::ip::tcp::resolver::iterator& iter)
    {
      if (!error_code)
      {
        do_connect(iter);
      }
      else
      {
        BOOST_LOG_TRIVIAL(error) << "Session id: " << session_id_.id << " Failed to resolve " << remote_host_ << ":" << remote_port_ << " Error: " << error_code;
      }
    });
}

void Session::do_connect(const boost::asio::ip::tcp::resolver::iterator &iter)
{
  auto self(shared_from_this());

  out_socket_.async_connect(*iter,
    [this, self](const boost::system::error_code& error_code)
    {
      if (!error_code)
      {
        BOOST_LOG_TRIVIAL(info) << "Session id: " << session_id_.id << " Connected to " << remote_host_ << ":" << remote_port_;
        write_socks5_response();
      }
      else
      {
        BOOST_LOG_TRIVIAL(error) << "Session id: " << session_id_.id << " Failed to connect " << remote_host_ << ":" << remote_port_ << " Error: " << error_code;

      }
    });

}

/*
The SOCKS request information is sent by the client as soon as it has
established a connection to the SOCKS server, and completed the
authentication negotiations.  The server evaluates the request, and
returns a reply formed as follows:

+----+-----+-------+------+----------+----------+
|VER | REP |  RSV  | ATYP | BND.ADDR | BND.PORT |
+----+-----+-------+------+----------+----------+
| 1  |  1  | X'00' |  1   | Variable |    2     |
+----+-----+-------+------+----------+----------+

Where:

o  VER    protocol version: X'05'
o  REP    Reply field:
o  X'00' succeeded
o  X'01' general SOCKS server failure
o  X'02' connection not allowed by ruleset
o  X'03' Network unreachable
o  X'04' Host unreachable
o  X'05' Connection refused
o  X'06' TTL expired
o  X'07' Command not support_ed
o  X'08' Address type not support_ed
o  X'09' to X'FF' unassigned
o  RSV    RESERVED
o  ATYP   address type of following address
o  IP V4 address: X'01'
o  DOMAINNAME: X'03'
o  IP V6 address: X'04'
o  BND.ADDR       server bound address
o  BND.PORT       server bound port_ in network octet order

Fields marked RESERVED (RSV) must be set to X'00'.
*/
void Session::socks5_address_response()
{
   auto self(shared_from_this());

  uint32_t bind_addr{};
  uint16_t bind_port{};

  switch (cmd_)
  {
  case 0x01: // CONNECT
  {
    BOOST_LOG_TRIVIAL(info) << "Session id: " << session_id_.id << " SOCKS5 CONNECT via " << out_socket_.local_endpoint();
    //auto realRemoteIP = out_socket_.remote_endpoint().address().to_v4().to_bytes();
    //auto realRemoteport = htons(out_socket_.remote_endpoint().port());
    bind_addr = htonl(out_socket_.local_endpoint().address().to_v4().to_uint());
    bind_port = htons(out_socket_.local_endpoint().port());

          //#ifdef BOOST_ENDIAN_LITTLE_BYTE
          //    byteSwap(realRemoteport);
          //#endif
  }
  break;
  case 0x02: // BIND
  {
    delete bind_acceptor_;
    bind_acceptor_ = new boost::asio::ip::tcp::acceptor{io_context_, {boost::asio::ip::tcp::v4(), 0}};
    bind_addr = htonl(bind_acceptor_->local_endpoint().address().to_v4().to_uint());
    bind_port = htons(bind_acceptor_->local_endpoint().port());
    BOOST_LOG_TRIVIAL(info) << "Session id: " << session_id_.id << " SOCKS5 BIND via address " << bind_acceptor_->local_endpoint();
  }
  break;
  case 0x03: // UDP
  {
    auto ipv4 = in_socket_->local_endpoint().address().to_v4();
    auto localEndpoint = boost::asio::ip::udp::endpoint{ipv4, 0};
    auto natEndpoint = boost::asio::ip::udp::endpoint{boost::asio::ip::address::from_string(nat_address_), 0};
    delete in_udp_sock_;
    in_udp_sock_ = new boost::asio::ip::udp::socket{io_context_, localEndpoint};
    delete nat_udp_socket_;
    nat_udp_socket_ = new boost::asio::ip::udp::socket{io_context_, natEndpoint};
    auto endpoint = in_udp_sock_->local_endpoint();
    BOOST_LOG_TRIVIAL(info) << "Session id: " << session_id_.id << " SOCKS5 UDP address " << endpoint << " via " << nat_udp_socket_->local_endpoint() << " out";

    bind_addr = htonl(endpoint.address().to_v4().to_uint());
    bind_port = htons(endpoint.port());
  }
  break;
  default:
    BOOST_LOG_TRIVIAL(error) << "Session id: " << session_id_.id << " Unsupport_ed command in SOCKS5 request. Closing session.";
    in_buf_[1] = COMMAND_NOT_SUPPORT_ED;
    break;
  }

  std::memcpy(&in_buf_[BND_ADDR], &bind_addr, 4);
  std::memcpy(&in_buf_[BND_PORT], &bind_port, 2);
}

void Session::write_socks5_response()
{
  auto self(shared_from_this());

  in_buf_[0] = SOCKS_VERSION;
  in_buf_[1] = SUCCEEDED;
  in_buf_[2] = RESERVED;
  in_buf_[3] = IPV4_ADDRESS;

  socks5_address_response();

  boost::asio::async_write(
    *in_socket_, boost::asio::buffer(in_buf_, RESPONSE_SIZE), // Always 10-byte according to RFC1928
    [this, self](boost::system::error_code error_code, std::size_t /*length*/)
    {
      if (!error_code) {
        switch (cmd_)
        {
        case 0x01: // CONNECT
        {
          BOOST_LOG_TRIVIAL(info) << "Session id: " << session_id_.id << " SOCKS5 response send. Start tcp ...";
          //read_client_tcp();
          //read_server_tcp();
          sockmap_relay();
          break;
        }
        case 0x02: // BIND
        {
          BOOST_LOG_TRIVIAL(info) << "Session id: " << session_id_.id << " SOCKS5 response send. Start bind listener ...";
          bind_listener();
        }
        break;
        case 0x03: // UDP
        {
          BOOST_LOG_TRIVIAL(info) << "Session id: " << session_id_.id << " SOCKS5 response send. Start udp ...";
          read_client_udp();
          read_server_udp();
        }
        break;
        default:
          break;
        }
      } else {
        BOOST_LOG_TRIVIAL(error) << "Session id: " << session_id_.id << " SOCKS5 response write" << error_code;
      }
    });
}

void Session::bind_listener()
{
  auto self(shared_from_this());

  const std::shared_ptr<boost::asio::ip::tcp::socket> client_socket = std::make_shared<boost::asio::ip::tcp::socket>(io_context_);
  bind_acceptor_->async_accept(
    *client_socket,
    [this, self, client_socket](boost::system::error_code error_code) {
      if (error_code) {
        BOOST_LOG_TRIVIAL(error) << "Session id: " << session_id_.id << " BIND failed from " << client_socket->local_endpoint() << " : " << error_code;
        return;
      }

      BOOST_LOG_TRIVIAL(info) << "Session id: " << session_id_.id << " BIND from client " << client_socket->local_endpoint();
      uint32_t bind_addr{0};
      uint16_t bind_port{0};

      /*
      The SOCKS request information is sent by the client as soon as it has
      established a connection to the SOCKS server, and completed the
      authentication negotiations.  The server evaluates the request, and
      returns a reply formed as follows:

             +----+-----+-------+------+----------+----------+
             |VER | REP |  RSV  | ATYP | BND.ADDR | BND.PORT |
             +----+-----+-------+------+----------+----------+
             | 1  |  1  | X'00' |  1   | Variable |    2     |
             +----+-----+-------+------+----------+----------+

              Where:

               o  VER    protocol version: X'05'
               o  REP    Reply field:
                   o  X'00' succeeded
                   o  X'01' general SOCKS server failure
                   o  X'02' connection not allowed by ruleset
                   o  X'03' Network unreachable
                   o  X'04' Host unreachable
                   o  X'05' Connection refused
                   o  X'06' TTL expired
                   o  X'07' Command not support_ed
                   o  X'08' Address type not support_ed
                   o  X'09' to X'FF' unassigned
               o  RSV    RESERVED
               o  ATYP   address type of following address
                   o  IP V4 address: X'01'
                   o  DOMAINNAME: X'03'
                   o  IP V6 address: X'04'
               o  BND.ADDR       server bound address
               o  BND.PORT       server bound port_ in network octet order

                Fields marked RESERVED (RSV) must be set to X'00'.
                */
      std::array<uint8_t, REPLY_SIZE> reply_buf{SOCKS_VERSION, SUCCEEDED, RESERVED, IPV4_ADDRESS};
      bind_addr = htonl(client_socket->remote_endpoint().address().to_v4().to_uint());
      bind_port = htons(client_socket->remote_endpoint().port());
      memcpy(&reply_buf[BND_ADDR], &bind_addr, 4);
      memcpy(&reply_buf[BND_PORT], &bind_port, 2);
      boost::asio::async_write(
        *in_socket_,
        boost::asio::buffer(reply_buf, reply_buf.size()),
        [this, self, client_socket](boost::system::error_code error_code, std::size_t) {
          if (error_code) {
            BOOST_LOG_TRIVIAL(error) << "Session id: " << session_id_.id << " BIND Replay failed: " << error_code;
          } else {
            BOOST_LOG_TRIVIAL(info) << "Session id: " << session_id_.id << " Send sockes BIND request to " << in_socket_->local_endpoint() << " with server bound address : " << client_socket->local_endpoint();
            read_bind_client(client_socket);
          }
        });
    });
}

void Session::read_bind_client(const std::shared_ptr<boost::asio::ip::tcp::socket>& client_socket)
{
  auto self(shared_from_this());

  client_socket->async_read_some(
    boost::asio::buffer(bind_buf_),
    [this, self, client_socket](const boost::system::error_code &error_code, std::size_t length)
    {
      if (!error_code)
      {
        boost::asio::async_write(
          *in_socket_,
          boost::asio::buffer(bind_buf_, length),
          [this, self, client_socket](const boost::system::error_code &error_code, std::size_t /*n*/)
          {
            if (!error_code)
            {
              read_bind_client(client_socket);
            }
            else
            {
              BOOST_LOG_TRIVIAL(error) << "Session id: " << session_id_.id << " Write to in socket failed: " << error_code;
            }
          });
      }
      else
      {
        BOOST_LOG_TRIVIAL(error) << "Session id: " << session_id_.id << " Read faild from client socket. " << error_code;
        if(client_socket->is_open())
        {
          BOOST_LOG_TRIVIAL(error) << "Session id: " << session_id_.id << " Closing session. Close out socket";
          client_socket->close();
        }

      }
    });
}


/*
+----+------+------+----------+----------+----------+
|RSV | FRAG | ATYP | DST.ADDR | DST.PORT |   DATA   |
+----+------+------+----------+----------+----------+
| 2  |  1   |  1   | Variable |    2     | Variable |
+----+------+------+----------+----------+----------+

  o  RSV            Reserved X'0000'
  o  FRAG           Current fragment number
  o  ATYP           address type of following addresses:
    o  IP V4 address:   X'01'
    o  DOMAINNAME:      X'03'
    o  IP V6 address:   X'04'
  o  DST.ADDR       desired destination address
  o  DST.PORT       desired destination port
  o  DATA           user data
*/
void Session::interpret_udp_header()
{
  auto self(shared_from_this());

  switch (in_buf_[3])
  {
  case 0x01: // IP V4 addres, with a length of 4 octets
  {
    const std::uint32_t netip = static_cast<std::uint32_t>(in_buf_[4] << 24U) + static_cast<std::uint32_t>(in_buf_[5] << 16U) + static_cast<std::uint32_t>(in_buf_[6] << 8U) + in_buf_[7];
    auto udp_r_host = boost::asio::ip::address_v4(netip);
    const std::uint16_t udp_r_port = static_cast<std::uint16_t>(in_buf_[8] << 8U) + in_buf_[9];
    send_to_endpoint_ = boost::asio::ip::udp::endpoint{udp_r_host, udp_r_port};
    skip_n_ = SKIP_10_BYTES;
    break;
  }
  case 0x03: // DOMAINNAME, The first
  {
    // octet of the address field contains the number of octets of name that
    // follow, there is no terminating NUL octet

    const std::size_t host_length = in_buf_[4];
    std::ostringstream convert;
    for (std::size_t i = DOMAINNAME; i < (DOMAINNAME + host_length); i++) {
      convert << in_buf_[i];
    }
    udp_r_host_ = convert.str();
    const std::uint16_t netport = static_cast<std::uint16_t>(in_buf_[DOMAINNAME + host_length] << 8U) + in_buf_[DOMAINNAME + host_length + 1];
    udp_r_port_ = std::to_string(netport);
    skip_n_ = DOMAINNAME + in_buf_[4] + 2;
    udp_resolver_.async_resolve(
      boost::asio::ip::udp::resolver::query({ udp_r_host_, udp_r_port_ }),
      [this, self](const boost::system::error_code& error_code, const boost::asio::ip::udp::resolver::results_type& eps) {
        if (!error_code) {
          send_to_endpoint_ = eps->endpoint();
        } else {
          BOOST_LOG_TRIVIAL(error) << "Session id: " << session_id_.id << " Failed to resolve udp " << udp_r_host_ << ":" << udp_r_port_ << " " << error_code;
        }
      });
    break;
  }
  case 0x04: // IP V6 address, with a length of 16 octets.
  {
  /*  boost::asio::ip::address_v6::bytes_type a_data{};
    std::copy(&in_buf_[4], &in_buf_[4] + a_data.size(), a_data.data());
    auto udp_r_host = boost::asio::ip::address_v6(a_data);
    auto udp_r_port = ntohls(static_cast<uint16_t>(in_buf_[20]));
    send_to_endpoint_ = boost::asio::ip::udp::endpoint{udp_r_host, udp_r_port};
    skip_n_ = SKIP_22_BYTES;*/
    break;
  }
  default:
    break;
  }
}

void Session::read_client_udp()
{
  auto self(shared_from_this());

  in_udp_sock_->async_receive_from(
    boost::asio::buffer(in_buf_), receive_endpoint_,
    [this, self](const boost::system::error_code &error_code, std::size_t receive_bytes) {
      if (error_code) {
        BOOST_LOG_TRIVIAL(error) << "Session id: " << session_id_.id << " Read faild from udp socket. " << error_code;
      }
      //BOOST_LOG_TRIVIAL(trace) << "Session id: " << session_id_.id << " receive " << receive_bytes << " bytes from " << receive_endpoint_;// << " compare with " << in_socket_->remote_endpoint();
      //if (receive_endpoint_.address().to_string() == in_socket_->remote_endpoint().address().to_string())
      {
        // Send to remote
        cli_udp_ep_ = receive_endpoint_;

        interpret_udp_header();

        nat_udp_socket_->async_send_to(boost::asio::buffer(&in_buf_[0 + skip_n_], receive_bytes - skip_n_),
          send_to_endpoint_,
          [this, self](const boost::system::error_code &error_code, std::size_t /*n*/){
            if(error_code) {
              BOOST_LOG_TRIVIAL(error) << "Session id: " << session_id_.id << " Read faild from udp socket. " << error_code;
            }
            //BOOST_LOG_TRIVIAL(trace) << "Session id: " << session_id_.id << " udp send " << n << " bytes to remote: " << eps->endpoint();
            read_client_udp();

          });

      }
    });
}

void Session::read_server_udp()
{
  auto self(shared_from_this());

  nat_udp_socket_->async_receive_from(
    boost::asio::buffer(inn_buf_), receive_endpoint_,  // TODO create a new buf. do not use in buf
    [this, self](const boost::system::error_code &error_code, std::size_t receive_bytes) {
      if (error_code) {
        BOOST_LOG_TRIVIAL(error) << "Session id: " << session_id_.id << " Read faild from udp socket. " << error_code;
      }

            // Send to client
      uint32_t dst_addr = htonl(receive_endpoint_.address().to_v4().to_uint());
      uint16_t dst_port = htons(receive_endpoint_.port());

      out_buf_[0] = RESERVED;
      out_buf_[1] = RESERVED;
      out_buf_[2] = NO_FRAGMENT;
      out_buf_[3] = IPV4_ADDRESS;

      std::memcpy(&out_buf_[BND_ADDR], &dst_addr, 4);
      std::memcpy(&out_buf_[BND_PORT], &dst_port, 2);
      std::memcpy(&out_buf_[REPLY_SIZE], static_cast<const void*>(inn_buf_.data()), receive_bytes);
      in_udp_sock_->async_send_to(
        boost::asio::buffer(out_buf_, REPLY_SIZE + receive_bytes),
        cli_udp_ep_,
        [this,self](const boost::system::error_code &error_code, std::size_t /*n*/){
          if(error_code) {
            BOOST_LOG_TRIVIAL(error) << "Session id: " << session_id_.id << " Read faild from udp socket. " << error_code;
          }
          //BOOST_LOG_TRIVIAL(trace) << "Session id: " << session_id_.id << " udp send " << n << " bytes to client: " << cli_udp_ep_;
          read_server_udp();
        });

    });
}

void Session::sockmap_relay()
{
  int fd = in_socket_->native_handle();
  int fd_out = out_socket_.native_handle();
  {
    /* There is a bug in sockmap which prevents it from
     * working right when snd buffer is full. Set it to
     * gigantic value. */
    int val = 32 * 1024 * 1024;
    setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &val, sizeof(val));
  }

  /* [*] Perform ebpf socket magic */
  /* Add socket to SOCKMAP. Otherwise the ebpf won't work. */
  int idx = 0;
  int val = fd;
  int r = tbpf_map_update_elem(sock_map_, &idx, &val, BPF_ANY);
  if (r != 0) {
    if (errno == EOPNOTSUPP) {
      throw std::logic_error("pushing closed socket to sockmap?");
    }
    throw std::logic_error("bpf(MAP_UPDATE_ELEM)");
  }

  int idx_out = 1;
  int val_out = fd_out;
  r = tbpf_map_update_elem(sock_map_, &idx_out, &val_out, BPF_ANY);
  if (r != 0) {
    if (errno == EOPNOTSUPP) {
      throw std::logic_error("pushing closed socket to sockmap?");
    }
    throw std::logic_error("bpf(MAP_UPDATE_ELEM)");
  }

  /* [*] Wait for the socket to close. Let sockmap do the magic. */
  struct pollfd fds[1]{};
  fds[0].fd = fd;
  fds[0].events = POLLRDHUP;

  poll(fds, 1, -1);

  /* Was there a socket error? */
  {
    int err;
    socklen_t err_len = sizeof(err);
    r = getsockopt(fd, SOL_SOCKET, SO_ERROR, &err, &err_len);
    if (r < 0) {
      throw std::logic_error("getsockopt()");
    }
    errno = err;
    if (errno) {
      throw std::logic_error("sockmap fd");
    }
  }

  /* Cleanup the entry from sockmap. */
  idx = 0;
  r = tbpf_map_delete_elem(sock_map_, &idx);
  if (r != 0) {
    if (errno == EINVAL) {
      std::cerr << "[-] Removing closed sock from sockmap\n";
    } else {
      throw std::logic_error("bpf(MAP_DELETE_ELEM, sock_map)");
    }
  }
  close(fd);

}

void Session::splice_relay()
{
  int cd = in_socket_->native_handle();
  int fd_out = out_socket_.native_handle();

  int pfd[2];
  int r = pipe(pfd);
  if (r < 0) {
    throw std::logic_error("Create pipe() fails");
  }

  /* There is no "good" splice buffer size. Anecdotical evidence
   * says that it should be no larger than 512KiB since this is
   * the max we can expect realistically to fit into cpu
   * cache. */
#define SPLICE_MAX (512*1024)

  r = fcntl(pfd[0], F_SETPIPE_SZ, SPLICE_MAX);
  if (r < 0) {
    throw std::logic_error("Create fcntl() fails");
  }


  while (1) {
    /* This is fairly unfair. We are doing 512KiB buffer
     * in one go, as opposed to naive approaches. Cheating. */
    ssize_t n = splice(cd, nullptr, pfd[1], nullptr, static_cast<std::size_t>(SPLICE_MAX),
      SPLICE_F_MOVE);
    if (n < 0) {
      if (errno == ECONNRESET) {
        std::cerr << "[!] ECONNRESET\n";
        break;
      }
      if (errno == EAGAIN) {
        break;
      }
      throw std::logic_error("Create pipe() fails");
    }
    if (n == 0) {
      /* On TCP socket zero means EOF */
      std::cerr << "[-] edge side EOF\n";
      break;
    }

    ssize_t m = splice(pfd[0], nullptr, cd, nullptr, static_cast<std::size_t>(n), SPLICE_F_MOVE);
    if (m < 0) {
      if (errno == ECONNRESET) {
        std::cerr << "[!] ECONNRESET on origin\n";
        break;
      }
      if (errno == EPIPE) {
        std::cerr << "[!] EPIPE on origin\n";
        break;
      }
      throw std::logic_error("send() fails");
    }
    if (m == 0) {
      int err;
      socklen_t err_len = sizeof(err);
      int u = getsockopt(cd, SOL_SOCKET, SO_ERROR, &err,
        &err_len);
      if (u < 0) {
         throw std::logic_error("getsockopt()");
      }
      errno = err;
       throw std::logic_error("send()");
    }
    if (m != n) {
       throw std::logic_error("expecting splice to block");
    }
  }
}

void Session::iosubmit_relay()
{
  std::uint32_t cd = static_cast<std::uint32_t>(in_socket_->native_handle());
  int fd_out = out_socket_.native_handle();

  aio_context_t ctx = {0};
  int r = io_setup(8, &ctx);
  if (r < 0) {
    throw std::logic_error("io_setup()");
  }

#define BUFFER_SIZE (128 * 1024)
  char buf[BUFFER_SIZE];

  struct iocb cb[2];

  cb[0].aio_fildes = cd;
  cb[0].aio_lio_opcode = IOCB_CMD_PWRITE;
  cb[0].aio_buf = (uint64_t)buf;
  cb[0].aio_nbytes = 0;

  cb[1].aio_fildes = cd;
  cb[1].aio_lio_opcode = IOCB_CMD_PREAD;
  cb[1].aio_buf = (uint64_t)buf;
  cb[1].aio_nbytes = BUFFER_SIZE;

  struct iocb *list_of_iocb[2] = {&cb[0], &cb[1]};

  while (1) {
    // io_submit on blocking network sockets will
    // block. It will loop over sockets one by one,
    // blocking on each operation. We abuse this to do
    // write+read in one syscall. In first iteration the
    // write is empty, we do write of size 0.
    r = io_submit(ctx, 2, list_of_iocb);
    if (r != 2) {
        throw std::logic_error("io_submit()");
    }

    /* We must pick up the result, since we need to get
     * the number of bytes read. */
    struct io_event events[2] = {{0}};
    r = io_getevents(ctx, 1, 2, events, NULL);
    if (r < 0) {
        throw std::logic_error("io_getevents()");
    }
    if (events[0].res < 0) {
       errno = -events[0].res;
       perror("io_submit(IOCB_CMD_PWRITE)");
       break;
    }
    if (events[1].res < 0) {
       errno = -events[1].res;
       perror("io_submit(IOCB_CMD_PREAD)");
       break;
    }
    if (events[1].res == 0) {
       std::cerr << "[-] edge side EOF\n";
       break;
    }
    cb[0].aio_nbytes = events[1].res;
  }
}

void Session::read_client_tcp()
{
  auto self(shared_from_this());

  in_socket_->async_read_some(
    boost::asio::buffer(in_buf_),
    [this, self](const boost::system::error_code &error_code, std::size_t length)
    {
      if (!error_code)
      {
        boost::asio::async_write(
          out_socket_,
          boost::asio::buffer(in_buf_, length),
          [this, self](const boost::system::error_code &error_code, std::size_t /*n*/)
          {
            if (!error_code) {
              [this]{ read_client_tcp(); }();
            } else {
              BOOST_LOG_TRIVIAL(error) << "Session id: " << session_id_.id << " Write to out socket faild: " << error_code;
            }
          });
      }
      else
      {
        BOOST_LOG_TRIVIAL(error) << "Session id: " << session_id_.id << " Read faild from in socket: " <<  error_code;
        if(out_socket_.is_open()) {
          BOOST_LOG_TRIVIAL(error) << "Session id: " << session_id_.id << " Closing session. Close in socket";
          out_socket_.close();
        }
      }
    });
}
void Session::read_server_tcp()
{
  auto self(shared_from_this());

  out_socket_.async_read_some(
    boost::asio::buffer(out_buf_),
    [this, self](const boost::system::error_code &error_code, std::size_t length)
    {
      if (!error_code)
      {
        boost::asio::async_write(
          *in_socket_,
          boost::asio::buffer(out_buf_, length),
          [this, self](const boost::system::error_code &error_code, std::size_t /*n*/)
          {
            if (!error_code) {
              [this]{ read_server_tcp(); }();
            } else {
              BOOST_LOG_TRIVIAL(error) << "Session id: " << session_id_.id << " Write to in socket faild: " << error_code;
            }
          });
      }
      else
      {
        BOOST_LOG_TRIVIAL(error) << "Session id: " << session_id_.id << " Read faild from out socket. " << error_code;
        if(in_socket_->is_open()) {
          BOOST_LOG_TRIVIAL(error) << "Session id: " << session_id_.id << " Closing session. Close out socket";
          in_socket_->close();
        }

      }
    });
}



} // namespace socks5
