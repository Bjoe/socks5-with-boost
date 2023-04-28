#include <iostream>
#include <boost/program_options.hpp>
#include <boost/exception/diagnostic_information.hpp>
#include <boost/log/trivial.hpp>

#include <linux/bpf.h>
#include <sys/resource.h>
extern "C" {
  #include "sockmap/tbpf.h"
};
#include "server.hpp"

constexpr int BUFFER_SIZE = 8192;
constexpr int PORT = 1080;

extern size_t bpf_insn_prog_parser_cnt;
extern struct bpf_insn bpf_insn_prog_parser[];
extern struct tbpf_reloc bpf_reloc_prog_parser[];

extern size_t bpf_insn_prog_verdict_cnt;
extern struct bpf_insn bpf_insn_prog_verdict[];
extern struct tbpf_reloc bpf_reloc_prog_verdict[];

std::istream& operator>>(std::istream& in, Options& options)
{
  std::string token;
  in >> token;
  if (token == "tcp")
    options = Options::TCP_RELAY;
  else if (token == "iosubmit")
    options = Options::IOSUBMIT_RELAY;
  else if (token == "splice")
    options = Options::SPLICE_RELAY;
  else if (token == "sockmap")
    options = Options::SOCKMAP_RELAY;
  else
    in.setstate(std::ios_base::failbit);
  return in;
}

int main(int argc, char* argv[])
{
  try
  {
    boost::program_options::options_description desc{"Options"};
    desc.add_options()
      ("help,h", "Help screen")
      ("socks5_address,s", boost::program_options::value<std::string>(), "Local listen ip")
      ("nat_address,n", boost::program_options::value<std::string>(), "NAT ip address")
      ("port,p", boost::program_options::value<unsigned short>()->default_value(PORT), "Port")
      ("buffer_size,b", boost::program_options::value<std::size_t>()->default_value(BUFFER_SIZE), "Buffer size")
      ("relay,r", boost::program_options::value<Options>()->required(), "Relay option")
      ;

    boost::program_options::variables_map variables_map;
    store(parse_command_line(argc, argv, desc), variables_map);
    notify(variables_map);

    if (variables_map.count("help") != 0U) {
      std::cout << desc << '\n';
      return EXIT_SUCCESS;
    }

    if(variables_map.count("socks5_address") == 0U) {
      std::cerr << "Socks5 listen IP address is needed." << '\n';
      std::cout << desc << '\n';
      return EXIT_FAILURE;
    }

    if(variables_map.count("nat_address") == 0U) {
      std::cerr << "NAT IP address is needed." << '\n';
      std::cout << desc << '\n';
      return EXIT_FAILURE;
    }

    Options options = variables_map["relay"].as<Options>();
    const auto port = variables_map["port"].as<unsigned short>();
    const auto buffer_size = variables_map["buffer_size"].as<std::size_t>();
    auto socks5Address = variables_map["socks5_address"].as<std::string>();
    auto natAddress = variables_map["nat_address"].as<std::string>();

    const boost::asio::ip::tcp::endpoint socks5Endpoint{boost::asio::ip::address::from_string(socks5Address), port};

    int sock_map{};
    if(options == Options::SOCKMAP_RELAY) {
      /*
       * Initialize ebpf
       */
      /* [*] SOCKMAP requires more than 16MiB of locked mem */
      struct rlimit rlim;
      rlim.rlim_cur = 128 * 1024 * 1024;
      rlim.rlim_max = 128 * 1024 * 1024;

      /* ignore error */
      setrlimit(RLIMIT_MEMLOCK, &rlim);

      /* [*] Prepare ebpf */
      sock_map = tbpf_create_map(BPF_MAP_TYPE_SOCKMAP, sizeof(int),
        sizeof(int), 2, 0);
      if (sock_map < 0) {
        std::cerr << "bpf(BPF_MAP_CREATE, BPF_MAP_TYPE_SOCKMAP)\n";
        return EXIT_FAILURE;
      }

      /* sockmap is only used in prog_verdict */
      tbpf_fill_symbol(bpf_insn_prog_verdict, bpf_reloc_prog_verdict,
        "sock_map", sock_map);

      /* Load prog_parser and prog_verdict */
      char log_buf[16 * 1024];
      int bpf_parser = tbpf_load_program(
        BPF_PROG_TYPE_SK_SKB, bpf_insn_prog_parser,
        bpf_insn_prog_parser_cnt, "Dual BSD/GPL",
        KERNEL_VERSION(4, 4, 0), log_buf, sizeof(log_buf));
      if (bpf_parser < 0) {
        std::cerr << "Bpf Log:\n" << log_buf << "\n bpf(BPF_PROG_LOAD, prog_parser)\n";
        return EXIT_FAILURE;
      }

      int bpf_verdict = tbpf_load_program(
        BPF_PROG_TYPE_SK_SKB, bpf_insn_prog_verdict,
        bpf_insn_prog_verdict_cnt, "Dual BSD/GPL",
        KERNEL_VERSION(4, 4, 0), log_buf, sizeof(log_buf));
      if (bpf_verdict < 0) {
        std::cerr << "Bpf Log:\n" << log_buf << "\n bpf(BPF_PROG_LOAD, prog_verdict)\n";
        return EXIT_FAILURE;
      }

      /* Attach maps to programs. It's important to attach SOCKMAP
       * to both parser and verdict programs, even though in parser
       * we don't use it. The whole point is to make prog_parser
       * hooked to SOCKMAP.*/
      int r = tbpf_prog_attach(bpf_parser, sock_map, BPF_SK_SKB_STREAM_PARSER,
        0);
      if (r < 0) {
        std::cerr << "bpf(PROG_ATTACH)\n";
        return EXIT_FAILURE;
      }

      r = tbpf_prog_attach(bpf_verdict, sock_map, BPF_SK_SKB_STREAM_VERDICT,
        0);
      if (r < 0) {
        std::cerr << "bpf(PROG_ATTACH)\n";
        return EXIT_FAILURE;
      }
      /*************************************************************************/
    }

    boost::asio::io_context io_context{};
    boost::asio::signal_set signals{io_context, SIGINT, SIGTERM};
    signals.async_wait([&io_context](const boost::system::error_code&, const int&){
      io_context.stop();
    });

    socks5::Server server(io_context, sock_map, socks5Endpoint, natAddress, buffer_size, options);
    server.start();

    boost::asio::signal_set signalsUser{io_context, SIGUSR1};
    signals.async_wait([&server](const boost::system::error_code&, const int&){
      server.close();
    });

    io_context.run();
  }
  catch (std::exception& e)
  {
    std::cerr << e.what();
  }
  catch (...)
  {
    std::cerr << boost::current_exception_diagnostic_information();
  }

  return EXIT_SUCCESS;
}
