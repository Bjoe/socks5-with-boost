#include <iostream>
#include <boost/program_options.hpp>
#include <boost/exception/diagnostic_information.hpp>
#include <boost/log/trivial.hpp>

#include "server.hpp"

constexpr int BUFFER_SIZE = 8192;
constexpr int PORT = 1080;

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

        const auto port = variables_map["port"].as<unsigned short>();
        const auto buffer_size = variables_map["buffer_size"].as<std::size_t>();
        auto socks5Address = variables_map["socks5_address"].as<std::string>();
        auto natAddress = variables_map["nat_address"].as<std::string>();

        const boost::asio::ip::tcp::endpoint socks5Endpoint{boost::asio::ip::address::from_string(socks5Address), port};

        boost::asio::io_context io_context{};
        boost::asio::signal_set signals{io_context, SIGINT, SIGTERM};
        signals.async_wait([&io_context](const boost::system::error_code&, const int&){
            io_context.stop();
        });

        socks5::Server server(io_context, socks5Endpoint, natAddress, buffer_size);
        server.start();

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
