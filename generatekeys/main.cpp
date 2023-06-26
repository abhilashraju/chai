#include <utils/command_line_parser.hpp>
#include <utils/sslsignutility.hpp>
int main(int argc, const char* argv[])
{
    using namespace chai;
    auto [filename] = getArgs(parseCommandline(argc, argv), "-o");
    if (filename.empty())
    {
        std::cout << "missing arguments \n";
        std::cout << "generatekeys -o outputfile \n";
        return -1;
    }
    try
    {
        generateCakeypairs(filename);
    }
    catch (std::exception& e)
    {
        std::cout << e.what() << "\n";
    }
    return 0;
}