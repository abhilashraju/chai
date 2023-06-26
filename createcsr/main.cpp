#include <utils/command_line_parser.hpp>
#include <utils/sslsignutility.hpp>
int main(int argc, const char* argv[])
{
    using namespace chai;
    auto [csrPath, subject] = getArgs(parseCommandline(argc, argv), "-o", "-s");
    if (csrPath.empty() || subject.empty())
    {
        std::cout << "missing arguments \n";
        std::cout << "createcert -o outputpath -s subject\n";
        return -1;
    }
    try
    {
        generateCSRFile(subject, csrPath);
    }
    catch (std::exception& e)
    {
        std::cout << e.what() << "\n";
    }
    return 0;
}