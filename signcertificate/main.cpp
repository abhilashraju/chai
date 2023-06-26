#include <utils/command_line_parser.hpp>
#include <utils/sslsignutility.hpp>
int main(int argc, const char* argv[])
{
    using namespace chai;
    auto [caPrivateKeyPath, csrFilePath, signedCertPath] =
        getArgs(parseCommandline(argc, argv), "-p", "-c", "-o");
    if (caPrivateKeyPath.empty() || csrFilePath.empty() ||
        signedCertPath.empty())
    {
        std::cout << "missing arguments \n";
        std::cout
            << "signcert -p private_key_file_path -c csr_file_path -o output_file_path \n";
        return -1;
    }
    try
    {
        signCertificate(caPrivateKeyPath, csrFilePath, signedCertPath);
    }
    catch (std::exception& e)
    {
        std::cout << e.what() << "\n";
    }
    return 0;
}