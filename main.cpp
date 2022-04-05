#include <iostream>
#include <iomanip>
#include <sstream>
#include <string>
#include <fstream>


#include <openssl/sha.h>

std::string sha256(const std::string str)
{
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, str.c_str(), str.size());
    SHA256_Final(hash, &sha256);
    std::stringstream ss;
    for(int i = 0; i < SHA256_DIGEST_LENGTH; i++)
    {
        ss << std::hex << std::setw(2) << std::setfill('0') << (int)hash[i];
    }
    return ss.str();
}

std::string askInputHash()
{
    std::string hashStr;
    std::string filename_hashIn;
    std::cout << "File of input hash: ";
    std::cin >> filename_hashIn;
    std::cout << std::endl;

    std::fstream hashfile;
    hashfile.open(filename_hashIn, std::ios::in);
    if (hashfile.is_open())
    {
        std::getline(hashfile, hashStr);
        hashfile.close();
    }
    return hashStr;

}

void searchFromPasswordFile(std::string inputHash)
{
    std::string pwFilename;
    std::cout << "Name of passwordlist file: ";
    std::cin >> pwFilename;
    std::cout << std::endl;

    std::ifstream pwfile(pwFilename);
    if (pwfile.is_open())
    {
        std::string tp;
        while (std::getline(pwfile, tp))
        {
            if (sha256(tp) == inputHash)
            {
                std::cout << "Match found! Password is " << tp << std::endl;
                pwfile.close();
                return;
            }
        }
        std::cout << "No match found in file " << pwFilename << std::endl;
        std::cout << "Last item checked was: " << tp << std::endl;
        pwfile.close();
        return;
    }
    std::cout << "Unable to read file " << pwFilename << std::endl;
    return;
}

int main() {
    
    std::string hashIn = askInputHash();
    std::cout << "Hash to search for is " << hashIn << std::endl;
    searchFromPasswordFile(hashIn);


    // std::cout << sha256("1234567890_1") << std::endl;
    // std::cout << sha256("1234567890_2") << std::endl;
    // std::cout << sha256("1234567890_3") << std::endl;
    // std::cout << sha256("1234567890_4") << std::endl;
    // std::cout << sha256("password") << std::endl;
    // std::cout << sha256("p4ssword") << std::endl;
    return 0;
}