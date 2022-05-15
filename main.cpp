#include <iostream>
#include <iomanip>
#include <sstream>
#include <string>
#include <fstream>
#include <cctype>
#include <vector>
#include <map>
#include <future>

//Requires libssl-dev library to be installed: sudo apt-get install libssl-dev
#include <openssl/sha.h>

#include "./bcryptLib/bcrypt.h"

namespace userSelection {
    char algo; //b=bcrypt, s=sha256
    std::string inputHash;
    char mode; //d=dict, v=variants, c=combinations
    std::string salt = "";
}

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

void checkGuess( const std::string guess)
{
    //Append salt given by user to end of guess. if user gave no salt, this is empty.
    std::string saltedGuess = guess + userSelection::salt;

    if (userSelection::algo == 'b')
    {
        int ret;
        ret = bcrypt_checkpw(saltedGuess.c_str(), userSelection::inputHash.c_str());
        if (ret == 0)
        {
            std::cout << "Match found! Password is " << guess << std::endl;
            exit(EXIT_SUCCESS);
        }
    }
    else if (userSelection::algo == 's')
    {
        if (sha256(saltedGuess) == userSelection::inputHash)
        {
            std::cout << "Match found! Password is " << guess << std::endl;
            exit(EXIT_SUCCESS);
        }
    }
}

void askInputHash()
{
    std::string filename_hashIn;
    std::cout << "File of input hash: ";
    std::cin >> filename_hashIn;
    std::cout << std::endl;

    std::fstream hashfile;
    hashfile.open(filename_hashIn, std::ios::in);
    if (hashfile.is_open())
    {
        std::getline(hashfile, userSelection::inputHash);
        hashfile.close();
    }
    else {
        std::cout << "ERROR: unable to open file " << filename_hashIn << std::endl;
        exit(EXIT_FAILURE);
    }

}

void askSaltFile()
{
    std::string filenameSalt;
    std::cout << "File of salt: " << std::endl;
    std::cin >> filenameSalt;
    std::cout << std::endl;

    std::fstream saltfile;
    saltfile.open(filenameSalt, std::ios::in);
    if (saltfile.is_open())
    {
        std::getline(saltfile, userSelection::salt);
        saltfile.close();
    }
    else {
        std::cout << "ERROR: unable to open file " << filenameSalt << std::endl;
        exit(EXIT_FAILURE);
    }

}

void searchFromPasswordFile()
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
            checkGuess(tp);
        }
        std::cout << "No match found in file " << pwFilename << std::endl;
        std::cout << "Last item checked was: " << tp << std::endl;
        pwfile.close();
        return;
    }
    std::cout << "Unable to read file " << pwFilename << std::endl;
    return;
}

void generateVariants(const std::string original, std::vector<std::string> &variants)
{
    variants.push_back(original);
    // Add version with first letter capitalized
    std::string modifiedString = original;
    modifiedString[0] = std::toupper(modifiedString[0]);
    variants.push_back(modifiedString);

    // Replace letters with numbers
    const std::map<char, char> charAsNumber = {{'a', '4'}, {'e', '3'}, {'i', '1'}, {'o', '0'}, {'t', '7'}, {'s', '5'}};

    int originalCount = variants.size();
    for (int i = 0; i < originalCount; ++i)
    {
        modifiedString = variants[i];
        for (int j = 0; j < modifiedString.length(); ++j)
        {
            if (charAsNumber.find(modifiedString[j]) != charAsNumber.end())
            {
                modifiedString[j] = charAsNumber.at(modifiedString[j]);
                variants.push_back(modifiedString);
            }
        }
    }

    // Add common endings
    const std::vector<std::string> commonEnds = {"1", "11", "12", "123", "1234", "0", "00", "789", "!" ,"!!", "?"};
    originalCount = variants.size();
    for (int i = 0; i < originalCount; ++i)
    {
        for (auto& ending : commonEnds) {
            variants.push_back( variants[i] + ending);
        }
    }
    return;
}

void generateAndCheckVariants( std::string baseGuess)
{

    // Make variants and check them
    std::vector<std::string> variants;
    variants.clear();
    generateVariants(baseGuess, variants);
    for (auto &variant : variants)
    {
        //std::cout << variant << std::endl;
        checkGuess(variant);
    }
    return;
}

void searchFromFileAndModify()
{
    std::string pwFilename;
    std::cout << "Name of passwordlist file: ";
    std::cin >> pwFilename;
    std::cout << std::endl;

    std::ifstream pwfile(pwFilename);
    if (pwfile.is_open())
    {
        std::string tp;

        auto start = std::chrono::steady_clock::now().time_since_epoch();
        while (std::getline(pwfile, tp))
        {
            // Generate variants and calculate hashes for them using multiple threads.
            // Async is high-level construct for managing this.
             //std::async(generateAndCheckVariants, tp );

             generateAndCheckVariants(tp);
        }

        auto stop = std::chrono::steady_clock::now().time_since_epoch();
        auto elapsed = (stop-start);
        std::cout << "Time spent generating and checking variants: " << std::chrono::duration_cast<std::chrono::milliseconds>(elapsed).count() << " ms" << std::endl;

        std::cout << "No match based on initial guesses in file " << pwFilename << std::endl;
        pwfile.close();
        return;
    }
    std::cout << "Unable to read file " << pwFilename << std::endl;
    return;
}

int main() {
    
    askInputHash();
    std::cout << "Hash to search for is " << userSelection::inputHash << std::endl;

    std::cout << "Select algorithm: [s]ha256 or [b]crypt " << std::endl;
    std::cin >> userSelection::algo;
    std::cout << std::endl;

    std::cout << "Select cracking mode: [d]ictionary attack   [v]ariants " << std::endl;
    std::cin >> userSelection::mode;
    std::cout << std::endl;

    if (userSelection::algo == 's') {
            std::cout << "Use salt? [y]es or [n]o" << std::endl;
            char useSalt;
            std::cin >> useSalt;
            if (useSalt == 'y')
            {
                askSaltFile();
                std::cout << "Salt added to guesses is: " << userSelection::salt << std::endl;
            }
    }


    if (userSelection::mode == 'd') {
        searchFromPasswordFile();
    }
    else if (userSelection::mode == 'v') {
        searchFromFileAndModify();
    }
    

    return 0;
}