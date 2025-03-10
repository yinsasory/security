#include <iostream>
#include <fstream>
#include <vector>
#include <memory>
#include <thread>
#include <future>
#include <filesystem>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <stdexcept>
#include <zlib.h>
#include <cstring>
#include <cxxopts.hpp>

namespace fs = std::filesystem;

class SecureFileHandler
{
private:
    std::vector<unsigned char> encryption_key;
    static constexpr int IV_SIZE = 12;
    static constexpr int TAG_SIZE = 16;
    const size_t BUFFER_SIZE;

    struct FileRAII
    {
        std::ifstream infile;
        std::ofstream outfile;
        std::string output_temp;
        bool success;

        FileRAII(const std::string &in, const std::string &out)
            : infile(in, std::ios::binary), output_temp(out + ".tmp"), success(false)
        {
            outfile.open(output_temp, std::ios::binary);
            if (!infile.is_open())
                throw std::runtime_error("Failed to open input file: " + in);
            if (!outfile.is_open())
                throw std::runtime_error("Failed to create temporary output file: " + out);
        }

        ~FileRAII()
        {
            infile.close();
            outfile.close();
            if (success)
            {
                try
                {
                    fs::rename(output_temp, output_temp.substr(0, output_temp.size() - 4));
                }
                catch (const fs::filesystem_error &e)
                {
                    fs::remove(output_temp);
                    throw std::runtime_error("Failed to rename temporary file: " + std::string(e.what()));
                }
            }
            else
            {
                fs::remove(output_temp);
            }
        }
    };

public:
    explicit SecureFileHandler(const std::vector<unsigned char> &key, size_t buffer_size = 256 * 1024)
        : encryption_key(key), BUFFER_SIZE(buffer_size)
    {
        if (key.size() != 16 && key.size() != 24 && key.size() != 32)
        {
            throw std::invalid_argument("Invalid key size. Key must be 16, 24, or 32 bytes.");
        }
    }

    ~SecureFileHandler()
    {
        std::fill(encryption_key.begin(), encryption_key.end(), 0);
    }

    void encrypt_decrypt_file(const std::string &input_filename, const std::string &output_filename,
                              bool encrypt, bool compress = false, const std::vector<unsigned char> &aad = {})
    {
        if (fs::exists(output_filename))
            throw std::runtime_error("Output file already exists: " + output_filename);
        if (fs::file_size(input_filename) == 0)
            throw std::runtime_error("Input file is empty: " + input_filename);

        FileRAII files(input_filename, output_filename);
        std::vector<unsigned char> iv(IV_SIZE);
        std::vector<unsigned char> tag(TAG_SIZE);

        auto ctx = std::unique_ptr<EVP_CIPHER_CTX, decltype(&EVP_CIPHER_CTX_free)>(EVP_CIPHER_CTX_new(), EVP_CIPHER_CTX_free);
        if (!ctx)
            throw std::runtime_error("Cipher context creation failed.");

        if (encrypt)
        {
            if (RAND_bytes(iv.data(), IV_SIZE) != 1)
                throw std::runtime_error("Error generating IV.");
            files.outfile.write(reinterpret_cast<char *>(iv.data()), IV_SIZE);
        }
        else
        {
            files.infile.read(reinterpret_cast<char *>(iv.data()), IV_SIZE);
            if (files.infile.gcount() != IV_SIZE)
                throw std::runtime_error("Invalid file format: Missing IV.");
            files.infile.seekg(-TAG_SIZE, std::ios::end);
            files.infile.read(reinterpret_cast<char *>(tag.data()), TAG_SIZE);
            files.infile.seekg(IV_SIZE, std::ios::beg);
            if (EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_SET_TAG, TAG_SIZE, tag.data()) != 1)
            {
                throw std::runtime_error("Invalid authentication tag.");
            }
        }

        if (EVP_CipherInit_ex(ctx.get(), EVP_aes_256_gcm(), nullptr, encryption_key.data(), iv.data(), encrypt) != 1)
        {
            throw std::runtime_error("Cipher initialization failed.");
        }

        if (!aad.empty())
        {
            int aad_len;
            if (EVP_CipherUpdate(ctx.get(), nullptr, &aad_len, aad.data(), aad.size()) != 1)
            {
                throw std::runtime_error("Error processing AAD.");
            }
        }

        std::vector<unsigned char> buffer(BUFFER_SIZE);
        std::vector<unsigned char> out_buffer(BUFFER_SIZE + EVP_CIPHER_block_size(EVP_aes_256_gcm()));
        std::vector<unsigned char> compressed_data;
        int out_len;

        if (!encrypt && compress)
        {
            while (files.infile.read(reinterpret_cast<char *>(buffer.data()), buffer.size()) || files.infile.gcount() > 0)
            {
                int bytes_read = files.infile.gcount();
                if (EVP_CipherUpdate(ctx.get(), out_buffer.data(), &out_len, buffer.data(), bytes_read) != 1)
                {
                    throw std::runtime_error("Decryption failed.");
                }
                compressed_data.insert(compressed_data.end(), out_buffer.begin(), out_buffer.begin() + out_len);
            }
            if (EVP_CipherFinal_ex(ctx.get(), out_buffer.data(), &out_len) != 1)
            {
                throw std::runtime_error("Final cipher step failed.");
            }
            compressed_data.insert(compressed_data.end(), out_buffer.begin(), out_buffer.begin() + out_len);
            auto decompressed_data = decompress_data(compressed_data);
            files.outfile.write(reinterpret_cast<char *>(decompressed_data.data()), decompressed_data.size());
        }
        else
        {
            while (files.infile.read(reinterpret_cast<char *>(buffer.data()), buffer.size()) || files.infile.gcount() > 0)
            {
                int bytes_read = files.infile.gcount();
                if (encrypt && compress)
                {
                    buffer = compress_data({buffer.data(), static_cast<size_t>(bytes_read)});
                    bytes_read = buffer.size();
                }
                if (EVP_CipherUpdate(ctx.get(), out_buffer.data(), &out_len, buffer.data(), bytes_read) != 1)
                {
                    throw std::runtime_error(encrypt ? "Encryption failed." : "Decryption failed.");
                }
                files.outfile.write(reinterpret_cast<char *>(out_buffer.data()), out_len);
            }
            if (EVP_CipherFinal_ex(ctx.get(), out_buffer.data(), &out_len) != 1)
            {
                throw std::runtime_error("Final cipher step failed.");
            }
            files.outfile.write(reinterpret_cast<char *>(out_buffer.data()), out_len);
        }

        if (encrypt)
        {
            if (EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_GET_TAG, TAG_SIZE, tag.data()) != 1)
            {
                throw std::runtime_error("Error getting authentication tag.");
            }
            files.outfile.write(reinterpret_cast<char *>(tag.data()), TAG_SIZE);
        }

        files.success = true;
    }

    void encrypt_decrypt_directory(const std::string &input_dir, const std::string &output_dir,
                                   bool encrypt, bool compress = false)
    {
        std::vector<std::future<void>> futures;
        const size_t thread_count = std::thread::hardware_concurrency();

        for (const auto &entry : fs::recursive_directory_iterator(input_dir))
        {
            if (entry.is_regular_file())
            {
                std::string relative_path = fs::relative(entry.path(), input_dir).string();
                std::string output_file = fs::path(output_dir) / relative_path;
                if (encrypt)
                    output_file += ".enc";
                fs::create_directories(fs::path(output_file).parent_path());

                futures.push_back(std::async(std::launch::async, [this, entry, output_file, encrypt, compress]()
                                             {
                    try {
                        encrypt_decrypt_file(entry.path().string(), output_file, encrypt, compress);
                        std::cout << "Processed: " << entry.path() << " -> " << output_file << std::endl;
                    } catch (const std::exception& e) {
                        std::cerr << "Error processing " << entry.path() << ": " << e.what() << std::endl;
                    } }));

                if (futures.size() >= thread_count)
                {
                    for (auto &f : futures)
                        f.get();
                    futures.clear();
                }
            }
        }
        for (auto &f : futures)
            f.get();
    }

    static std::vector<unsigned char> generate_random_key(size_t key_size = 32)
    {
        std::vector<unsigned char> key(key_size);
        if (RAND_bytes(key.data(), key_size) != 1)
        {
            throw std::runtime_error("Error generating encryption key.");
        }
        return key;
    }

    static void save_key_to_file(const std::string &filename, const std::vector<unsigned char> &key)
    {
        std::ofstream keyfile(filename, std::ios::binary);
        if (!keyfile)
            throw std::runtime_error("Failed to open key file for writing: " + filename);
        keyfile.write(reinterpret_cast<const char *>(key.data()), key.size());
    }

    static std::vector<unsigned char> load_key_from_file(const std::string &filename)
    {
        std::ifstream keyfile(filename, std::ios::binary);
        if (!keyfile)
            throw std::runtime_error("Failed to open key file for reading: " + filename);
        keyfile.seekg(0, std::ios::end);
        size_t size = keyfile.tellg();
        if (size != 16 && size != 24 && size != 32)
            throw std::runtime_error("Invalid key size in file: " + filename);
        std::vector<unsigned char> key(size);
        keyfile.seekg(0, std::ios::beg);
        keyfile.read(reinterpret_cast<char *>(key.data()), size);
        return key;
    }

    static std::string sha256_hash(const std::string &filename)
    {
        std::ifstream file(filename, std::ios::binary);
        if (!file)
            throw std::runtime_error("Cannot open file for hashing: " + filename);

        SHA256_CTX sha256;
        SHA256_Init(&sha256);
        std::vector<unsigned char> buffer(8192); // Tăng buffer lên 8KB
        while (file.read(reinterpret_cast<char *>(buffer.data()), buffer.size()) || file.gcount() > 0)
        {
            SHA256_Update(&sha256, buffer.data(), file.gcount());
        }
        std::vector<unsigned char> hash(SHA256_DIGEST_LENGTH);
        SHA256_Final(hash.data(), &sha256);
        std::ostringstream result;
        for (unsigned char byte : hash)
        {
            result << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(byte);
        }
        return result.str();
    }

    static std::vector<unsigned char> encrypt_key_with_rsa(const std::vector<unsigned char> &key, const std::string &public_key_file)
    {
        auto rsa = std::unique_ptr<RSA, decltype(&RSA_free)>(PEM_read_RSA_PublicKey(fopen(public_key_file.c_str(), "r"), nullptr, nullptr, nullptr), RSA_free);
        if (!rsa)
            throw std::runtime_error("Failed to load RSA public key from " + public_key_file);

        std::vector<unsigned char> encrypted_key(RSA_size(rsa.get()));
        int encrypted_len = RSA_public_encrypt(key.size(), key.data(), encrypted_key.data(), rsa.get(), RSA_PKCS1_OAEP_PADDING);
        if (encrypted_len == -1)
            throw std::runtime_error("RSA encryption failed.");
        encrypted_key.resize(encrypted_len);
        return encrypted_key;
    }

    static std::vector<unsigned char> decrypt_key_with_rsa(const std::vector<unsigned char> &encrypted_key, const std::string &private_key_file)
    {
        auto rsa = std::unique_ptr<RSA, decltype(&RSA_free)>(PEM_read_RSAPrivateKey(fopen(private_key_file.c_str(), "r"), nullptr, nullptr, nullptr), RSA_free);
        if (!rsa)
            throw std::runtime_error("Failed to load RSA private key from " + private_key_file);

        std::vector<unsigned char> decrypted_key(RSA_size(rsa.get()));
        int decrypted_len = RSA_private_decrypt(encrypted_key.size(), encrypted_key.data(), decrypted_key.data(), rsa.get(), RSA_PKCS1_OAEP_PADDING);
        if (decrypted_len == -1)
            throw std::runtime_error("RSA decryption failed.");
        decrypted_key.resize(decrypted_len);
        return decrypted_key;
    }

private:
    static std::vector<unsigned char> compress_data(const std::vector<unsigned char> &data)
    {
        uLongf compressed_size = compressBound(data.size());
        std::vector<unsigned char> compressed_data(compressed_size + sizeof(uLong));
        std::memcpy(compressed_data.data(), &data.size(), sizeof(uLong));
        if (compress(compressed_data.data() + sizeof(uLong), &compressed_size, data.data(), data.size()) != Z_OK)
        {
            throw std::runtime_error("Compression failed.");
        }
        compressed_data.resize(compressed_size + sizeof(uLong));
        return compressed_data;
    }

    static std::vector<unsigned char> decompress_data(const std::vector<unsigned char> &compressed_data)
    {
        if (compressed_data.size() < sizeof(uLong))
            throw std::runtime_error("Invalid compressed data.");
        uLong original_size;
        std::memcpy(&original_size, compressed_data.data(), sizeof(uLong));
        std::vector<unsigned char> decompressed_data(original_size);
        uLongf decompressed_size = original_size;
        if (uncompress(decompressed_data.data(), &decompressed_size, compressed_data.data() + sizeof(uLong),
                       compressed_data.size() - sizeof(uLong)) != Z_OK ||
            decompressed_size != original_size)
        {
            throw std::runtime_error("Decompression failed.");
        }
        return decompressed_data;
    }
};

int main(int argc, char *argv[])
{
    cxxopts::Options options("SecureFile", "A secure file encryption/decryption tool");
    options.add_options()("gen-key", "Generate and save a new AES key", cxxopts::value<std::string>())("e,encrypt", "Encrypt a file or directory", cxxopts::value<std::string>())("d,decrypt", "Decrypt a file or directory", cxxopts::value<std::string>())("o,output", "Output file or directory", cxxopts::value<std::string>())("k,keyfile", "AES key file", cxxopts::value<std::string>())("p,pubkey", "RSA public key file for key encryption", cxxopts::value<std::string>())("r,privkey", "RSA private key file for key decryption", cxxopts::value<std::string>())("c,compress", "Enable compression", cxxopts::value<bool>()->default_value("false"))("hash", "Calculate SHA-256 hash of a file", cxxopts::value<std::string>())("h,help", "Print usage");

    try
    {
        auto result = options.parse(argc, argv);

        if (result.count("help") || (result.count("gen-key") + result.count("encrypt") + result.count("decrypt") + result.count("hash") == 0))
        {
            std::cout << options.help() << std::endl;
            return 0;
        }

        if (result.count("gen-key"))
        {
            std::string keyfile = result["gen-key"].as<std::string>();
            auto key = SecureFileHandler::generate_random_key();
            if (result.count("pubkey"))
            {
                std::string pubkey_file = result["pubkey"].as<std::string>();
                auto encrypted_key = SecureFileHandler::encrypt_key_with_rsa(key, pubkey_file);
                SecureFileHandler::save_key_to_file(keyfile, encrypted_key);
                std::cout << "Generated and encrypted key saved to " << keyfile << std::endl;
            }
            else
            {
                SecureFileHandler::save_key_to_file(keyfile, key);
                std::cout << "Generated key saved to " << keyfile << std::endl;
            }
            return 0;
        }

        if (result.count("hash"))
        {
            std::string filename = result["hash"].as<std::string>();
            std::string hash = SecureFileHandler::sha256_hash(filename);
            std::cout << "SHA-256 hash of " << filename << ": " << hash << std::endl;
            return 0;
        }

        if (!result.count("keyfile"))
            throw std::runtime_error("Key file is required for encryption/decryption.");
        std::string keyfile = result["keyfile"].as<std::string>();
        std::vector<unsigned char> key;

        if (result.count("privkey"))
        {
            std::string privkey_file = result["privkey"].as<std::string>();
            auto encrypted_key = SecureFileHandler::load_key_from_file(keyfile);
            key = SecureFileHandler::decrypt_key_with_rsa(encrypted_key, privkey_file);
        }
        else
        {
            key = SecureFileHandler::load_key_from_file(keyfile);
        }

        SecureFileHandler fileHandler(key);
        bool encrypt = result.count("encrypt") > 0;
        std::string input = encrypt ? result["encrypt"].as<std::string>() : result["decrypt"].as<std::string>();
        std::string output = result["output"].as<std::string>();
        bool compress = result["compress"].as<bool>();

        if (output.empty())
        {
            output = encrypt ? input + ".enc" : input.substr(0, input.size() - 4);
        }

        if (fs::is_directory(input))
        {
            fileHandler.encrypt_decrypt_directory(input, output, encrypt, compress);
        }
        else
        {
            fileHandler.encrypt_decrypt_file(input, output, encrypt, compress);
            std::cout << "Processed: " << input << " -> " << output << std::endl;
            std::cout << "Input hash: " << SecureFileHandler::sha256_hash(input) << std::endl;
            std::cout << "Output hash: " << SecureFileHandler::sha256_hash(output) << std::endl;
        }
    }
    catch (const std::exception &e)
    {
        std::cerr << "Error: " << e.what() << std::endl;
        return 1;
    }

    return 0;
}