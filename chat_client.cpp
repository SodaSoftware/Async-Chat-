#include <iostream>
#include <boost/asio.hpp>
#include <memory>
#include <fstream>
#include <mutex>
#include <thread>
#include <filesystem>
#include <cryptopp/aes.h>
#include <cryptopp/filters.h>
#include <cryptopp/gcm.h>
#include <cryptopp/osrng.h>
#include <cryptopp/rsa.h>
#include <cryptopp/hex.h>

using namespace CryptoPP;
//доделать постоянное чтение сообщений, добавить парсинг чтобы отображалось имя отправителя +

class Info
{
private:
    std::string username;
    std::string command;
    std::string chat_name;
    std::string password;

public:
    void set_username(std::string str)
    {
        username = str;
    }

    void set_chat_name(std::string str)
    {
        chat_name = str;
    }

    void set_command(std::string str)
    {
        command = str;
    }

    void set_password(std::string str)
    {
        password = str;
    }

    std::string& get_username()
    {
        return username;
    }


    std::string& get_chat_name()
    {
        return chat_name;
    }


    std::string& get_command()
    {
        return command;
    }

    std::string& get_password()
    {
        return password;
    }

    void print()
    {
        std::cout << "Your name " << username << ": Name of your chat " << chat_name << "\n";
    }
};


Info client_info;


// команды для чата

 // имя нужного чата, если значеник равно / то выводится список чатов

std::string AES_Encr(std::string msg, byte key[32], byte iv[16])
{

    CryptoPP::GCM<CryptoPP::AES>::Encryption encr;

   encr.SetKeyWithIV(key, 32, iv);

   std::string out_str;
   CryptoPP::StringSource src(msg, true, new CryptoPP::AuthenticatedEncryptionFilter(encr, new CryptoPP::StringSink(out_str)));

   return out_str;
}

std::string AES_Decr(std::string msg, byte key2[32], byte iv2[16])
{
    
   CryptoPP::GCM<CryptoPP::AES>::Decryption decr;

   decr.SetKeyWithIV(key2, 32, iv2);

   std::string decr_str;

   CryptoPP::StringSource(msg, true, new CryptoPP::AuthenticatedDecryptionFilter(decr, new CryptoPP::StringSink(decr_str)));

   return decr_str;
}

std::string RSA_Encr(std::string msg, RSA::PublicKey pubKey)
{
    RSAES_OAEP_SHA_Encryptor encr(pubKey);

    std::string encr_str;
    AutoSeededRandomPool rng;

    StringSource str_src(msg, true, new PK_EncryptorFilter(rng, encr, new StringSink(encr_str)));

    return encr_str;
}

std::string RSA_Decr(std::string msg, RSA::PrivateKey prKey)
{
    RSAES_OAEP_SHA_Decryptor decr(prKey);

    std::string decr_str;
    AutoSeededRandomPool rng;

    StringSource str_src(msg, true, new PK_DecryptorFilter(rng, decr, new StringSink(decr_str)));

    return decr_str;
}

std::string Hex_Encr(std::string msg)
{
    std::string hex_str;
    StringSource str_ss(msg, true, new HexEncoder(new StringSink(hex_str)));

    return hex_str;
}

std::string Hex_Decr(std::string msg)
{
    std::string str;
    StringSource str_ss(msg, true, new HexDecoder(new StringSink(str)));

    return str;
}


std::pair<CryptoPP::SecByteBlock, std::string> parsing_raw_message(std::string raw_message)
{
    if (raw_message.size() <= 32)
    {
        throw std::invalid_argument("Error: message doesn`t include Initialising Vector(IV)");
    }
    std::string iv = Hex_Decr(raw_message.substr(0, 32));
    //std::cout << "IV size - " << iv.size() << ": IV - " << iv << "\n";
    std::string message = Hex_Decr(raw_message.substr(32));
    //std::cout << message <<  " - message\n";


    return std::pair<CryptoPP::SecByteBlock, std::string> (CryptoPP::SecByteBlock(reinterpret_cast<const byte*>(iv.data()), iv.size()), message);
}

void check_msg(boost::asio::ip::tcp::socket &sock, SecByteBlock &s_key) //доделать обработку входящих сообщений
{
    std::shared_ptr<boost::asio::streambuf> buf = std::make_shared<boost::asio::streambuf>();
    
    //sock_mtx.lock();
    //std::cout << "Read start\n";
    boost::asio::async_read_until(sock, *buf, '\n', [buf, &sock, &s_key](boost::system::error_code er, size_t bytes_transfered){
        
        if (!er)
        {
            //std::cout << "Read end\n";
            std::istream bufread(buf.get());

            std::string msg_raw;
            std::getline(bufread, msg_raw);

            auto msg_pair = parsing_raw_message(msg_raw);

            std::string msg = AES_Decr(msg_pair.second, s_key, msg_pair.first);

            int ind = msg.find(":");
            std::string filename(msg.substr(0, ind)+".txt");
            std::fstream log(client_info.get_username()+"/"+filename, std::fstream::app);
            msg += "\n";
            log.write(msg.data(), msg.length());
            log.close();

            
            if (client_info.get_chat_name() == msg.substr(0, ind))
            {
                std::cout << msg;
            }
            //cout.lock();
            //std::cout << msg;
            //cout.unlock();

            check_msg(sock, s_key);
        }
        else{
            std::cout << er.message() << "\n";
        }

    });
}


std::string file_read(std::string filedir_name, bool write_strings)
{
    //std::cout << filedir_name << "\n";
    std::fstream file(filedir_name);
    std::string file_source;
    std::string buf = "";

    if (write_strings)
    {
        std::getline(file, buf);
        while(std::getline(file, buf))
        {
            std::cout << buf << "\n";
            file_source += buf;
        }
    }
    else
    {
        std::getline(file, buf);
        while(std::getline(file, buf))
        {
            file_source += buf;
        }
        file.close();
    }
    //std::cout << "read end\n";

    return file_source;
}


void write_chats()
{
    std::cout << "\033[2J\033[1;1H";
    client_info.set_chat_name("/");
        //вывод всех чатов
        //{
    std::cout << "Contacts: \n";
    file_read(std::string(client_info.get_username()+"/chats.txt"), 1);

        //}
}


std::string make_msg(std::string msg, SecByteBlock msg_key)
{
    AutoSeededRandomPool rng;
    SecByteBlock msg_iv(16);
    rng.GenerateBlock(msg_iv, 16);

    std::string encr_msg = AES_Encr(msg, msg_key, msg_iv);

    std::string encr_full_msg(std::string(reinterpret_cast<const char*>(msg_iv.BytePtr()), msg_iv.size())+encr_msg);

    std::string hex_msg = Hex_Encr(encr_full_msg)+"\n";

    return hex_msg;
}

void send_msg(boost::asio::ip::tcp::socket &sock, SecByteBlock seance_key)
{
            //std::cout << "Print message:\n";
        //cout.unlock();
        //std::getline(std::cin , msg);

        std::string send_msg("/n"+client_info.get_chat_name()+"/m"+client_info.get_command());
        std::string log_msg(client_info.get_command()+"\n");

        std::string filename(client_info.get_chat_name()+".txt");
        std::fstream log(client_info.get_username()+"/"+filename, std::fstream::app);
        log.write(log_msg.data(), log_msg.length());
        log.close();

        //sock_mtx.lock();
        sock.write_some(boost::asio::buffer(make_msg(send_msg, seance_key)));
        //sock_mtx.unlock();
}

void open_chat()
{
    client_info.set_chat_name(client_info.get_command().substr(6));

    std::cout << "\033[2J\033[1;1H";
    
    std::string cl_name, cl_chat_name;
    cl_name = client_info.get_username();
    cl_chat_name = client_info.get_chat_name();
        //вывод содержимого переписки
        //{
    std::cout << "Chat start: (" << cl_chat_name << ")\n";
    std::string chat = file_read(std::string(cl_name+"/"+cl_chat_name+".txt"), 1);
        //}
    std::string log_msg1(client_info.get_chat_name()+"\n");


    std::string chats_list = file_read(std::string(cl_name+"/chats.txt"), 0);
        //std::string log_msg1(chat_name+"\n");

    if (chats_list.find(cl_chat_name) == std::string::npos)
    {
        std::fstream chats_list_f(cl_name+"/chats.txt", std::fstream::app);
        chats_list_f.write(log_msg1.data(), log_msg1.size());
        chats_list_f.close();
    }
}

void write_msg(boost::asio::ip::tcp::socket &sock, SecByteBlock seance_key)
{
    while(true)
    {

    std::string msg;
    //cout.lock();
    //std::cout << "Print to who send:\n";
    //cout.unlock();

    std::getline(std::cin ,client_info.get_command());
        // /open LeshaLoh
    if (client_info.get_command().substr(0, 6) == "/open ")
    {
        open_chat();
    }
    else if(client_info.get_command().substr(0, 6) == "/exit")
    {
        write_chats();
    }
    else if(client_info.get_command().substr(0, 6) == "/name")
    {
        client_info.print();
    }
    else if (client_info.get_chat_name() != "/"){
        send_msg(sock, seance_key);
    }

    }

}
//добавить сохранение сообщений в файл на компьютере +

void TLS_HandShake(boost::asio::ip::tcp::socket &sock, SecByteBlock &key)
{
        std::cout << "[TLS step 001] Connected\n";
        AutoSeededRandomPool rng;

        // создаем сеансовый ключ AES
        
        SecByteBlock iv(AES::BLOCKSIZE);
        std::cout << "[TLS step 002] SEANCE KEY CREATED\n";

        // генерируем ключ и ив
        rng.GenerateBlock(key, key.size());
        rng.GenerateBlock(iv, iv.size());
        std::cout << "[TLS step 003] SEANCE KEY INIT\n";

        // ключ в строку
        std::string key_str(reinterpret_cast<const char*>(key.BytePtr()), key.size());
        std::cout << "[TLS step 004] SEANCE KEY STR " << key_str << ":\n";

        // получить публичный ключ RSA 
        boost::asio::streambuf rsa_pubkey_buf;
        boost::asio::read_until(sock, rsa_pubkey_buf, '\n');

        // перевести из стримбаф в строку
        std::istream istr(&rsa_pubkey_buf);
        std::string rsa_pubkey_hex;
        std::getline(istr, rsa_pubkey_hex);
        std::cout << "[TLS step 005] RSA PUBLIC KEY " << rsa_pubkey_hex << ":\n";

        //из hex в сырые байты
        std::string rsa_pubkey_str;
        rsa_pubkey_str = Hex_Decr(rsa_pubkey_hex);
        std::cout << "[TLS step 006] RSA PUBLIC KEY: hex >> bytes\n";

        // из строки в ключ
        RSA::PublicKey rsa_pubkey;
        StringSource rsa_pubkey_ss(rsa_pubkey_str, true);
        rsa_pubkey.Load(rsa_pubkey_ss);
        std::cout << "[TLS step 007] RSA PUBLIC KEY LOADED\n";

        
        // шифруем сеансовый ключ публичным RSA
        std::string seance_rsa_key = RSA_Encr(key_str, rsa_pubkey);
        
        // шифруем в hex
        std::string seance_rsa_key_hex = (Hex_Encr(seance_rsa_key) + "\n");
        std::cout << "[TLS step 008] SEANCE KEY STRING " << seance_rsa_key_hex;

        // отправляем сеансовый ключ 
        sock.write_some(boost::asio::buffer(seance_rsa_key_hex));
        std::cout << "[TLS step 010] SEANCE KEY SEND > WAIT...\n";

}



int main()
{
    boost::asio::io_context io;


    SecByteBlock seance_key(AES::MAX_KEYLENGTH);

    std::string address;
    std::cout << "Print address\n";
    std::getline(std::cin , address);

    boost::asio::ip::tcp::socket sock(io, boost::asio::ip::tcp::endpoint(boost::asio::ip::make_address(address), 0));

    std::cout << "Print your nick:\n";

    std::getline(std::cin , client_info.get_username());
    std::filesystem::create_directory(client_info.get_username());

    std::cout << "Print password:\n";
    std::getline(std::cin , client_info.get_password());

    //std::string name2(name+"\n");
    

    boost::asio::ip::tcp::endpoint ep(boost::asio::ip::make_address("127.0.0.1"), 5231);
    boost::system::error_code er;
    std::cout << "Connecting...\n";
    sock.connect(ep, er);
    if (!er)
    {
        // TSL рукопожатие
        TLS_HandShake(sock, seance_key);


        sock.write_some(boost::asio::buffer(make_msg(client_info.get_username() + "|" + client_info.get_password(), seance_key)));
        std::cout << "[TLS step 011] Connected\n";
        //std::cout << "Print name of your friend:\n";
        //std::string secondName;
        //std::cin >> secondName;

        std::thread read_th(check_msg, std::ref(sock), std::ref(seance_key));
        std::thread write(write_msg, std::ref(sock), seance_key);
        //while(true)
        // {
        //     std::cout << "Print message:\n";
        //     std::string msg;
        //     std::cin >> msg;

        //     std::cout << "/n"+secondName+"/m"+msg << ": message\n";
        //     sock.write_some(boost::asio::buffer(make_msg("/n"+secondName+"/m"+msg, seance_key)));

        //     std::cout << name << ":" << msg << "\n";
        // }

        //std::cout << "Writed\n";

        

        check_msg(sock, seance_key);
        

        while(true)
        {
            io.poll();
        }

    }
    else
    {
        std::cout << er.message();
    }
}