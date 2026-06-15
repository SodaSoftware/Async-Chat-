#include <iostream>
#include <boost/asio.hpp>
#include <memory>
#include <fstream>
#include <chrono>
#include <thread>
#include <list>
#include <exception>
#include <optional>
#include <cryptopp/aes.h>
#include <cryptopp/filters.h>
#include <cryptopp/gcm.h>
#include <cryptopp/osrng.h>
#include <cryptopp/rsa.h>
#include <cryptopp/hex.h>
#include <sqlite3.h>

//цели
// 1 - добавить std::optional в места с поиском чего либо
// 2 - разобраться с глобальными переменными
// 3 - вынести лишний код в отдельный функции ( в том числе вложенные лямбда функции )

using namespace CryptoPP;

//сервер
// 1 отправляет публичный ключ
// 2 принимает сеансовый ключ
// 3 шифрует и расшифровывает данные этим ключом
//
//клиент
// 1 принимает публичный ключ
// 2 шифрует сеасовый ключ публичным
// 3 отправляет сеансовый ключ
// 4 шифрует и расшифровывает данные этим ключом
//
//
class Database
{
    private:
        sqlite3 *db;

    public:

        Database()
        {
            int result = sqlite3_open("passwords.db", &db);
            if (result == SQLITE_OK)
            {
                std::cout << "\n[INFO]|OPEN DB|\n";
            }
            else
            {
                 std::cout << "\n[ERROR]|OPEN DB|\n";
            }
        }

        ~Database()
        {
            sqlite3_close(db);
        }

        void CreateTable()
        {
            std::string request = "CREATE TABLE IF NOT EXISTS clients ("
                        "id INTEGER PRIMARY KEY AUTOINCREMENT, "
                        "name TEXT NOT NULL, "
                        "password TEXT NOT NULL);";

            char* err_msg = nullptr;
            int result = sqlite3_exec(db, request.c_str(), nullptr, nullptr, &err_msg);

            if (result != SQLITE_OK)
            {
                std::cerr << "[ERROR]" << err_msg << "\n";
            }
            else
            {
                std::cout << "\n[INFO]|creating done|\n";
            }
        }

        bool check_password(std::string name_sql, std::string password_sql)
        {
            sqlite3_stmt *stmt;
            std::string request = "SELECT password FROM clients WHERE name=?;";

            std::string password_sql_db;

            sqlite3_prepare_v2(db, request.c_str(), -1, &stmt, nullptr);
            sqlite3_bind_text(stmt, 1, name_sql.c_str(), -1, SQLITE_STATIC);

            if(sqlite3_step(stmt) == SQLITE_ROW)
            {
                password_sql_db = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 0));
                std::cout << password_sql_db << " password\n";
                if (password_sql == password_sql_db)
                {
                    sqlite3_finalize(stmt);
                    std::cout << "Correct password\n";
                    return true;
                }
                else
                {
                    sqlite3_finalize(stmt);
                    std::cout << "Wrond password\n";
                    return false;
                }
            }
            else{
                sqlite3_stmt *stmt2;
                std::string request2 = "INSERT INTO clients (name, password) VALUES(?,?);";

                sqlite3_prepare_v2(db, request2.c_str(), -1, &stmt2, nullptr);

                sqlite3_bind_text(stmt2, 1, name_sql.c_str(), -1, SQLITE_STATIC);
                sqlite3_bind_text(stmt2, 2, password_sql.c_str(), -1, SQLITE_STATIC);

                sqlite3_step(stmt2);

                sqlite3_finalize(stmt2);
                sqlite3_finalize(stmt);
                std::cout << "New user " << name_sql << " created\n";
                return true;
            }
            
        }

};
class Client
{
private:
    std::shared_ptr<boost::asio::ip::tcp::socket> client_sock;
    std::string client_name;
    CryptoPP::SecByteBlock key;

public:
    Client(std::shared_ptr<boost::asio::ip::tcp::socket> sock, std::string name,  std::string key_str) : client_sock(sock), client_name(name), key(32)
    {
        
        if (key_str.size() == 32)
        {
        std::memcpy(key.BytePtr(), key_str.data(), key_str.size());
        }
        else
        {
            std::cout << "Error: Invalid key length\n";
        }
    }

    Client(std::shared_ptr<boost::asio::ip::tcp::socket> sock) : client_sock(sock), key(32)
    {
        
    }

    void set_name(std::string nm)
    {
        client_name = nm;
    }

    void set_key(std::string key_str)
    {
        if (key_str.size() == 32)
        {
        std::memcpy(key.BytePtr(), key_str.data(), key_str.size());
        }
        else
        {
            std::cout << "Error: Invalid key length\n";
        }
    }

    std::string get_name() const
    {
        return client_name;
    }

    std::shared_ptr<boost::asio::ip::tcp::socket> get_sock() const
    {
        return client_sock;
    }

    CryptoPP::SecByteBlock get_key()
    {
        return key;
    }

    void print()
    {
        std::cout << "Address: " << client_sock->remote_endpoint().address() << ", Name: " << client_name << ", Key: " << std::string(reinterpret_cast<const char*>(key.BytePtr()), key.size()) << "\n";
    }
};

class Message
{
private:
    std::string sink_name;
    std::string sink_msg;
    std::string source_name;

public:
    Message(std::string sk_name, std::string mag, std::string src_name) : sink_name(sk_name), sink_msg(mag), source_name(src_name)
    {

    }

    std::string get_sink_name() const
    {
        return sink_name;
    }

    std::string get_msg() const
    {
        return sink_msg;
    }

    std::string get_source_name() const
    {
        return source_name;
    }

    void print()
    {
        std::cout << "Msg - " << sink_msg << " send to " << sink_name << " from " << source_name << "\n";
    }
};

class ChatServer
{
    public:
        std::vector<std::string> usernames;

        std::list<std::shared_ptr<Client>> sockets;

        std::list<Message> queue_msg; //пара имя получателя / сообщение 

        std::shared_ptr<boost::asio::ip::tcp::acceptor> acpt;
};

boost::asio::io_context io;
boost::asio::steady_timer timer(io);
std::mutex write_read_mtx;



using namespace CryptoPP;

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

std::optional<std::string> get_address(std::string name, ChatServer &server)
{
    for (auto it = server.sockets.begin(); it != server.sockets.end(); it++)
    {
        //std::cout << users[i].second << ":" << users[i].second.length() << " username : " << name << ":" << name.length() << "correct name\n" << (users[i].second == name) << "-\n";
        if ((*it)->get_name() == name)
        {
            
            
            boost::system::error_code ec;
            std::string address = (*it)->get_sock()->remote_endpoint(ec).address().to_string();

            if(!ec)
            {
                std::cout << "Correct\n";
                return address;
            }
            else{
                std::cout << "[ERROR] " << ec.message() << "\n";
                return std::nullopt;
            }
        }
        else
        {
            std::cout << "User " << (*it)->get_name() << " is isn`t sink of " << name << "\n";
        }
    }

    return std::nullopt;
}

auto get_sock(std::string address, ChatServer &server)
{
    for (auto client_it = server.sockets.begin(); client_it != server.sockets.end(); client_it++)
    {
        std::cout << "Check Sock\n";
        boost::system::error_code ec;
        std::cout << (*client_it)->get_sock()->remote_endpoint(ec).address().to_string() << ":" << address << "\n";
        if ((*client_it)->get_sock()->remote_endpoint(ec).address().to_string() == address)
        {
            std::cout << "Correct\n";
            return client_it;
        }
        if (ec)
        {
            std::cout << "[WARNING] Client disconect\n";
        }
    } 

    return server.sockets.end();
}



std::optional<std::string> parsing_message(std::string raw_msg, char object_ind)
{       
    std::string name_ind = "/n";
    std::string msg_ind = "/m";

    int i1 = raw_msg.find(name_ind);
    int i2 = raw_msg.find(msg_ind);

    if (i1 != std::string::npos && i2 != std::string::npos && i1+2 < raw_msg.size() &&  i2+2 < raw_msg.size() && i1<i2)
    {
        int l = raw_msg.substr(i1+2, raw_msg.length() - (i1+2)).length();
        std::string name = raw_msg.substr(i1+2, l - (l - i2 + 2));

        std::string msg = raw_msg.substr(i2+2, raw_msg.length()-1 - (i2+2) + 1);

        switch (object_ind)
        {
        case 'n':
            return name;
                
        case 'm':
            return msg;

        default:
            break;
        }
    }
        else{
        std::cerr << "[ERROR] Invalid message";
    }

    return std::nullopt;
}

std::optional<std::string> parsing_message_password(std::string raw_msg, char object_ind)
{       
    std::string rise_ind = "/n";


    int pos = raw_msg.find("|");

    if (pos != std::string::npos && pos+1 < raw_msg.size())
    {
        std::string name = raw_msg.substr(0, pos);

        std::string password = raw_msg.substr(pos+1);

        switch (object_ind)
        {
        case 'n':
            return name;
                
        case 'p':
            return password;

        default:
            break;
        }
    }
    else{
        std::cerr << "[ERROR] Invalid message";
    }
    return std::nullopt;
}

std::pair<CryptoPP::SecByteBlock, std::string> parsing_raw_message(std::string raw_message)
{
    if (raw_message.size() <= 32)
    {
        throw std::invalid_argument("Error: message doesn`t include Initialising Vector(IV)");
    }
    std::string iv = Hex_Decr(raw_message.substr(0, 32));
    std::cout << "IV size - " << iv.size() << ": IV - " << iv << "\n";
    std::string message = Hex_Decr(raw_message.substr(32));
    std::cout << message <<  " - message\n";


    return std::pair<CryptoPP::SecByteBlock, std::string> (CryptoPP::SecByteBlock(reinterpret_cast<const byte*>(iv.data()), iv.size()), message);
}



void read_message()
{

}

void check_massages(std::shared_ptr<Client> sock1, ChatServer &server)
{
    std::cout << "Start check\n";

    std::shared_ptr<boost::asio::streambuf> buf = std::make_shared<boost::asio::streambuf>();


    boost::asio::async_read_until(*sock1->get_sock(), *buf, '\n', [buf, sock1, &server](const boost::system::error_code &error, size_t bytes_trasfered){
        if(!error)
        {
        std::cout << "Read end\n";
        std::istream i(buf.get());
        std::string str;
        std::getline(i, str);
        
        auto parssed_raw_message = parsing_raw_message(str);
        SecByteBlock iv = parssed_raw_message.first;
        std::string msg_encr = parssed_raw_message.second;
        //std::cout << "Key size - " << key.size() << ": Key - " << key << "\n";

        std::string msg_unparsed = AES_Decr(msg_encr, sock1->get_key(), iv);
        std::cout << msg_unparsed << "\n";

        std::optional<std::string> name = parsing_message(msg_unparsed, 'n');
        std::optional<std::string> msg = parsing_message(msg_unparsed, 'm');

        if (name.has_value() && msg.has_value())
        {

            
            std::cout << name.value() << ":" << msg.value() << "\n";

            Message full_message(name.value(), msg.value(), sock1->get_name());
            full_message.print();

            {
                std::lock_guard<std::mutex> lock(write_read_mtx);
                server.queue_msg.push_back(full_message);
            }
            

            check_massages(sock1, server);
        }
            else if(error == boost::asio::error::eof)
            {
                sock1->get_sock()->close();
                server.sockets.remove(sock1);
                std::cout << "Socket delete\n";
            }
        }
        else if(error)
        {
            sock1->get_sock()->close();
            server.sockets.remove(sock1);
            std::cout << "[ERROR] Socket delete: " << error.message() << std::endl;
        }
    });
    
}

void send_rsa_pubkey(std::shared_ptr<boost::asio::ip::tcp::socket> sock, RSA::PublicKey pubKey)
{
                // преобразовываем публичный ключ в строку
            std::string publick_key_string;
            StringSink pks_ss(publick_key_string);
            pubKey.Save(pks_ss);
            std::cout << "PUBLIC KEY STR \n" << publick_key_string << "\n";

            // ключ в hex
            std::string public_key_hex = (Hex_Encr(publick_key_string) + "\n");
            std::cout << "RSA KEY PUBLIC HEX " << public_key_hex << "\n";

            // тут отправляем клиенту публичный ключ
            sock->write_some(boost::asio::buffer(public_key_hex));
}

void accept_connects(std::shared_ptr<boost::asio::ip::tcp::acceptor> acceptor, RSA::PrivateKey prKey, RSA::PublicKey pubKey, ChatServer &server)
{
    std::shared_ptr<boost::asio::ip::tcp::socket> sock = std::make_shared<boost::asio::ip::tcp::socket>(io);

    boost::system::error_code er;
    std::cout << "Accept...\n";
    acceptor->async_accept(*sock, [sock, acceptor, prKey, pubKey, &server](const boost::system::error_code &error){
        if (error)
        {
           std::cout << error.message();
        }
        else
        {
            
            std::cout << "[TLS step 001] Greate accept\n";
            
            std::shared_ptr it_sock = std::make_shared<Client>(sock);
            //sockets.push_back(std::make_shared<Client>(sock));
            
            std::shared_ptr<boost::asio::streambuf> buf_seance = std::make_shared<boost::asio::streambuf>();

            send_rsa_pubkey(sock, pubKey);

            // тут ждем от пользователя сеансовый ключ
            std::cout << "[TLS step 002] Read seance key..\n";
            boost::asio::async_read_until(*sock, *buf_seance, '\n', [it_sock, buf_seance, sock, acceptor, prKey, pubKey, &server](const boost::system::error_code &error, size_t bytes_trasfered){
            
            if (!error)
            {
            std::cout << "[TLS step 003] Read end\n";

            // тут принимаем от клиента зашифрованный сеансовый ключ в виде строки
            std::istream i(buf_seance.get());

            std::string key_str_hex;
            std::getline(i, key_str_hex);

            std::cout << "[TLS step 004] SEANCE KEY ENCRYPTED " << key_str_hex << "\n";

            // из hex в ключ
            std::string key_str = Hex_Decr(key_str_hex);
            
            // разшифровываем сеансовый ключ при помощи RSA_Decr
            std::string seance_key_str = RSA_Decr(key_str, prKey);
            
            //auto it = std::prev(sockets.end());
            it_sock->set_key(seance_key_str);

            std::shared_ptr<boost::asio::streambuf> buf = std::make_shared<boost::asio::streambuf>();

            std::cout << "[TLS step 005] Read name...\n";
            boost::asio::async_read_until(*sock, *buf, '\n', [buf, sock, acceptor, prKey, pubKey, it_sock, &server](const boost::system::error_code &error, size_t bytes_trasfered){
                
                
                std::istream i(buf.get());

                std::string client_name_msg;
                std::getline(i, client_name_msg);
                std::cout << "[TLS step 006] Client name loaded " << client_name_msg << "\n:";

                try
                {
                    auto parssed_message = parsing_raw_message(client_name_msg);

                    std::cout << "[TLS step 007] Message parsed\n";

                    SecByteBlock iv = parssed_message.first;
                    std::string client_name_encr = parssed_message.second;
                    std::cout << client_name_encr << "\n";
                    //std::cout << "Key size - " << key.size() << ": Key - " << key << "\n";

                    //std::string client_name_unhex = Hex_Decr(client_name_encr);
                    std::string client_name = AES_Decr(client_name_encr, it_sock->get_key(), iv);
                    

                    std::optional<std::string> password_encr = parsing_message_password(client_name, 'p');
                    //std::cout << password_encr << " password\n\n";
                    std::optional<std::string> name_encr = parsing_message_password(client_name, 'n');

                    if (name_encr.has_value() && password_encr.has_value())
                    {

                        Database db;
                        db.CreateTable();
                        bool result = db.check_password(name_encr.value(), password_encr.value());
                    
                        if (result)
                        {
                        it_sock->set_name(name_encr.value());
                    
                        it_sock->print();

                        server.sockets.push_back(it_sock);
                        check_massages(it_sock, server);
                        }
                        else
                        {
                            it_sock->get_sock()->close();
                        }
                    }

                }
                catch(const std::invalid_argument& e)
                {
                    std::cerr << e.what() << '\n';

                }
            

                

                accept_connects(acceptor, prKey, pubKey, server);
                });
            }
            else
            {
                std::cout << "ERROR: " << error.message() << ": ACCEPT ABORT\n";
            }

            });

            
        }

    });


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

void write_sock(boost::system::error_code er, ChatServer &server)
{
    std::cout << "Start queue check\n";
    
    for(auto i = server.queue_msg.begin(); i != server.queue_msg.end();)
    {
        std::cout << "Check msg " << i->get_sink_name() << "\n";
        auto address = get_address(i->get_sink_name(), server);
        
        if(address)
        {
            std::cout << "User with name " << i->get_sink_name() << " has address " << address.value() << "\n";
            auto ind = get_sock(address.value(), server);
            if (ind != server.sockets.end())
            {
                std::string msg(i->get_source_name()+":"+i->get_msg());
                (*ind)->get_sock()->write_some(boost::asio::buffer(make_msg(msg, (*ind)->get_key())));
                std::cout << "Msg sent to " << i->get_sink_name() << "\n";
                std::this_thread::sleep_for(std::chrono::milliseconds(50));

                {
                std::lock_guard<std::mutex> lock(write_read_mtx);
                i = server.queue_msg.erase(i);
                }
                
            }
            else{
                i++;
            }
        }
        else{
            i++;
        }
    }
    
    timer.expires_at(timer.expiry() + boost::asio::chrono::milliseconds(1500));
    timer.async_wait([&server](const boost::system::error_code& ec) {
    write_sock(ec, server);
    });
}

int main()
{
    
    std::cout << "Start\n";
    ChatServer server;
    server.acpt = std::make_shared<boost::asio::ip::tcp::acceptor>(io, boost::asio::ip::tcp::endpoint(boost::asio::ip::tcp::v4(), 5231));


    AutoSeededRandomPool rng;

    RSA::PrivateKey prKey;
    prKey.GenerateRandomWithKeySize(rng, 2048);
    RSA::PublicKey pubKey(prKey);

    std::cout << "Start accepting\n";
    accept_connects(server.acpt, prKey, pubKey, server);

    timer.expires_after(boost::asio::chrono::milliseconds(500));

    timer.async_wait([&server](const boost::system::error_code& ec) {
    write_sock(ec, server);
    });

    // while(true)
    // {

    //     io.poll();
    // }
    io.run();
    
}