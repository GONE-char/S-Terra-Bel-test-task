#include <cerrno>
#include <cstdio>
#include <cstring>
#include <iostream>
#include <string>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

#include "common.h"
#include "protocol.h"

using namespace proto;

namespace {

constexpr int kMaxRetries = 5;   // 5 попыток по 1 секунде = срок жизни попытки 5 с
constexpr int kRecvTimeoutMs = 1000;

// Всё секретное затирается деструктором при любом выходе (успех/ошибка)
struct Secrets {
    Bytes client_random;
    Bytes server_random;
    Bytes nonce;
    Secret secret{};
    Secret confirm_tag{};
    Secret ack_tag{};

    ~Secrets() {
        wipe(client_random);
        wipe(server_random);
        wipe(nonce);
        wipe(secret);
        wipe(confirm_tag);
        wipe(ack_tag);
    }
};

// true — пакет получен, false — таймаут (или ошибка уже напечатана)
bool recv_packet(int fd, uint8_t* buf, size_t cap, ssize_t& n, sockaddr_in& from) {
    for (;;) {
        socklen_t from_len = sizeof(from);
        n = recvfrom(fd, buf, cap, 0, reinterpret_cast<sockaddr*>(&from), &from_len);
        if (n >= 0) {
            return true;
        }
        if (errno == EINTR) {
            continue;
        }
        if (errno != EAGAIN && errno != EWOULDBLOCK) {
            std::perror("recvfrom");
        }
        return false;
    }
}

} // namespace

int main(int argc, char** argv) {
    const char* ip = (argc > 1) ? argv[1] : "127.0.0.1";
    uint16_t port = 5555;
    if (argc > 2 && !parse_port(argv[2], port)) {
        std::cerr << "usage: " << argv[0] << " [server_ip] [port]" << std::endl;
        return 1;
    }

    sockaddr_in server{};
    server.sin_family = AF_INET;
    server.sin_port = htons(port);
    if (inet_pton(AF_INET, ip, &server.sin_addr) != 1) {
        std::cerr << "client: bad server ip: " << ip << std::endl;
        return 1;
    }

    const int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) {
        std::perror("socket");
        return 1;
    }
    set_recv_timeout(fd, kRecvTimeoutMs);

    Secrets sec;
    const uint32_t id = random_exchange_id();
    sec.client_random = random_bytes(kRandomSize);
    uint8_t buf[4096];

    //Шаг 1: INIT -> INIT_ACK (с повторами при потерях) ----
    const Bytes init_pkt = build_packet(INIT, id, sec.client_random);
    bool got_init_ack = false;
    for (int attempt = 0; attempt < kMaxRetries && !got_init_ack; ++attempt) {
        if (sendto(fd, init_pkt.data(), init_pkt.size(), 0,
                   reinterpret_cast<const sockaddr*>(&server), sizeof(server)) < 0) {
            std::perror("sendto");
            close(fd);
            return 1;
        }
        for (;;) {
            sockaddr_in from{};
            ssize_t n = 0;
            if (!recv_packet(fd, buf, sizeof(buf), n, from)) {
                break; // таймаут: повторяем INIT
            }
            if (!same_endpoint(from, server)) {
                std::cerr << "client: packet from unknown sender, ignored" << std::endl;
                continue;
            }
            Header hdr;
            Bytes payload;
            std::string err;
            if (!parse_packet(buf, static_cast<size_t>(n), hdr, payload, err)) {
                std::cerr << "client: bad packet: " << err << std::endl;
                continue;
            }
            if (hdr.type != INIT_ACK || hdr.exchange_id != id) {
                std::cerr << "client: unexpected packet, ignored" << std::endl;
                continue;
            }
            sec.server_random.assign(payload.begin(), payload.begin() + kRandomSize);
            sec.nonce.assign(payload.begin() + kRandomSize, payload.end());
            got_init_ack = true;
            break;
        }
    }
    if (!got_init_ack) {
        std::cerr << "client: no INIT_ACK from server, giving up" << std::endl;
        close(fd);
        return 1;
    }

    //Общий секрет и HMAC-теги
    sec.secret = compute_secret(sec.client_random, sec.server_random, sec.nonce, id);
    sec.confirm_tag = confirm_hmac(sec.secret, CONFIRM, id,
                                   sec.client_random, sec.server_random, sec.nonce);
    sec.ack_tag = confirm_hmac(sec.secret, CONFIRM_ACK, id,
                               sec.client_random, sec.server_random, sec.nonce);

    //Шаг 2: CONFIRM -> CONFIRM_ACK
    const Bytes confirm_payload(sec.confirm_tag.begin(), sec.confirm_tag.end());
    const Bytes confirm_pkt = build_packet(CONFIRM, id, confirm_payload);
    bool confirmed = false;
    for (int attempt = 0; attempt < kMaxRetries && !confirmed; ++attempt) {
        if (sendto(fd, confirm_pkt.data(), confirm_pkt.size(), 0,
                   reinterpret_cast<const sockaddr*>(&server), sizeof(server)) < 0) {
            std::perror("sendto");
            close(fd);
            return 1;
        }
        for (;;) {
            sockaddr_in from{};
            ssize_t n = 0;
            if (!recv_packet(fd, buf, sizeof(buf), n, from)) {
                break; // таймаут: повторяем CONFIRM
            }
            if (!same_endpoint(from, server)) {
                std::cerr << "client: packet from unknown sender, ignored" << std::endl;
                continue;
            }
            Header hdr;
            Bytes payload;
            std::string err;
            if (!parse_packet(buf, static_cast<size_t>(n), hdr, payload, err)) {
                std::cerr << "client: bad packet: " << err << std::endl;
                continue;
            }
            if (hdr.type != CONFIRM_ACK || hdr.exchange_id != id) {
                std::cerr << "client: unexpected packet, ignored" << std::endl;
                continue;
            }
            if (!ct_equal(sec.ack_tag.data(), payload.data(), sec.ack_tag.size())) {
                std::cerr << "client: CONFIRM_ACK hmac mismatch" << std::endl;
                close(fd);
                return 1; // секреты затрутся в деструкторе Secrets
            }
            confirmed = true;
            break;
        }
    }
    close(fd);

    if (!confirmed) {
        std::cerr << "client: no CONFIRM_ACK from server, giving up" << std::endl;
        return 1;
    }
    std::cout << "ok exchange=" << id << std::endl;
    return 0;
}
