#include <cerrno>
#include <chrono>
#include <cstdio>
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

using Clock = std::chrono::steady_clock;
const auto kSessionTtl = std::chrono::seconds(5); // попытка живёт 5 секунд

struct Session {
    bool active = false;
    uint32_t id = 0;
    sockaddr_in peer{};
    Bytes client_random;
    Bytes server_random;
    Bytes nonce;
    Secret secret{};
    Clock::time_point started{};

    // После успеха или ошибки затираем секрет и случайные байты
    void reset() {
        wipe(client_random);
        wipe(server_random);
        wipe(nonce);
        wipe(secret);
        active = false;
        id = 0;
        peer = sockaddr_in{};
    }

    ~Session() { reset(); }
};

void send_packet(int fd, uint8_t type, uint32_t id,
                 const Bytes& payload, const sockaddr_in& to) {
    const Bytes pkt = build_packet(type, id, payload);
    if (sendto(fd, pkt.data(), pkt.size(), 0,
               reinterpret_cast<const sockaddr*>(&to), sizeof(to)) < 0) {
        std::perror("sendto");
    }
}

} // namespace

int main(int argc, char** argv) {
    uint16_t port = 5555;
    if (argc > 1 && !parse_port(argv[1], port)) {
        std::cerr << "usage: " << argv[0] << " [port]" << std::endl;
        return 1;
    }

    const int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) {
        std::perror("socket");
        return 1;
    }

    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_ANY);
    addr.sin_port = htons(port);
    if (bind(fd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) < 0) {
        std::perror("bind");
        close(fd);
        return 1;
    }
    // Таймаут на recvfrom, чтобы периодически проверять срок жизни сессии
    set_recv_timeout(fd, 500);
    std::cerr << "server: listening on udp port " << port << std::endl;

    Session s; // одна активная сессия
    uint8_t buf[4096];

    auto send_init_ack = [&](const sockaddr_in& to) {
        Bytes pl;
        pl.reserve(kRandomSize + kNonceSize);
        pl.insert(pl.end(), s.server_random.begin(), s.server_random.end());
        pl.insert(pl.end(), s.nonce.begin(), s.nonce.end());
        send_packet(fd, INIT_ACK, s.id, pl, to);
    };

    for (;;) {
        sockaddr_in from{};
        socklen_t from_len = sizeof(from);
        const ssize_t n = recvfrom(fd, buf, sizeof(buf), 0,
                                   reinterpret_cast<sockaddr*>(&from), &from_len);
        if (n < 0 && errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR) {
            std::perror("recvfrom");
            continue;
        }

        // Сброс просроченной попытки (срабатывает и на пустых просыпаниях)
        if (s.active && Clock::now() - s.started > kSessionTtl) {
            std::cerr << "server: exchange=" << s.id << " timed out, session reset" << std::endl;
            s.reset();
        }
        if (n < 0) {
            continue; // таймаут или сигнал: пакета нет, состояние не меняем
        }

        Header hdr;
        Bytes payload;
        std::string err;
        if (!parse_packet(buf, static_cast<size_t>(n), hdr, payload, err)) {
            std::cerr << "server: bad packet: " << err << std::endl;
            continue; // состояние не меняется, процесс не падает
        }

        if (hdr.type == INIT) {
            if (s.active) {
                if (s.id == hdr.exchange_id && same_endpoint(s.peer, from) &&
                    s.client_random == payload) {
                    // Повторный INIT той же попытки (потерялся INIT_ACK):
                    // новую сессию НЕ создаём, просто шлём тот же INIT_ACK
                    send_init_ack(from);
                } else {
                    std::cerr << "server: busy, INIT with another exchange rejected" << std::endl;
                }
                continue;
            }
            s.id = hdr.exchange_id;
            s.peer = from;
            s.client_random = payload;
            s.server_random = random_bytes(kRandomSize);
            s.nonce = random_bytes(kNonceSize);
            s.secret = compute_secret(s.client_random, s.server_random, s.nonce, s.id);
            s.started = Clock::now();
            s.active = true;
            send_init_ack(from); // ответ уходит отправителю датаграммы
        } else if (hdr.type == CONFIRM) {
            if (!s.active || s.id != hdr.exchange_id || !same_endpoint(s.peer, from)) {
                std::cerr << "server: unexpected CONFIRM, ignored" << std::endl;
                continue;
            }
            Secret expect = confirm_hmac(s.secret, CONFIRM, s.id,
                                         s.client_random, s.server_random, s.nonce);
            const bool ok = ct_equal(expect.data(), payload.data(), expect.size());
            wipe(expect);
            if (!ok) {
                std::cerr << "server: CONFIRM hmac mismatch, session reset" << std::endl;
                s.reset(); // ошибка: секреты затёрты в reset()
                continue;
            }
            Secret ack = confirm_hmac(s.secret, CONFIRM_ACK, s.id,
                                      s.client_random, s.server_random, s.nonce);
            const Bytes pl(ack.begin(), ack.end());
            send_packet(fd, CONFIRM_ACK, s.id, pl, from);
            wipe(ack);
            std::cout << "ok exchange=" << s.id << std::endl;
            s.reset(); // успех: секреты затёрты, готовы к новой сессии
        } else {
            std::cerr << "server: unexpected message type "
                      << static_cast<unsigned>(hdr.type) << ", ignored" << std::endl;
        }
    }
}
