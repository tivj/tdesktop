#pragma once
#include <unordered_map>
namespace remote {

class MessageCryptoWraper {
public:
    MessageCryptoWraper(int command, const QByteArray &);
    QByteArray Proceed(size_t peer_id) const;
    static QByteArray InitiateHandShake(size_t peer_id);
    static QByteArray SendSessionKey(size_t peer_id);
    static bool IsMCW(const QByteArray &byte);
    enum commands : char {
        initiate = 0,
        session_key,
        key_index,
        handshake,
        handshake_approve
    };
private:
    QByteArray ProceedInitiate(size_t peer_id) const;
    QByteArray ProceedSessionKey(size_t peer_id) const;
    QByteArray ProceedKeyIndex(size_t peer_id) const;
    QByteArray ProceedApprove() const;
    int command_;
    QByteArray bytes_;

};
}
