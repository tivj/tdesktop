#pragma once
#include <unordered_map>
namespace remote {

class MessageCryptoWraper {
public:
    MessageCryptoWraper(int command, const QByteArray &);
    QByteArray Proceed(PeerId peer_id) const;
    static QByteArray InitiateHandShake();
    static QByteArray SendSessionKey(PeerId peer_id);
    static bool IsMCW(const QByteArray &byte);
    enum commands : char {
        initiate = 0,
        session_key,
        key_index,
        handshake,
        handshake_approve
    };
private:
    QByteArray ProceedInitiate(PeerId peer_id) const;
    QByteArray ProceedSessionKey(PeerId peer_id) const;
    QByteArray ProceedKeyIndex(PeerId peer_id) const;
    QByteArray ProceedApprove() const;
    int command_;
    QByteArray bytes_;

};
}
