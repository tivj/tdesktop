#include <remote/message_crypto_wraper.h>
#include <tg_local_lib/local.h>
#include "remote/state.h"
#include <fstream>
namespace remote {
const QByteArray key_prefix = "KEYPREFIX";
bool MessageCryptoWraper::IsMCW(const QByteArray &bytes) {
    return bytes.startsWith(key_prefix);
}
MessageCryptoWraper::MessageCryptoWraper(int command, const QByteArray& bytes) : command_(command), bytes_(bytes) {}
QByteArray MessageCryptoWraper::InitiateHandShake(size_t peer_id) {
    QByteArray msg;
    msg.append(key_prefix);
    msg.append(commands::initiate);
    auto key_pair = local::api::genKeys();
    State::GetInstance().SetPublicKey(peer_id, key_pair.first);
    State::GetInstance().SetPrivateKey(peer_id, key_pair.second);
    msg.append(key_pair.first);
    return msg;
}
QByteArray MessageCryptoWraper::SendSessionKey(size_t peer_id) {
    size_t key_id = local::api::getCurrentKeyId(peer_id);
    QByteArray key = local::api::getCurrentKey(peer_id);
    if (!local::api::hasPeer(peer_id)) {
        local::api::addPeer(peer_id);
    }
    // local::api::updateCurrentKey(peer_id.value, key);
    QByteArray public_key = State::GetInstance().GetPublicKey(peer_id);
    std::ofstream out("./my_log.txt");
    out << "Find public_key with peer_id: " << peer_id << "\n";
    for (int i = 0; i <public_key.size(); ++i) {
        out << (int)public_key[i] << " ";
    }
    out << "\n";
    out.close();
    QByteArray msg = key_prefix;
    msg.append(commands::session_key);
    msg.append(local::api::encryptPublic(key, public_key));
    return msg;
}
QByteArray MessageCryptoWraper::ProceedInitiate(size_t peer_id) const {
    QByteArray session_key = local::api::genSessionKey();
    if (!local::api::hasPeer(peer_id)) {
        local::api::addPeer(peer_id);
    }
    std::ofstream out("./my_log.txt", std::ios::app);
    QByteArray public_key = bytes_;
    out << "Public Keys\n";
    for (int i = 0; i < public_key.size(); ++i) {
        out << (int)public_key[i] << " ";
    }
    out << "\n";
    out.close();
    State::GetInstance().SetPublicKey(peer_id, bytes_);
    
    size_t key_id = local::api::getCurrentKeyId(peer_id);
    local::api::updateCurrentKey(peer_id, session_key);
    QByteArray session_key_msg(commands::session_key, 1);

    session_key_msg.append(local::api::encryptPublic(session_key, public_key));
    return session_key_msg;
}
QByteArray MessageCryptoWraper::ProceedSessionKey(size_t peer_id) const {
    const QByteArray &private_key = State::GetInstance().GetPrivateKey(peer_id);
    QByteArray session_key = local::api::decryptPrivate(bytes_, private_key);
    size_t key_id = local::api::getCurrentKeyId(peer_id);
    // local::api::updateCurrentKey(peer_id.value, session_key);
    QByteArray key_index_bytes;
    key_index_bytes.append(commands::key_index);
    key_index_bytes.append(key_id);
    return key_index_bytes;
}
QByteArray MessageCryptoWraper::ProceedKeyIndex(size_t peer_id) const {
    size_t key_index = bytes_[1]; /// get key index
    /// check key index
    QByteArray approve_bytes;
    approve_bytes.append(commands::handshake);
    if (key_index == local::api::getCurrentKeyId(peer_id)) {
        approve_bytes.append((char)1);
    } else {
        approve_bytes.append((char)0);
    }
    return approve_bytes;
}
QByteArray MessageCryptoWraper::ProceedApprove() const {
    int approve = bytes_.front();
    if (approve) {
        /// Handshake done!
    } else {
        /// Handshake failed!
    }
    return QByteArray(); ///???
}
QByteArray MessageCryptoWraper::Proceed(size_t peer_id) const {
    switch (command_) {
        case commands::initiate:
            return ProceedInitiate(peer_id);
        case commands::session_key:
            return ProceedSessionKey(peer_id);
        case commands::key_index:
            return ProceedKeyIndex(peer_id);
        case commands::handshake:
            return ProceedApprove();
        default:
            return QByteArray();
    }
}
}
