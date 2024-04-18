#include <remote/message_crypto_wraper.h>
#include <tg_local_lib/local.h>
#include "remote/state.h"
#include <fstream>
namespace remote {
QByteArray privkey = QByteArray(), pubkey = QByteArray();
const QByteArray key_prefix = "KEYPREFIX";
bool MessageCryptoWraper::IsMCW(const QByteArray &bytes) {
    return bytes.startsWith(key_prefix);
}
MessageCryptoWraper::MessageCryptoWraper(int command, const QByteArray& bytes) : command_(command), bytes_(bytes) {}
QByteArray MessageCryptoWraper::InitiateHandShake() {
    QByteArray msg;
    msg.append(key_prefix);
    msg.append(commands::initiate);
    auto key_pair = local::api::genKeys();
    pubkey = key_pair.first;
    privkey = key_pair.second;
    msg.append(pubkey);
    return msg;
}
QByteArray MessageCryptoWraper::SendSessionKey(PeerId peer_id) {
    size_t key_id = local::api::getCurrentKeyId(peer_id.value);
    QByteArray key = local::api::getKeyForPeer(peer_id.value, key_id);
    if (!local::api::hasPeer(peer_id.value)) {
        local::api::addPeer(peer_id.value);
    }
    local::api::addKeyForPeer(peer_id.value, local::api::getCurrentKeyId(peer_id.value) + 1, key);
    QByteArray bytes = State::GetInstance().GetKey(peer_id.value);
    std::ofstream out("./my_log.txt");
    out << "Find public_key with peer_id: " << peer_id.value << "\n";
    for (int i = 0; i < bytes.size(); ++i) {
        out << (int)bytes[i] << " ";
    }
    out << "\n";
    out.close();
    QByteArray msg = key_prefix;
    msg.append(commands::session_key);
    msg.append(local::api::encryptPublic(key, bytes));
    return msg;
}
QByteArray MessageCryptoWraper::ProceedInitiate(PeerId peer_id) const {
    QByteArray session_key = local::api::genKey();
    if (!local::api::hasPeer(peer_id.value)) {
        local::api::addPeer(peer_id.value);
    }
    std::ofstream out("./my_log.txt", std::ios::app);
    QByteArray public_key = bytes_;
    out << "Public Keys\n";
    for (int i = 0; i < public_key.size(); ++i) {
        out << (int)public_key[i] << " ";
    }
    out << "\n";
    out.close();
    State::GetInstance().SetPublicKey(peer_id.value, bytes_);
    
    size_t key_id = local::api::getCurrentKeyId(peer_id.value);
    local::api::addKeyForPeer(peer_id.value, key_id, session_key);
    session_key = local::api::getKeyForPeer(peer_id.value, key_id);
    QByteArray session_key_msg(commands::session_key, 1);

    session_key_msg.append(local::api::encryptPublic(session_key, public_key));
    return session_key_msg;
}
QByteArray MessageCryptoWraper::ProceedSessionKey(PeerId peer_id) const {
    QByteArray session_key = local::api::decryptPrivate(bytes_, privkey);
    size_t key_id = local::api::getCurrentKeyId(peer_id.value);
    local::api::addKeyForPeer(peer_id.value, key_id, session_key);
    QByteArray key_index_bytes;
    key_index_bytes.append(commands::key_index);
    key_index_bytes.append(key_id);
    return key_index_bytes;
}
QByteArray MessageCryptoWraper::ProceedKeyIndex(PeerId peer_id) const {
    size_t key_index = bytes_[1]; /// get key index
    /// check key index
    QByteArray approve_bytes;
    approve_bytes.append(commands::handshake);
    if (key_index == local::api::getCurrentKeyId(peer_id.value)) {
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
QByteArray MessageCryptoWraper::Proceed(PeerId peer_id) const {
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
