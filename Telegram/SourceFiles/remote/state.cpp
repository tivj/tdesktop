#include "remote/state.h"
namespace remote {
void State::SetPublicKey(size_t peer_id, const QByteArray& key) {
    public_keys[peer_id] = key;
}
void State::SetPrivateKey(size_t peer_id, const QByteArray& key) {
    private_keys[peer_id] = key;
}
const QByteArray& State::GetPublicKey(size_t peer_id) const {
    return public_keys.at(peer_id);
}
QByteArray& State::GetPublicKey(size_t peer_id) {
    return public_keys[peer_id];
}
const QByteArray& State::GetPrivateKey(size_t peer_id) const {
    return private_keys.at(peer_id);
}
QByteArray& State::GetPrivateKey(size_t peer_id) {
    return private_keys[peer_id];
}
}
