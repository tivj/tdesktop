#include "remote/state.h"
namespace remote {
void State::SetPublicKey(size_t peer_id, const QByteArray& key) {
    public_keys[peer_id] = key;
}
const QByteArray& State::GetKey(size_t peer_id) const {
    return public_keys.at(peer_id);
}
QByteArray& State::GetKey(size_t peer_id) {
    return public_keys[peer_id];
}
}
