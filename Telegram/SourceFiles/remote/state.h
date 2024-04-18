#pragma once
#include <unordered_map>
#include <QByteArray>
namespace remote {
class State {
public:
    static State& GetInstance() {
        static State remote_state;
        return remote_state;
    }
    void SetPublicKey(size_t peer_id, const QByteArray &key);
    const QByteArray& GetKey(size_t peer_id) const;
    QByteArray& GetKey(size_t peer_id);
private:
    State() = default;
    State(const State&) = delete;
    State& operator=(const State&) = delete;
    std::unordered_map<size_t, QByteArray> public_keys;
};
}
