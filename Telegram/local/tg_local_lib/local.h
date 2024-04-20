#pragma once
#include <QtCore/QByteArray>

namespace local::api {

std::pair<QByteArray, QByteArray> genKeys();
QByteArray encryptPublic(const QByteArray& data, const QByteArray& key);
QByteArray decryptPrivate(const QByteArray& data, const QByteArray& key);

QByteArray genSessionKey();

void addPeer(size_t peer_id);
bool hasPeer(size_t peer_id);

void addMessageToHide(size_t peer_id, size_t message_id);
bool needToHideMessage(size_t peer_id, size_t message_id);

size_t getCurrentKeyId(size_t peer_id);
QByteArray getCurrentKey(size_t peer_id);
QByteArray getKey(size_t peer_id, size_t key_id);

void updateCurrentKey(size_t peer_id, size_t key_id, const QByteArray& key);
void updateCurrentKey(size_t peer_id, const QByteArray& key);

QByteArray encryptMessage(size_t peer_id, size_t message_id, const QByteArray& content);
QByteArray decryptMessage(size_t peer_id, size_t message_id, const QByteArray& content);

}  // namespace local::api
