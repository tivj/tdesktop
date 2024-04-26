#pragma once
#include <QtCore/QByteArray>
#include <openssl/aes.h>
#include <openssl/rsa.h>

namespace local::rsa_2048 {
bool genKeys(QByteArray& public_key, QByteArray& private_key);
bool encryptPublic(const QByteArray& data, const QByteArray& key, QByteArray& encrypted);
bool decryptPrivate(const QByteArray& data, const QByteArray& key, QByteArray& decrypted);
}  // namespace local::rsa_2048

namespace local::aes_128 {
bool genKey(QByteArray& key);
bool encrypt(const QByteArray& data, const QByteArray& key, QByteArray& encrypted);
bool decrypt(const QByteArray& data, const QByteArray& key, QByteArray& decrypted);
}  // namespace local::aes_128
