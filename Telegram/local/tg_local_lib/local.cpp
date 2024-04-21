#include "local.h"
#include "coder.h"
#include "key_manager.h"
#include "log.h"
#include <vector>

namespace local::api {

std::pair<QByteArray, QByteArray> genKeys() {
    QByteArray public_key, private_key;
    if (rsa_2048::genKeys(public_key, private_key)) {
        log::write("INFO: Key pair was generated");
        return {public_key, private_key};
    }
    log::write("ERROR: Failed to generate key pair");
    return {};
}

QByteArray encryptPublic(const QByteArray& data, const QByteArray& key) {
    QByteArray encrypted;
    if (rsa_2048::encryptPublic(data, key, encrypted)) {
        log::write("INFO: Data was encrypted with public key");
        return encrypted;
    }
    log::write("ERROR: Failed to encrypt data with public key");
    return {};
}

QByteArray decryptPrivate(const QByteArray& data, const QByteArray& key) {
    QByteArray decrypted;
    if (rsa_2048::decryptPrivate(data, key, decrypted)) {
        log::write("INFO: Data was decrypted with private key");
        return decrypted;
    }
    log::write("ERROR: Failed to decrypt data with private key");
    return {};
}

QByteArray genSessionKey() {
    QByteArray key;
    if (aes_128::genKey(key)) {
        log::write("INFO: Session key was generated");
        return key;
    }
    log::write("ERROR: Failed to generate session key");
    return {};
}

bool hasPeer(size_t peer_id) { return KeyManager::getInstance().hasPeer(peer_id); }

void addPeer(size_t peer_id) {
    if (!hasPeer(peer_id)) {
        KeyManager::getInstance().setPeer(peer_id);
        log::write("INFO: Peer with id ", peer_id, " was added");
    } else {
        log::write("WARNING: Peer with id ", peer_id, " already exists");
    }
}

void addMessageToHide(size_t peer_id, size_t message_id) {
    if (hasPeer(peer_id)) {
        KeyManager::getInstance().setMessageToHide(peer_id, message_id);
    } else {
        log::write("ERROR: No peer with id ", peer_id);
    }
}

bool needToHideMessage(size_t peer_id, size_t message_id) {
    return KeyManager::getInstance().hasMessageToHide(peer_id, message_id);
}

size_t getCurrentKeyId(size_t peer_id) {
    if (auto current_key_id = KeyManager::getInstance().getCurentKeyId(peer_id)) {
        return current_key_id.value();
    }
    log::write("ERROR: No peer with id ", peer_id);
    return 0;
}

QByteArray getCurrentKey(size_t peer_id) {
    auto key_vector = KeyManager::getInstance().getCurrentKeyForPeer(peer_id);
    if (!key_vector.empty()) {
        return QByteArray(reinterpret_cast<const char*>(key_vector.data()), key_vector.size());
    }
    log::write("ERROR: Failed to get current key for peer ", peer_id);
    return {};
}

QByteArray getKey(size_t peer_id, size_t key_id) {
    auto key_vector = KeyManager::getInstance().getKeyForPeer(peer_id, key_id);
    if (!key_vector.empty()) {
        return QByteArray(reinterpret_cast<const char*>(key_vector.data()), key_vector.size());
    }
    log::write("ERROR: Failed to get key with id ", key_id, " for peer ", peer_id);
    return {};
}

void updateCurrentKey(size_t peer_id, size_t key_id, const QByteArray& key) {
    if (hasPeer(peer_id)) {
        std::vector<char> key_vector(key.begin(), key.end());
        KeyManager::getInstance().setPeerPassword(peer_id, key_id, key_vector, 0);
        if (size_t current_key_id = getCurrentKeyId(peer_id); current_key_id != 0) {
            if (KeyManager::getInstance().changeKeyStatus(peer_id, current_key_id, -1)) {
                log::write("INFO: Previous current key status was changed to revoced");
            } else {
                log::write("ERROR: Failed to change status of previous current key");
            }
        }
        KeyManager::getInstance().setCurrentKeyId(peer_id, key_id);
        log::write("INFO: Current key for peer with id ", peer_id, " was updated");
    } else {
        log::write("ERROR: No peer with id ", peer_id);
    }
}

void updateCurrentKey(size_t peer_id, const QByteArray& key) {
    updateCurrentKey(peer_id, getCurrentKeyId(peer_id) + 1, key);
}

QByteArray encryptMessage(size_t peer_id, size_t message_id, const QByteArray& content) {
    if (!hasPeer(peer_id)) {
        return content;
    }
    size_t ckey_id = getCurrentKeyId(peer_id);
    auto status_of_ckey = KeyManager::getInstance().getKeyStatus(peer_id, ckey_id);
    if (!status_of_ckey.has_value()) {
        log::write(
            "ERROR: Failed to encrypt message for peer with id ",
            peer_id,
            " because failed to get current key status");
        return {};
    }
    if (status_of_ckey == 0) {
        KeyManager::getInstance().setCryptoMessage(peer_id, message_id, ckey_id);
        if (KeyManager::getInstance().changeKeyStatus(peer_id, ckey_id, 1)) {
            log::write(
                "INFO: Current key for peer with id ",
                peer_id,
                " was activated while encrypting message");
        } else {
            log::write("ERROR: Failed to activate current key for peer with id ", peer_id);
            return {};
        }
    }
    auto key_vector = KeyManager::getInstance().getCurrentKeyForPeer(peer_id);
    if (key_vector.empty()) {
        log::write(
            "ERROR: Failed to encrypt message for peer with id ",
            peer_id,
            " because failed to get current key");
        return {};
    }
    auto key = QByteArray(reinterpret_cast<const char*>(key_vector.data()), key_vector.size());
    QByteArray encrypted;
    if (aes_128::encrypt(content, key, encrypted)) {
        log::write("INFO: Message was encrypted for peer with id ", peer_id);
        return encrypted;
    }
    log::write("ERROR: Failed to encrypt message for peer with id ", peer_id);
    return {};
}

QByteArray decryptMessage(size_t peer_id, size_t message_id, const QByteArray& content) {
    if (!hasPeer(peer_id)) {
        return content;
    }
    // TODO: Refactor this part
    size_t first_crypto_message_id = KeyManager::getInstance().getFirstCryptoMessageId(peer_id);  //
    /*
    if (message_id < first_crypto_message_id) {
        return content;
    }
     */
    size_t last_crypto_message_id = KeyManager::getInstance().getLastCryptoMessageId(peer_id);
    if (message_id > last_crypto_message_id) {
        size_t ckey_id = getCurrentKeyId(peer_id);
        auto status_of_ckey = KeyManager::getInstance().getKeyStatus(peer_id, ckey_id);
        if (!status_of_ckey.has_value()) {
            log::write(
                "ERROR: Failed to decrypt message for peer with id ",
                peer_id,
                " because failed to get current key status");
            return {};
        }
        if (status_of_ckey == 0) {
            KeyManager::getInstance().setCryptoMessage(peer_id, message_id, ckey_id);
            if (KeyManager::getInstance().changeKeyStatus(peer_id, ckey_id, 1)) {
                log::write(
                    "INFO: current key for peer with id ",
                    peer_id,
                    " was activated while decrypting message");
            } else {
                log::write("ERROR: Failed to activate current key for peer with id ", peer_id);
                return {};
            }
        }
    }
    auto key_vector = KeyManager::getInstance().getKeyForCryptoMessage(peer_id, message_id);
    if (key_vector.empty()) {
        log::write(
            "ERROR: Failed to decrypt message for peer with id ",
            peer_id,
            " because failed to get key for crypto message with id ",
            message_id);
        return {};
    }
    auto key = QByteArray(reinterpret_cast<const char*>(key_vector.data()), key_vector.size());
    QByteArray decrypted;
    if (aes_128::decrypt(content, key, decrypted)) {
        log::write("INFO: Message was decrypted for peer with id ", peer_id);
        return decrypted;
    }
    log::write("ERROR: Failed to decrypt message for peer with id ", peer_id);
    return {};
}

}  // namespace local::api
