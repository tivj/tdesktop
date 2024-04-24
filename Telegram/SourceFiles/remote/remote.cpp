#include <remote/remote.h>
#include <data/data_peer_id.h>
#include <data/data_histories.h>
#include <data/data_session.h>
#include <base/random.h>
#include <tg_local_lib/local.h>
#include <remote/message_crypto_wraper.h>
#include <fstream>
#include <QtCore/QDir>
#include "main/main_session.h"
#include <tg_local_lib/log.h>
#include "remote/state.h"
#include <history/history_widget.h>
#include <main/session/send_as_peers.h>
#include <apiwrap.h>
QByteArray remote::HandShake(size_t peer_id) {
    QByteArray start_msg = remote::MessageCryptoWraper::InitiateHandShake(peer_id).toBase64();
    return start_msg;
}
QByteArray remote::SendSessionKey(size_t peer_id) {
    QByteArray session_msg = remote::MessageCryptoWraper::SendSessionKey(peer_id).toBase64();
    return session_msg;
}
QString remote::ProceedText(size_t peer_id, int64 message_id, const QString &text) {
    ///Message is key:
    QByteArray text_bytes = text.toUtf8();
    std::ofstream out("./my_log.txt", std::ios::app);
    out << "Proceed\n";
    for (int i = 0; i < text_bytes.size(); ++i) {
        out << (int)text_bytes[i] << " ";
    }
    out << "\n";
    QByteArray text_bytes_64 = QByteArray::fromBase64(text_bytes);
    out << "Base64\n";
    for (int i = 0; i < text_bytes_64.size(); ++i) {
        out << (int)text_bytes_64[i] << " ";
    }
    out << "\n";
    if (!MessageCryptoWraper::IsMCW(text_bytes_64)) { ///Message is not key
        QByteArray decrypted_text = local::api::decryptMessage(peer_id, message_id, text_bytes_64);
        if (decrypted_text == text_bytes_64 || decrypted_text.isEmpty()) {
            return text;
        }
        return decrypted_text;
    }
    /*
    if (peer_id == session->userId()) {
        return QString();
    }
     */
    out << (int)text_bytes_64[9] << "\n";
    QByteArray bytes = text_bytes_64.sliced(10);
    out << "Base64(removed)\n";
    for (int i = 0; i < bytes.size(); ++i) {
        out << (int)bytes[i] << " ";
    }
    out << "\n";
    out.close();
    remote::MessageCryptoWraper msw(text_bytes_64[9], bytes);
    QByteArray answer = msw.Proceed(peer_id);
    if (!answer.isEmpty()) {
        // remote::SendRawHiddenText(session, history, QString::fromUtf8(answer));
    }
    return QString("Some shit");
}
void remote::SendRawHiddenText(not_null<Main::Session*> session, const not_null<History*> history, const QString &text) {
    // session->data().peer;
    const auto peer = history->peer;
    PeerId id = peer->id;
    auto newId = FullMsgId(
			peer->id,
			session->data().nextLocalMessageId());
	auto randomId = base::RandomValue<uint64>();
    const auto sendAs = history->session().sendAsPeers().resolveChosen(history->peer).get();
    Api::SendAction action(history, {.sendAs = sendAs});
    session->api().sendAction(action);
    session->data().registerMessageRandomId(randomId, newId);
	session->data().registerMessageSentData(
			randomId,
			peer->id,
			text);
    if (!local::api::hasPeer(id.value)) {
        local::api::addPeer(id.value);
    }
    // local::api::addMessageToHide(id.value, newId.msg.bare);
    MTPstring text_string = MTP_string(QString(text));
    const auto clearCloudDraft = true;
    const auto draftTopicRootId = 0;
    const auto done = [=](
            const MTPUpdates &result,
            const MTP::Response &response) {
    };
    const auto fail = [=](
            const MTP::Error &error,
            const MTP::Response &response) {
    };
    auto& histories = history->owner().histories();
    histories.sendPreparedMessage(
        history,
        FullReplyTo(),
        randomId,
        Data::Histories::PrepareMessage<MTPmessages_SendMessage>(
            MTP_flags(MTPmessages_SendMessage::Flags(0)),
            peer->input,
            Data::Histories::ReplyToPlaceholder(),
            text_string,
            MTP_long(randomId),
            MTPReplyMarkup(),
            MTP_vector<MTPMessageEntity>(QVector<MTPMessageEntity>()),
            MTP_int(0),
            (sendAs ? sendAs->input : MTP_inputPeerEmpty())
        ), done, fail);
}
QString remote::EncryptText(size_t peer_id, int64 message_id, const QString &text) {
    // remote::SendRawHiddenText(session, history, text);
    if (text == "Create key") {
        return HandShake(peer_id);
    }
    if (text == "Send session") {
        return remote::SendSessionKey(peer_id);
    }
    QByteArray text_bytes = text.toUtf8();
    if (local::api::hasPeer(peer_id)) {
        
        QByteArray encrypted_text = local::api::encryptMessage(peer_id, message_id, text_bytes);
        return QString::fromUtf8(encrypted_text.toBase64());
    }
    return text_bytes;
}

