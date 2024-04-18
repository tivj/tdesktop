#pragma once
#include <QtCore/QByteArray>
#include <history/history.h>
namespace remote {
QString EncryptText(const not_null<Main::Session*> session, const not_null<History*> history, Api::SendAction &action, const QString &text);
void SendRawHiddenText(const not_null<Main::Session*> session, const not_null<History*> history, const QString &text);
QString ProceedText(const not_null<Main::Session*> session, const not_null<History*> history, size_t message_id, const QString &text);
QByteArray HandShake(const not_null<Main::Session*> session, const not_null<History*> history, Api::SendAction &action);
QByteArray SendSessionKey(PeerId peer_id);
}
