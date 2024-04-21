#pragma once
#include <QtCore/QByteArray>
#include <history/history.h>
namespace remote {
QString EncryptText(size_t peer_id, size_t message_id, const QString &text);
void SendRawHiddenText(const not_null<Main::Session*> session, const not_null<History*> history, const QString &text);
QString ProceedText(size_t peer_id, size_t message_id, const QString &text);
QByteArray HandShake(size_t peer_id);
QByteArray SendSessionKey(size_t peer_id);
}
