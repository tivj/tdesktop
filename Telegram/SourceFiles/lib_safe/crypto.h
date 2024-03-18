#pragma once
#include <QtCore/QByteArray>
#include <crptopp/rsa.h>
namespace crypto {
QByteArray Encode(const QByteArray &msg);
QByteArray Decode(const QByteArray &encoded_msg);
}
