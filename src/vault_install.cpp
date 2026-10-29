#include "vault_install.h"

#include <QByteArray>
#include <QDir>
#include <QElapsedTimer>
#include <QJsonDocument>
#include <QJsonObject>
#include <QLocalSocket>
#include <QtEndian>

namespace {
constexpr int TimeoutMs = 35000;
constexpr quint32 MaxFrame = 16u * 1024u * 1024u;
const QString Module = QStringLiteral("neebles-proxy-server");

bool readBytes(QLocalSocket &socket, QByteArray &out,
               qsizetype length, QElapsedTimer &clock) {
    while (out.size() < length) {
        const QByteArray available = socket.read(length - out.size());
        if (!available.isEmpty()) {
            out.append(available);
            continue;
        }
        const int remaining = TimeoutMs - int(clock.elapsed());
        if (remaining <= 0 || !socket.waitForReadyRead(remaining))
            return false;
    }
    return true;
}

bool writeBytes(QLocalSocket &socket, const QByteArray &bytes,
                QElapsedTimer &clock) {
    qsizetype offset = 0;
    while (offset < bytes.size()) {
        const qint64 written = socket.write(bytes.constData() + offset,
                                           bytes.size() - offset);
        if (written < 0)
            return false;
        offset += written;
        const int remaining = TimeoutMs - int(clock.elapsed());
        if (remaining <= 0 || !socket.waitForBytesWritten(remaining))
            return false;
    }
    return true;
}
}

bool ensureProxyVault(QString *error) {
    // F21_MODULE_ENV_GATE: Boss identity and requested vault may never diverge.
    const QByteArray injectedModule = qgetenv("NEEBLES_MODULE");
    if (!injectedModule.isEmpty() && injectedModule != QByteArray("neebles-proxy-server")) {
        if (error) *error = QStringLiteral("Identidad de módulo no autorizada");
        return false;
    }

    const QByteArray runtime = qgetenv("XDG_RUNTIME_DIR");
    if (runtime.isEmpty() || !QDir::isAbsolutePath(QString::fromUtf8(runtime))) {
        if (error) *error = QStringLiteral("XDG_RUNTIME_DIR inválido");
        return false;
    }

    const QString path = QString::fromUtf8(runtime)
        + QStringLiteral("/neebles-secrets/secrets.sock");

    QLocalSocket socket;
    socket.connectToServer(path, QIODevice::ReadWrite);
    if (!socket.waitForConnected(TimeoutMs)) {
        if (error) *error = QStringLiteral(
            "NEEBLES Secrets no está disponible en la sesión autorizada");
        return false;
    }

    const QJsonObject request{
        {QStringLiteral("op"), QStringLiteral("vault.ensure")},
        {QStringLiteral("module"), Module}
    };
    const QByteArray payload = QJsonDocument(request).toJson(
        QJsonDocument::Compact);

    QElapsedTimer timer;
    timer.start();

    QByteArray frame(4, '\0');
    qToBigEndian<quint32>(quint32(payload.size()),
                          reinterpret_cast<uchar *>(frame.data()));
    frame += payload;

    if (!writeBytes(socket, frame, timer)) {
        if (error) *error = QStringLiteral("Error enviando solicitud a Secrets");
        return false;
    }

    QByteArray header;
    if (!readBytes(socket, header, 4, timer)) {
        if (error) *error = QStringLiteral("Sin encabezado de respuesta de Secrets");
        return false;
    }

    const quint32 size = qFromBigEndian<quint32>(
        reinterpret_cast<const uchar *>(header.constData()));

    if (size == 0 || size > MaxFrame) {
        if (error) *error = QStringLiteral("Respuesta IPC de tamaño inválido");
        return false;
    }

    QByteArray responseBytes;
    if (!readBytes(socket, responseBytes, size, timer)) {
        if (error) *error = QStringLiteral("Respuesta IPC incompleta");
        return false;
    }

    QJsonParseError parseError;
    const QJsonDocument response =
        QJsonDocument::fromJson(responseBytes, &parseError);

    if (parseError.error != QJsonParseError::NoError ||
        !response.isObject()) {
        if (error) *error = QStringLiteral("Respuesta JSON inválida de Secrets");
        return false;
    }

    const QJsonObject result = response.object();
    if (result.value(QStringLiteral("ok")).toBool() != true) {
        if (error) *error = QStringLiteral("Secrets rechazó vault.ensure");
        return false;
    }

    const QJsonObject data = result.value(QStringLiteral("data")).toObject();
    if (data.value(QStringLiteral("module")).toString() != Module ||
        data.value(QStringLiteral("exists")).toBool() != true) {
        if (error) *error = QStringLiteral(
            "Secrets no confirmó la bóveda exclusiva de Proxy Server");
        return false;
    }

    return true;
}
