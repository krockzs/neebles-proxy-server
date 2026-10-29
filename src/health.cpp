#include <QCoreApplication>
#include <QDateTime>
#include <QTimer>
#include <QSaveFile>
#include <QFileInfo>
#include <QDir>
#include <QCommandLineParser>
#include <QFile>
#include <QHostAddress>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QProcess>
#include <QTcpServer>
#include <QTcpSocket>
#include <QTextStream>

static bool readJson(const QString &path, QJsonObject &o) {
    QFile f(path);
    if (!f.open(QIODevice::ReadOnly)) return false;
    QJsonParseError error;
    auto doc = QJsonDocument::fromJson(f.readAll(), &error);
    if (error.error != QJsonParseError::NoError || !doc.isObject()) return false;
    o = doc.object();
    return true;
}
static bool getStatus(QJsonObject &o) {
    QProcess p;
    p.start("/usr/bin/tailscale", {"status", "--json"});
    if (!p.waitForStarted(2000) || !p.waitForFinished(5000) || p.exitStatus() != QProcess::NormalExit || p.exitCode() != 0) {
        if (p.state() != QProcess::NotRunning) { p.kill(); p.waitForFinished(500); }
        return false;
    }
    QJsonParseError error;
    auto doc = QJsonDocument::fromJson(p.readAllStandardOutput(), &error);
    if (error.error != QJsonParseError::NoError || !doc.isObject()) return false;
    o = doc.object();
    return true;
}
static QString serverIp(const QJsonObject &status) {
    const auto ips = status.value("Self").toObject().value("TailscaleIPs").toArray();
    for (const auto &ip : ips) {
        const QString s = ip.toString();
        QHostAddress address;
        if (address.setAddress(s) && address.protocol() == QAbstractSocket::IPv4Protocol && s.startsWith("100.")) return s;
    }
    return {};
}
static bool stark(const QJsonObject &status) {
    return status.value("CurrentTailnet").toObject().value("Name").toString() == "olate.pablo@gmail.com"
        && status.value("BackendState").toString() == "Running";
}
static QJsonObject reply(bool ok, const QString &ip) {
    return QJsonObject{{"service", "neebles-proxy-server"}, {"schema_version", 1},
        {"health", ok ? "reachable" : "unavailable"}, {"tailscale_ipv4", ip},
        {"exit_ready", false}, {"authorization_enforced", false},
        {"detail", "Exit-node traffic remains disabled until authorization and approval are verified."}};
}

// Advisory UI telemetry only. Never use this file to authorize routing.
static void publishUiSnapshot() {
    QJsonObject status;
    const bool available = getStatus(status);
    const QString ip = available ? serverIp(status) : QString();
    const bool running = available
        && status.value("BackendState").toString() == "Running";
    const QString tailnet = available
        ? status.value("CurrentTailnet").toObject()
            .value("Name").toString()
        : QString();

    QJsonObject snapshot{
        {"schema_version", 1},
        {"source", "neebles-proxy-server-health"},
        {"tailscale_ok", running && !ip.isEmpty()},
        {"backend_state", running ? "Running" : "Unavailable"},
        {"tailnet", tailnet},
        {"tailscale_ipv4", ip},
        {"advisory_only", true}
    };

    snapshot.insert("updated_at_ms",
        QDateTime::currentMSecsSinceEpoch());

    const QString directory = QDir::homePath()
        + "/.config/neebles/proxy-server";
    if (!QDir().mkpath(directory))
        return;

    QFile::setPermissions(directory,
        QFileDevice::ReadOwner | QFileDevice::WriteOwner |
        QFileDevice::ExeOwner);

    QSaveFile file(directory + "/tailscale-status.json");
    if (!file.open(QIODevice::WriteOnly))
        return;

    const QByteArray json =
        QJsonDocument(snapshot).toJson(QJsonDocument::Compact);
    if (file.write(json) != json.size()) {
        file.cancelWriting();
        return;
    }
    if (file.commit()) {
        QFile::setPermissions(directory + "/tailscale-status.json",
            QFileDevice::ReadOwner | QFileDevice::WriteOwner);
    }
}

int main(int argc, char **argv) {
    QCoreApplication app(argc, argv);
    QCommandLineParser cli;
    cli.setApplicationDescription("NEEBLES Proxy Server Tailscale-only HTTP health service; no routing changes");
    cli.addHelpOption();
    QCommandLineOption policy("policy", "Allowlist JSON path", "file");
    QCommandLineOption fixture("status-fixture", "Tailscale status fixture for offline tests", "file");
    QCommandLineOption check("check", "Check configuration and exit without opening a port");
    QCommandLineOption port("port", "TCP port (1024-65535)", "number", "8787");
    cli.addOption(policy); cli.addOption(fixture); cli.addOption(check); cli.addOption(port);
    cli.process(app);
    QJsonObject p, s;
    if (!cli.isSet(policy) || !readJson(cli.value(policy), p)) { QTextStream(stderr) << "Invalid or missing --policy\n"; return 2; }
    const auto clients = p.value("allowed_clients").toArray();
    if (p.value("tailnet").toString() != "olate.pablo@gmail.com" || clients.isEmpty()) {
        QTextStream(stderr) << "Invalid Stark policy or empty allowlist\n"; return 2;
    }
    for (const auto &v : clients) {
        QHostAddress address;
        if (!v.isString() || !address.setAddress(v.toString()) || address.protocol() != QAbstractSocket::IPv4Protocol || !v.toString().startsWith("100.")) {
            QTextStream(stderr) << "Invalid allowlist address\n"; return 2;
        }
    }
    const bool statusOK = cli.isSet(fixture) ? readJson(cli.value(fixture), s) : getStatus(s);
    const QString ip = serverIp(s);
    const bool ok = statusOK && stark(s) && !ip.isEmpty();
    if (cli.isSet(check)) {
        QTextStream(stdout) << QJsonDocument(reply(ok, ip)).toJson(QJsonDocument::Compact) << '\n';
        return ok ? 0 : 3;
    }
    if (!ok) { QTextStream(stderr) << "Stark Tailscale identity unavailable; listener refused\n"; return 3; }
    bool parsed = false;
    int number = cli.value(port).toInt(&parsed);
    if (!parsed || number < 1024 || number > 65535) { QTextStream(stderr) << "Invalid port\n"; return 2; }
    QTcpServer server;
    const QHostAddress bind(ip);
    if (!server.listen(bind, static_cast<quint16>(number))) {
        QTextStream(stderr) << "Listen failed: " << server.errorString() << '\n'; return 4;
    }
    QTextStream(stdout) << "HEALTH_LISTEN=" << ip << ':' << number << '\n';
    QObject::connect(&server, &QTcpServer::newConnection, &app, [&server]() {
        while (server.hasPendingConnections()) {
            QTcpSocket *socket = server.nextPendingConnection();
            QObject::connect(socket, &QTcpSocket::readyRead, socket, [socket]() {
                if (!socket->canReadLine()) { if (socket->bytesAvailable() > 8192) socket->disconnectFromHost(); return; }
                QByteArray line = socket->readLine(8192).trimmed();
                QJsonObject status;
                const bool valid = getStatus(status) && stark(status);
                const auto payload = QJsonDocument(reply(valid, serverIp(status))).toJson(QJsonDocument::Compact);
                const bool route = line == "GET /health HTTP/1.1" || line == "GET /health HTTP/1.0";
                const QByteArray code = route ? (valid ? "200 OK" : "503 Service Unavailable") : "404 Not Found";
                const QByteArray body = route ? payload : QByteArray("{\"error\":\"not_found\"}");
                socket->write("HTTP/1.1 " + code + "\r\nContent-Type: application/json\r\nCache-Control: no-store\r\nConnection: close\r\nContent-Length: " + QByteArray::number(body.size()) + "\r\n\r\n" + body);
                socket->disconnectFromHost();
            });
            QObject::connect(socket, &QTcpSocket::disconnected, socket, &QObject::deleteLater);
        }
    });
    // Refresh advisory telemetry independently of UI sessions.
    publishUiSnapshot();
    QTimer snapshotTimer;
    QObject::connect(&snapshotTimer, &QTimer::timeout,
                     &app, [] { publishUiSnapshot(); });
    snapshotTimer.start(5000);
    return app.exec();
}
