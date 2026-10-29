#include <QCoreApplication>
#include <QCommandLineParser>
#include <QFile>
#include <QJsonDocument>
#include <QJsonObject>
#include <QJsonArray>
#include <QProcess>
#include <QTextStream>
#include <QHostAddress>

static QString readKernelFlag(const QString &path) {
    QFile file(path);
    if (!file.open(QIODevice::ReadOnly | QIODevice::Text)) return QStringLiteral("unavailable");
    return QString::fromUtf8(file.readAll()).trimmed();
}

static QJsonObject inspect() {
    QJsonObject output;
    output.insert("schema_version", 1);
    output.insert("component", "neebles-proxy-server");
    output.insert("read_only", true);
    QJsonObject forwarding;
    forwarding.insert("ipv4", readKernelFlag("/proc/sys/net/ipv4/ip_forward"));
    forwarding.insert("ipv6", readKernelFlag("/proc/sys/net/ipv6/conf/all/forwarding"));
    output.insert("forwarding", forwarding);
    QProcess proc;
    proc.start("/usr/bin/tailscale", {"status", "--json"});
    if (!proc.waitForStarted(3000)) {
        output.insert("tailscale_ok", false);
        output.insert("error", "tailscale executable unavailable");
        return output;
    }
    if (!proc.waitForFinished(5000)) {
        proc.kill(); proc.waitForFinished(1000);
        output.insert("tailscale_ok", false);
        output.insert("error", "tailscale status timed out");
        return output;
    }
    QJsonParseError error;
    auto document = QJsonDocument::fromJson(proc.readAllStandardOutput(), &error);
    if (proc.exitCode() != 0 || error.error != QJsonParseError::NoError || !document.isObject()) {
        output.insert("tailscale_ok", false);
        output.insert("error", "tailscale returned an invalid status");
        return output;
    }
    const QJsonObject status = document.object();
    const QJsonObject self = status.value("Self").toObject();
    const QJsonObject tailnet = status.value("CurrentTailnet").toObject();
    const QString tailnetName = tailnet.value("Name").toString();
    const QJsonArray ips = self.value("TailscaleIPs").toArray();
    QJsonArray v4;
    for (const auto &item: ips) {
        QHostAddress ip(item.toString());
        if (ip.protocol() == QAbstractSocket::IPv4Protocol) v4.append(ip.toString());
    }
    output.insert("tailscale_ok", true);
    output.insert("backend_state", status.value("BackendState").toString());
    output.insert("tailnet", tailnetName);
    output.insert("host", self.value("HostName").toString());
    output.insert("tailscale_ipv4", v4);
    output.insert("exit_node_advertised", self.value("ExitNodeOption").toBool(false));
    // Tailnet identity is intentionally NOT inferred from an IP prefix.
    output.insert("stark_candidate", tailnetName == "olate.pablo@gmail.com");
    output.insert("ready_for_advertising", false);
    output.insert("note", "Read-only inspection only; forwarding, exit-node approval and ACLs are not configured.");
    return output;
}

int main(int argc, char **argv) {
    QCoreApplication app(argc, argv);
    QCoreApplication::setApplicationName("neebles-proxy-server-inspect");
    QCommandLineParser parser;
    parser.setApplicationDescription("NEEBLES Proxy Server - read-only Tailscale inspector");
    parser.addHelpOption();
    parser.addOption({"json", "Print sanitized JSON snapshot (default)."});
    parser.process(app);
    QTextStream out(stdout);
    out << QJsonDocument(inspect()).toJson(QJsonDocument::Indented);
    out.flush();
    return 0;
}
