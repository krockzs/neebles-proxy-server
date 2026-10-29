#include <QCoreApplication>
#include <QFile>
#include <QCommandLineParser>
#include <QHostInfo>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QProcess>
#include <QTextStream>
#include <unistd.h>

static constexpr auto Host = "server-20fms4udus";
static constexpr auto Tailnet = "olate.pablo@gmail.com";
static constexpr auto ServerIP = "100.71.3.52";

static bool status(QJsonObject &out) {
    QProcess p;
    p.start("/usr/bin/tailscale", {"status", "--json"});
    if (!p.waitForStarted(2000) ||
        !p.waitForFinished(5000) ||
        p.exitStatus() != QProcess::NormalExit ||
        p.exitCode() != 0) {
        if (p.state() != QProcess::NotRunning) {
            p.kill();
            p.waitForFinished(500);
        }
        return false;
    }
    QJsonParseError error;
    auto doc = QJsonDocument::fromJson(
        p.readAllStandardOutput(), &error);
    if (error.error != QJsonParseError::NoError ||
        !doc.isObject())
        return false;

    out = doc.object();
    return true;
}

static bool identity(const QJsonObject &s) {
    if (QHostInfo::localHostName() != Host)
        return false;
    if (s.value("BackendState").toString() != "Running")
        return false;
    if (s.value("CurrentTailnet").toObject()
            .value("Name").toString() != Tailnet)
        return false;

    const auto ips = s.value("Self").toObject()
                         .value("TailscaleIPs").toArray();
    for (const auto &ip : ips)
        if (ip.toString() == ServerIP)
            return true;

    return false;
}

int main(int argc, char **argv) {
    QCoreApplication app(argc, argv);
    QCommandLineParser cli;
    cli.setApplicationDescription(
        "NEEBLES Proxy Server privileged native operation");
    cli.addHelpOption();
    // F22_READONLY_PREFLIGHT: diagnose the dedicated host without privilege or mutation.
    cli.addOption({"preflight", "Read-only identity, forwarding and Exit Node status."});
    cli.addOption({"deactivate",
        "Disable Exit Node advertisement on the dedicated server."});
    cli.process(app);

    if (cli.isSet("preflight")) {
        if (cli.isSet("deactivate")) {
            QTextStream(stderr) << "Conflicting operations\n";
            return 2;
        }
        QJsonObject current;
        const bool queried = status(current);
        const bool recognized = queried && identity(current);
        QFile forwarding("/proc/sys/net/ipv4/ip_forward");
        bool forwardingEnabled = false;
        if (forwarding.open(QIODevice::ReadOnly))
            forwardingEnabled = forwarding.readAll().trimmed() == "1";
        QJsonObject result{
            {"schema", 1}, {"operation", "preflight"},
            {"read_only", true},
            {"identity_verified", recognized},
            {"ipv4_forwarding", forwardingEnabled},
            {"exit_node_advertised", queried && current.value("Self").toObject().value("ExitNodeOption").toBool(false)},
            {"live_acl_verified", false},
            {"client_egress_verified", false},
            {"ready_for_activation", false}
        };
        QTextStream(stdout) << QJsonDocument(result).toJson(QJsonDocument::Compact) << "\n";
        return recognized && forwardingEnabled ? 0 : 7;
    }
    if (!cli.isSet("deactivate")) {
        QTextStream(stderr) << "Operation required\n";
        return 2;
    }

    if (geteuid() != 0) {
        QTextStream(stderr) << "Root authority required\n";
        return 3;
    }

    QJsonObject before;
    if (!status(before) || !identity(before)) {
        QTextStream(stderr) << "Server identity rejected\n";
        return 4;
    }

    QProcess process;
    process.start("/usr/bin/tailscale",
                  {"set", "--advertise-exit-node=false"});

    if (!process.waitForStarted(2000) ||
        !process.waitForFinished(10000) ||
        process.exitStatus() != QProcess::NormalExit ||
        process.exitCode() != 0) {
        if (process.state() != QProcess::NotRunning) {
            process.kill();
            process.waitForFinished(500);
        }
        QTextStream(stderr) << "Deactivation failed\n";
        return 5;
    }

    QJsonObject after;
    if (!status(after) || !identity(after) ||
        after.value("Self").toObject()
            .value("ExitNodeOption").toBool(true)) {
        QTextStream(stderr)
            << "Advertisement deactivation not confirmed\n";
        return 6;
    }

    QTextStream(stdout)
        << "{\"ok\":true,\"advertisement_confirmed_off\":true}\n";
    return 0;
}
