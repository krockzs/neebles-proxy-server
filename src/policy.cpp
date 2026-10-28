#include <QCoreApplication>
#include <QCommandLineParser>
#include <QFile>
#include <QJsonDocument>
#include <QJsonObject>
#include <QJsonArray>
#include <QHostAddress>
#include <QSet>
#include <QProcess>
#include <QTextStream>

static QJsonObject validate(const QJsonObject &policy, const QJsonObject &status) {
    QJsonObject result{{"schema_version",1},{"component","neebles-proxy-server-policy"},{"read_only",true}};
    QJsonArray errors, approved;
    const auto tailnet=policy.value("tailnet").toString();
    if(tailnet.isEmpty() || tailnet!="olate.pablo@gmail.com") errors.append("policy tailnet must be Stark");
    const auto nodes=policy.value("allowed_clients");
    if(!nodes.isArray()) errors.append("allowed_clients must be an array");
    else {
        QSet<QString> seen;
        for(const auto &item: nodes.toArray()) {
            if(!item.isString()) {errors.append("allowed client must be an IPv4 string");continue;}
            const QString s=item.toString(); QHostAddress ip;
            if(!ip.setAddress(s) || ip.protocol()!=QAbstractSocket::IPv4Protocol || !s.startsWith("100.") || seen.contains(s)) {
                errors.append("invalid or duplicate client address: "+s);continue;
            }
            seen.insert(s);approved.append(s);
        }
    }
    const auto liveTailnet=status.value("CurrentTailnet").toObject().value("Name").toString();
    if(liveTailnet != tailnet) errors.append("active tailnet does not match policy");
    if(status.value("BackendState").toString()!="Running") errors.append("tailscaled is not running");
    result.insert("tailnet",tailnet);
    result.insert("active_tailnet",liveTailnet);
    result.insert("allowed_clients",approved);
    result.insert("errors",errors);
    result.insert("valid",errors.isEmpty());
    result.insert("enforcement","not_configured");
    result.insert("notice","This validator does not grant or block exit-node access. Tailnet grants/ACLs must be enforced separately.");
    return result;
}
static bool loadJson(const QString &path,QJsonObject &obj) {
    QFile file(path); if(!file.open(QIODevice::ReadOnly))return false;
    QJsonParseError e; auto d=QJsonDocument::fromJson(file.readAll(),&e);
    if(e.error!=QJsonParseError::NoError || !d.isObject())return false;
    obj=d.object();return true;
}
int main(int argc,char **argv){
    QCoreApplication app(argc,argv);
    QCommandLineParser parser;
    parser.setApplicationDescription("NEEBLES Proxy Server - read-only whitelist policy validation");
    parser.addHelpOption();
    QCommandLineOption fileOpt("policy","Policy JSON path","file");
    QCommandLineOption fixtureOpt("status-fixture","Read status JSON from a fixture rather than calling Tailscale","file");
    parser.addOption(fileOpt);parser.addOption(fixtureOpt);parser.process(app);
    if(!parser.isSet(fileOpt)){QTextStream(stderr)<<"--policy is required\n";return 2;}
    QJsonObject policy,status;
    if(!loadJson(parser.value(fileOpt),policy)){QTextStream(stderr)<<"Could not parse policy\n";return 2;}
    if(parser.isSet(fixtureOpt)){
        if(!loadJson(parser.value(fixtureOpt),status)){QTextStream(stderr)<<"Could not parse status fixture\n";return 2;}
    } else {
        QProcess p; p.start("/usr/bin/tailscale",{"status","--json"});
        if(!p.waitForStarted(2000)||!p.waitForFinished(5000)||p.exitCode()!=0){
            if(p.state()!=QProcess::NotRunning){p.kill();p.waitForFinished(500);}
            QTextStream(stderr)<<"Tailscale status unavailable\n";return 3;
        }
        QJsonParseError err; auto d=QJsonDocument::fromJson(p.readAllStandardOutput(),&err);
        if(err.error!=QJsonParseError::NoError || !d.isObject()){QTextStream(stderr)<<"Invalid Tailscale status\n";return 3;}
        status=d.object();
    }
    auto result=validate(policy,status);
    QTextStream(stdout)<<QJsonDocument(result).toJson(QJsonDocument::Indented);
    return result.value("valid").toBool()?0:1;
}
