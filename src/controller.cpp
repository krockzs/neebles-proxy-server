#include <QCoreApplication>
#include <QCommandLineParser>
#include <QFile>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QProcess>
#include <QSet>
#include <QHostAddress>
#include <QTextStream>
#include <QStringList>
#include <unistd.h>

static bool load(const QString &path,QJsonObject &out){
    QFile f(path); if(!f.open(QIODevice::ReadOnly)) return false;
    QJsonParseError e; const auto doc=QJsonDocument::fromJson(f.readAll(),&e);
    if(e.error!=QJsonParseError::NoError||!doc.isObject())return false;
    out=doc.object();return true;
}
static bool tailscale(QJsonObject &out){
    QProcess p; p.start("/usr/bin/tailscale",{"status","--json"});
    if(!p.waitForStarted(2000)||!p.waitForFinished(5000)||p.exitStatus()!=QProcess::NormalExit||p.exitCode()!=0){
        if(p.state()!=QProcess::NotRunning){p.kill();p.waitForFinished(500);}return false;
    }
    QJsonParseError e; auto doc=QJsonDocument::fromJson(p.readAllStandardOutput(),&e);
    if(e.error!=QJsonParseError::NoError||!doc.isObject())return false;
    out=doc.object();return true;
}
static QString flag(const char *path){QFile f(QString::fromLatin1(path)); if(!f.open(QIODevice::ReadOnly))return "unavailable";return QString::fromUtf8(f.readAll()).trimmed();}
static QJsonObject plan(const QJsonObject &policy,const QJsonObject &status){
    QJsonArray blockers,clients,steps;
    const QString expected="olate.pablo@gmail.com";
    const QString tailnet=policy.value("tailnet").toString();
    const QString actual=status.value("CurrentTailnet").toObject().value("Name").toString();
    if(tailnet!=expected)blockers.append("policy_tailnet_not_stark");
    if(actual!=expected)blockers.append("active_tailnet_not_stark");
    if(status.value("BackendState").toString()!="Running")blockers.append("tailscale_not_running");
    const auto raw=policy.value("allowed_clients");
    if(!raw.isArray()||raw.toArray().isEmpty())blockers.append("allowlist_empty_or_invalid");
    else {
        QSet<QString> seen;
        for(const auto &v:raw.toArray()){
            const QString s=v.toString(); QHostAddress addr;
            if(!v.isString()||!addr.setAddress(s)||addr.protocol()!=QAbstractSocket::IPv4Protocol||!s.startsWith("100.")||seen.contains(s)){
                blockers.append("allowlist_invalid_or_duplicate");break;
            }
            seen.insert(s);clients.append(s);
        }
    }
    // Planning is not authorization. An exit node forwards IP traffic outside this app.
    blockers.append("tailnet_acl_enforcement_not_verified");
    blockers.append("exit_node_approval_not_verified");
    steps.append("verify_tailnet_grants_and_exit_node_approval_outside_module");
    steps.append("configure_forwarding_via_privileged_boss_service");
    steps.append("advertise_exit_node_via_tailscale_set");
    steps.append("verify_actual_advertisement_and_approval");
    steps.append("perform_end_to_end_client_egress_test");
    return QJsonObject{
        {"schema_version",1},{"component","neebles-proxy-server-controller"},
        {"mode","plan_only"},{"read_only",true},{"eligible_for_activation",false},
        {"tailnet",actual},{"server_ips",status.value("Self").toObject().value("TailscaleIPs").toArray()},
        {"allowed_clients",clients},{"forwarding_ipv4",flag("/proc/sys/net/ipv4/ip_forward")},
        {"forwarding_ipv6",flag("/proc/sys/net/ipv6/conf/all/forwarding")},
        {"blockers",blockers},{"planned_steps",steps},
        {"authorization_note","Local allowlist does not enforce Tailscale exit-node access; tailnet grants or firewall enforcement are required."}
    };
}
int main(int argc,char **argv){
    QCoreApplication app(argc,argv);
    QCommandLineParser cli;
    cli.setApplicationDescription("NEEBLES Proxy Server - safe exit-node activation planner (read-only)");
    cli.addHelpOption();
    QCommandLineOption p("policy","Path to allowlist policy","file");
    QCommandLineOption f("status-fixture","Path to Tailscale status fixture for tests","file");
    QCommandLineOption disable("deactivate", "Revoke Exit Node advertisement on the dedicated server (requires root).");
    QCommandLineOption activate("activate", "Request Exit Node activation; fail closed until ACL enforcement is verified.");
    cli.addOption(p);cli.addOption(f);cli.addOption(disable);cli.addOption(activate);cli.process(app);
    if(cli.isSet(disable) && cli.isSet(activate)) { QTextStream(stderr)<<"Conflicting operations\n";return 2; }
    if(cli.isSet(disable)) {
        if(cli.isSet(f)) { QTextStream(stderr)<<"Fixture prohibited for state-changing operation\n";return 2; }
        QJsonObject current;
        if(!tailscale(current)) { QTextStream(stderr)<<"Tailscale unavailable\n";return 3; }
        const QString tailnet=current.value("CurrentTailnet").toObject().value("Name").toString();
        const QStringList ips=current.value("Self").toObject().value("TailscaleIPs").toVariant().toStringList();
        if(tailnet!="olate.pablo@gmail.com" || !ips.contains("100.71.3.52")) {
            QTextStream(stderr)<<"Refusing operation: unexpected tailnet or dedicated server\n"; return 4;
        }
        if(geteuid()!=0) { QTextStream(stderr)<<"Root required; invoke via authorized Boss lifecycle\n";return 5; }
        QProcess action;
        action.start("/usr/bin/tailscale", {"set", "--advertise-exit-node=false"});
        if(!action.waitForStarted(2000) || !action.waitForFinished(10000) ||
           action.exitStatus()!=QProcess::NormalExit || action.exitCode()!=0) {
            if(action.state()!=QProcess::NotRunning){action.kill();action.waitForFinished(500);}
            QTextStream(stderr)<<"Disable failed: "<<QString::fromUtf8(action.readAllStandardError())<<"\n";return 6;
        }
        QTextStream(stdout)<<"EXIT_NODE_ADVERTISEMENT_DISABLED\n";
        return 0;
    }
    if(cli.isSet(activate)) {
        QTextStream(stderr)<<"ACTIVATION_BLOCKED: server-side ACL enforcement and tailnet grants not verified\n";
        return 7;
    }
    if(!cli.isSet(p)){QTextStream(stderr)<<"--policy required\n";return 2;}
    QJsonObject policy,status;
    if(!load(cli.value(p),policy)){QTextStream(stderr)<<"Invalid policy JSON\n";return 2;}
    if(!(cli.isSet(f)?load(cli.value(f),status):tailscale(status))){QTextStream(stderr)<<"Tailscale status unavailable\n";return 3;}
    QTextStream(stdout)<<QJsonDocument(plan(policy,status)).toJson(QJsonDocument::Indented);
    return 0;
}
