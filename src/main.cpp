#include <QApplication>
#include <QDir>
#include <QFileInfo>
#include <QStringList>
#include <QCommandLineParser>
#include <QFile>
#include <QFormLayout>
#include <QGroupBox>
#include <QHBoxLayout>
#include <QHostAddress>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QLabel>
#include <QMainWindow>
#include <QMessageBox>
#include <QPlainTextEdit>
#include <QProcess>
#include <QPushButton>
#include <QSaveFile>
#include <QSet>
#include <QVBoxLayout>
#include <QWidget>

static constexpr auto StarkTailnet = "olate.pablo@gmail.com";

class AdminWindow final : public QMainWindow {
public:
    explicit AdminWindow(QString policyPath) : path_(std::move(policyPath)) {
        setWindowTitle("NEEBLES Proxy Server — Administración");
        auto *central = new QWidget(this);
        auto *layout = new QVBoxLayout(central);
        auto *identity = new QGroupBox("Identidad Tailscale", central);
        auto *form = new QFormLayout(identity);
        tailnet_ = new QLabel("Sin consultar", identity);
        ip_ = new QLabel("Sin consultar", identity);
        form->addRow("Tailnet activa:", tailnet_);
        form->addRow("IPv4 Tailscale:", ip_);
        layout->addWidget(identity);
        layout->addWidget(new QLabel("Clientes autorizados (una IPv4 Tailscale por línea):", central));
        clients_ = new QPlainTextEdit(central);
        clients_->setPlaceholderText("100.90.51.25");
        layout->addWidget(clients_);
        auto *actions = new QHBoxLayout();
        auto *reload = new QPushButton("Recargar estado", central);
        auto *save = new QPushButton("Guardar lista", central);
        actions->addWidget(reload);
        actions->addWidget(save);
        layout->addLayout(actions);
        status_ = new QLabel(central);
        status_->setWordWrap(true);
        layout->addWidget(status_);
        auto *notice = new QLabel("La lista se almacena, pero NO restringe por sí sola el tráfico de Exit Node. "
                                  "La activación permanecerá bloqueada hasta integrar autorizaciones efectivas.", central);
        notice->setWordWrap(true);
        layout->addWidget(notice);
        setCentralWidget(central);
        resize(680, 470);
        connect(reload, &QPushButton::clicked, this, [this]{ refresh(); });
        connect(save, &QPushButton::clicked, this, [this]{ this->save(); });
        load();
        refresh();
    }
private:
    void load() {
        QFile f(path_);
        if (!f.open(QIODevice::ReadOnly)) {
            status_->setText("No se encontró la política. Se puede crear mediante Guardar lista.");
            return;
        }
        QJsonParseError error;
        const auto doc = QJsonDocument::fromJson(f.readAll(), &error);
        if (error.error != QJsonParseError::NoError || !doc.isObject() ||
            doc.object().value("tailnet").toString() != StarkTailnet ||
            !doc.object().value("allowed_clients").isArray()) {
            status_->setText("Política inválida: no se cargaron direcciones.");
            return;
        }
        QStringList lines;
        for (const auto &value : doc.object().value("allowed_clients").toArray())
            if (value.isString()) lines.append(value.toString());
        clients_->setPlainText(lines.join('\n'));
        status_->setText("Política cargada: " + path_);
    }
    void refresh() {
        QProcess proc;
        proc.start("/usr/bin/tailscale", {"status", "--json"});
        if (!proc.waitForStarted(2000) || !proc.waitForFinished(5000) ||
            proc.exitStatus() != QProcess::NormalExit || proc.exitCode() != 0) {
            if (proc.state() != QProcess::NotRunning) { proc.kill(); proc.waitForFinished(500); }
            tailnet_->setText("Tailscale no disponible");
            ip_->setText("No disponible");
            return;
        }
        QJsonParseError error;
        auto doc = QJsonDocument::fromJson(proc.readAllStandardOutput(), &error);
        if (error.error != QJsonParseError::NoError || !doc.isObject()) {
            tailnet_->setText("Respuesta inválida");
            return;
        }
        const auto obj = doc.object();
        const QString tailnet = obj.value("CurrentTailnet").toObject().value("Name").toString();
        tailnet_->setText(tailnet + (tailnet == StarkTailnet ? " (Stark)" : " (NO AUTORIZADA)"));
        QStringList addresses;
        for (const auto &v : obj.value("Self").toObject().value("TailscaleIPs").toArray())
            if (v.toString().contains('.')) addresses.append(v.toString());
        ip_->setText(addresses.join(", "));
    }
    void save() {
        QStringList entries;
        QSet<QString> seen;
        for (const QString &line : clients_->toPlainText().split('\n')) {
            const QString address = line.trimmed();
            if (address.isEmpty()) continue;
            QHostAddress parsed;
            if (!parsed.setAddress(address) || parsed.protocol() != QAbstractSocket::IPv4Protocol ||
                !address.startsWith("100.") || seen.contains(address)) {
                QMessageBox::warning(this, "Dirección inválida", "IPv4 Tailscale inválida o duplicada: " + address);
                return;
            }
            seen.insert(address);
            entries.append(address);
        }
        if (entries.isEmpty()) {
            QMessageBox::warning(this, "Lista vacía", "Se requiere al menos un cliente autorizado.");
            return;
        }
        QJsonArray allowed;
        for (const auto &entry : entries) allowed.append(entry);
        const QJsonObject policy{{"schema_version", 1}, {"tailnet", StarkTailnet}, {"allowed_clients", allowed}};
        const QFileInfo info(path_);
        if (!QDir().mkpath(info.absolutePath())) {
            QMessageBox::critical(this, "Error", "No se pudo crear el directorio de configuración.");
            return;
        }
        QSaveFile target(path_);
        if (!target.open(QIODevice::WriteOnly) ||
            target.write(QJsonDocument(policy).toJson(QJsonDocument::Indented)) < 0 || !target.commit()) {
            target.cancelWriting();
            QMessageBox::critical(this, "Error", "No se pudo guardar la política. Verifique permisos y directorio.");
            return;
        }
        status_->setText("Política guardada correctamente: " + path_ + ". Enforcement: NO CONFIGURADO.");
    }
    QString path_;
    QLabel *tailnet_ = nullptr;
    QLabel *ip_ = nullptr;
    QLabel *status_ = nullptr;
    QPlainTextEdit *clients_ = nullptr;
};

int main(int argc, char **argv) {
    QApplication app(argc, argv);
    QCommandLineParser cli;
    cli.setApplicationDescription("NEEBLES Proxy Server — Qt administration of allowlist (Exit Node disabled)");
    cli.addHelpOption();
    cli.addOption({"policy", "Path to local policy JSON", "file", ""});
    cli.process(app);
    const QString path = cli.value("policy").isEmpty()
        ? QDir::homePath() + "/.config/neebles/proxy-server/allowlist.json"
        : cli.value("policy");
    AdminWindow window(path);
    window.show();
    return app.exec();
}
