#include "vault_install.h"
#include <QApplication>
#include <QLocalSocket>
#include <QColor>
#include <QPainter>
#include <QCoreApplication>
#include <QDateTime>
#include <QStyleFactory>
#include <QTimer>
#include <QSplashScreen>
#include <QPixmap>
#include <QIcon>
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


static QString neeblesTheme() {
    return QStringLiteral(R"QSS(
        QWidget {
            background-color: #10131d;
            color: #e7edf8;
            font-family: "Noto Sans", sans-serif;
            font-size: 12px;
        }
        QMainWindow { background-color: #10131d; }
        QGroupBox {
            background-color: #191d2c;
            border: 1px solid #313a55;
            border-radius: 9px;
            margin-top: 12px;
            padding: 14px;
            font-weight: 600;
        }
        QGroupBox::title {
            subcontrol-origin: margin;
            left: 12px;
            padding: 0 6px;
            color: #65ddeb;
        }
        QPlainTextEdit {
            background-color: #131827;
            color: #edf5ff;
            border: 1px solid #39435e;
            border-radius: 8px;
            padding: 9px;
            selection-background-color: #7355c6;
        }
        QPlainTextEdit:focus {
            border-color: #4fc9de;
        }
        QPushButton {
            background-color: #252c42;
            color: #eaf4ff;
            border: 1px solid #465377;
            border-radius: 7px;
            padding: 9px 16px;
            font-weight: 600;
        }
        QPushButton:hover {
            background-color: #30415c;
            border-color: #50d4e8;
        }
        QPushButton:pressed {
            background-color: #453a76;
        }
        QPushButton:disabled {
            color: #777f92;
            background-color: #202330;
        }
        QLabel { background: transparent; }
        QMessageBox {
            background-color: #171c2a;
            color: #e7edf8;
        }
        QScrollBar:vertical {
            background: #151928;
            width: 11px;
        }
        QScrollBar::handle:vertical {
            background: #45516c;
            border-radius: 4px;
            min-height: 24px;
        }
    )QSS");
}

static constexpr auto StarkTailnet = "olate.pablo@gmail.com";


static QJsonObject requestLocal(const QJsonObject &request) {
    const QString runtime=qEnvironmentVariable("XDG_RUNTIME_DIR");
    QLocalSocket socket;
    socket.connectToServer(runtime+"/neebles/proxy-server.sock");
    if (!socket.waitForConnected(1200)) return QJsonObject{{"ok",false},{"error","socket_unavailable"}};
    const QByteArray message=QJsonDocument(request).toJson(QJsonDocument::Compact)+"\n";
    if (socket.write(message)!=message.size() || !socket.waitForBytesWritten(1200))
        return QJsonObject{{"ok",false},{"error","write_timeout"}};
    if (!socket.waitForReadyRead(3500)) return QJsonObject{{"ok",false},{"error","read_timeout"}};
    QByteArray response=socket.readAll();
    if (response.size()>8192) return QJsonObject{{"ok",false},{"error","oversize_response"}};
    QJsonParseError error;
    const QJsonDocument document=QJsonDocument::fromJson(response.trimmed(),&error);
    if (error.error!=QJsonParseError::NoError || !document.isObject())
        return QJsonObject{{"ok",false},{"error","invalid_response"}};
    return document.object();
}

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
        const QJsonObject answer=requestLocal(QJsonObject{{"op","policy.get"}});
        if (!answer.value("ok").toBool()) {
            status_->setText("Política no disponible: "+answer.value("error").toString());
            return;
        }
        const QJsonObject policy=answer.value("policy").toObject();
        QStringList entries;
        for (const auto &v:policy.value("allowed_clients").toArray())
            if (v.isString()) entries.append(v.toString());
        clients_->setPlainText(entries.join('\n'));
        status_->setText("Política persistente cargada desde Health. Enforcement: NO CONFIGURADO.");
    }
    void refresh() {
        const QJsonObject answer=requestLocal(QJsonObject{{"op","status"}});
        if (!answer.value("ok").toBool()) {
            tailnet_->setText("Health IPC no disponible");
            ip_->setText("No disponible");
            return;
        }
        const bool running=answer.value("tailscale_ok").toBool();
        const QString tailnet=answer.value("tailnet").toString();
        const QString ip=answer.value("tailscale_ipv4").toString();
        tailnet_->setText(running ? tailnet+(tailnet==StarkTailnet ? " (Stark)" : " (NO AUTORIZADA)") : "Tailscale no disponible");
        ip_->setText(running ? ip : "No disponible");
    }
    void save() {
        QJsonArray allowed;
        QSet<QString> seen;
        for (const auto &line:clients_->toPlainText().split('\n')) {
            const QString address=line.trimmed();
            if (address.isEmpty()) continue;
            QHostAddress parsed;
            if (!parsed.setAddress(address) || parsed.protocol()!=QAbstractSocket::IPv4Protocol ||
                !address.startsWith("100.") || seen.contains(address)) {
                QMessageBox::warning(this,"Dirección inválida","IPv4 Tailscale inválida o duplicada: "+address);
                return;
            }
            seen.insert(address); allowed.append(address);
        }
        if (allowed.isEmpty()) { QMessageBox::warning(this,"Lista vacía","Se requiere al menos un cliente.");return; }
        const QJsonObject policy{{"schema_version",1},{"tailnet",StarkTailnet},{"allowed_clients",allowed}};
        const QJsonObject answer=requestLocal(QJsonObject{{"op","policy.set"},{"policy",policy}});
        if (!answer.value("ok").toBool()) {
            QMessageBox::critical(this,"Error", "Health no guardó la política: "+answer.value("error").toString());
            return;
        }
        status_->setText("Política persistente guardada. Enforcement: NO CONFIGURADO.");
    }
    QString path_;
    QLabel *tailnet_ = nullptr;
    QLabel *ip_ = nullptr;
    QLabel *status_ = nullptr;
    QPlainTextEdit *clients_ = nullptr;
};

int main(int argc, char **argv) {
    // Lifecycle install/update: no QApplication and no GUI session required.
    if (argc == 3 &&
        QString::fromLocal8Bit(argv[1]) == QStringLiteral("--intent") &&
        QString::fromLocal8Bit(argv[2]) == QStringLiteral("install-vault")) {
        QString error;
        if (!ensureProxyVault(&error)) {
            fprintf(stderr, "PROXY_VAULT_INSTALL_FAILED: %s\n",
                    qPrintable(error));
            return 1;
        }
        puts("PROXY_VAULT_READY");
        return 0;
    }
    // Governor/CUSTOM V2 canonical Open intent; reject unrelated intents.
    if (argc == 3 &&
        QString::fromLocal8Bit(argv[1]) == QStringLiteral("--intent") &&
        QString::fromLocal8Bit(argv[2]) == QStringLiteral("open")) {
        argc = 1;  // QApplication and Qt parser see no extra arguments.
    }
    // F21_REQUIRE_CANONICAL_INTENT: never interpret an unsupported lifecycle intent as GUI flags.
    if (argc >= 2 && QString::fromLocal8Bit(argv[1]) == QStringLiteral("--intent") &&
        !(argc == 3 && QString::fromLocal8Bit(argv[2]) == QStringLiteral("open"))) {
        fprintf(stderr, "PROXY_INVALID_INTENT\n");
        return 2;
    }
    QApplication app(argc, argv);
    QCommandLineParser cli;
    cli.setApplicationDescription("NEEBLES Proxy Server — Qt administration of allowlist (Exit Node disabled)");
    cli.addHelpOption();
    cli.addOption({"policy", "Path to local policy JSON", "file", ""});
    cli.process(app);
    const QString path = cli.value("policy").isEmpty()
        ? QDir::homePath() + "/.config/neebles/proxy-server/allowlist.json"
        : cli.value("policy");

    // NEEBLES standard dark theme.
    QApplication::setStyle(QStyleFactory::create("Fusion"));
    app.setStyleSheet(neeblesTheme());

    // Canonical assets, relative to the installed runtime executable.
    const QDir moduleRoot(
        QDir(QCoreApplication::applicationDirPath()).absoluteFilePath("..")
    );

    const QString iconPath =
        moduleRoot.absoluteFilePath("icon.png");

    const QString splashPath =
        moduleRoot.absoluteFilePath("assets/neebles-server-logo.png");

    const QPixmap moduleIcon(iconPath);
    const QPixmap splashLogo(splashPath);

    if (!moduleIcon.isNull())
        app.setWindowIcon(QIcon(moduleIcon));

    // Distinct splash artwork; do not reuse the small module icon.
    QPixmap splashCanvas(700, 420);
    splashCanvas.fill(QColor("#10131d"));

    if (!splashLogo.isNull()) {
        QPainter painter(&splashCanvas);
        const QPixmap scaled = splashLogo.scaled(
            splashCanvas.size(),
            Qt::KeepAspectRatio,
            Qt::SmoothTransformation
        );
        painter.drawPixmap(
            (splashCanvas.width() - scaled.width()) / 2,
            (splashCanvas.height() - scaled.height()) / 2,
            scaled
        );
    }

    auto *splash = new QSplashScreen(splashCanvas);
    splash->show();

    // The administration window is shown after the 3-second splash.
    QTimer::singleShot(3000, &app, [&app, splash, path] {
        auto *window = new AdminWindow(path);
        window->setAttribute(Qt::WA_DeleteOnClose);
        window->setWindowIcon(app.windowIcon());
        window->show();
        splash->finish(window);
        splash->deleteLater();
    });

    return app.exec();
}
