#include <QApplication>
#include <QCommandLineParser>
#include <QLabel>
#include <QMainWindow>
#include <QVBoxLayout>
#include <QWidget>

int main(int argc,char **argv) {
    QApplication app(argc,argv);
    QCommandLineParser parser;parser.setApplicationDescription("NEEBLES Proxy Server — Qt preview, no Exit Node changes");
    parser.addHelpOption();parser.process(app);
    QMainWindow window;window.setWindowTitle("NEEBLES Proxy Server (DEMO)");
    auto *root=new QWidget;auto *layout=new QVBoxLayout(root);
    layout->addWidget(new QLabel("NEEBLES Proxy Server"));
    layout->addWidget(new QLabel("Tailnet: pending identity verification"));
    layout->addWidget(new QLabel("Whitelist: not operational yet"));
    layout->addWidget(new QLabel("Exit Node: not configured"));
    layout->addWidget(new QLabel("This preview does not modify Tailscale or authorize clients."));
    window.setCentralWidget(root);window.resize(620,250);window.show();
    return app.exec();
}
