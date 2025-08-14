#include "sniffer.hpp"
#include <pcap/pcap.h>
#include <QtWidgets/QApplication>
#include <QtWidgets/QMainWindow>
#include <QtWidgets/QComboBox>
#include <QtWidgets/QPushButton>
#include <QtWidgets/QLabel>
#include <QtWidgets/QGridLayout>
#include <QtWidgets/QGroupBox>
#include <QtWidgets/QHBoxLayout>
#include <QtWidgets/QVBoxLayout>
#include <QtWidgets/QLineEdit>
#include <QtWidgets/QTableWidget>
#include <QtWidgets/QHeaderView>
#include <QtWidgets/QMessageBox>
#include <QtCore/QTimer>
#include <QtCore/QDateTime>
#include <QtGui/QFont>
#include <algorithm>
#include <map>
#include <memory>
#include <mutex>
#include <string>
#include <vector>

using namespace sniffer;

class TopAnalyzer : public Analyzer {
public:
    explicit TopAnalyzer(std::mutex& m, std::map<std::string, unsigned long long>& bytes, std::map<std::string, unsigned long long>& pkts)
        : m_(m), bytes_(bytes), pkts_(pkts) {}
    void on_packet(const PacketInfo& info, const u_char*, std::size_t length) override {
        std::lock_guard<std::mutex> lk(m_);
        if (info.src_ip) { bytes_[*info.src_ip] += length; pkts_[*info.src_ip]++; }
        if (info.dst_ip) { bytes_[*info.dst_ip] += length; pkts_[*info.dst_ip]++; }
    }
    void on_stats(const StatsSnapshot&) override {}
private:
    std::mutex& m_;
    std::map<std::string, unsigned long long>& bytes_;
    std::map<std::string, unsigned long long>& pkts_;
};

static QStringList list_devices() {
    char errbuf[PCAP_ERRBUF_SIZE] = {0};
    pcap_if_t* alld = nullptr;
    QStringList out;
    if (pcap_findalldevs(&alld, errbuf) == 0) {
        for (pcap_if_t* d = alld; d; d = d->next) if (d->name) out << d->name;
        pcap_freealldevs(alld);
    }
    return out;
}

class MainWindow : public QMainWindow {
    Q_OBJECT
public:
    MainWindow() {
        setWindowTitle("PacketSniffer");
        auto* central = new QWidget(this);
        auto* root = new QVBoxLayout(central);

        auto* controls = new QGroupBox("Быстрый старт", central);
        auto* cgrid = new QGridLayout(controls);
        ifaceBox_ = new QComboBox(controls);
        autoBtn_ = new QPushButton("Определить", controls);
        modeBox_ = new QComboBox(controls);
        modeBox_->addItems({"Всё", "Веб-трафик", "DNS", "ICMP", "Локальная сеть"});
        startBtn_ = new QPushButton("Старт", controls);
        stopBtn_ = new QPushButton("Стоп", controls);
        filterEdit_ = new QLineEdit(controls);
        filterEdit_->setPlaceholderText("tcp or udp or icmp");
        cgrid->addWidget(new QLabel("Интерфейс", controls), 0, 0);
        cgrid->addWidget(ifaceBox_, 0, 1);
        cgrid->addWidget(autoBtn_, 0, 2);
        cgrid->addWidget(new QLabel("Режим", controls), 1, 0);
        cgrid->addWidget(modeBox_, 1, 1);
        cgrid->addWidget(new QLabel("BPF фильтр", controls), 2, 0);
        cgrid->addWidget(filterEdit_, 2, 1, 1, 2);
        cgrid->addWidget(startBtn_, 3, 1);
        cgrid->addWidget(stopBtn_, 3, 2);

        auto* statsBox = new QGroupBox("Статистика", central);
        auto* sgrid = new QGridLayout(statsBox);
        lblStatus_ = makeKV(sgrid, 0, "Статус", "остановлен");
        lblPkts_ = makeKV(sgrid, 1, "Пакеты", "0");
        lblBytes_ = makeKV(sgrid, 1, "Байт", "0", 2);
        lblTCP_ = makeKV(sgrid, 2, "TCP", "0");
        lblUDP_ = makeKV(sgrid, 2, "UDP", "0", 2);
        lblICMP_ = makeKV(sgrid, 3, "ICMP", "0");
        lblPPS_ = makeKV(sgrid, 3, "PPS", "0", 2);
        lblBPS_ = makeKV(sgrid, 4, "bps", "0");

        auto* topBox = new QGroupBox("Топ хостов", central);
        topTable_ = new QTableWidget(0, 3, topBox);
        topTable_->setHorizontalHeaderLabels({"IP", "Пакеты", "Байт"});
        topTable_->horizontalHeader()->setSectionResizeMode(QHeaderView::Stretch);
        auto* topLayout = new QVBoxLayout(topBox);
        topLayout->addWidget(topTable_);

        QLabel* author = new QLabel("<a href='https://github.com/BengaminButton'>Автор: BengaminButton</a> • <span style='color:#9da3ae'>см. руководство ниже</span>", central);
        author->setTextFormat(Qt::RichText);
        author->setOpenExternalLinks(true);
        author->setAlignment(Qt::AlignLeft);
        author->setStyleSheet("QLabel { color:#9da3ae; } QLabel a { color:#8aa0b2; text-decoration:none; } QLabel a:hover { color:#c5d1db; }");
        root->addWidget(author);
        root->addWidget(controls);
        root->addWidget(statsBox);
        root->addWidget(topBox);
        auto* guide = new QGroupBox("Руководство", central);
        auto* gv = new QVBoxLayout(guide);
        auto* gl = new QLabel("<ol><li>Выберите интерфейс или нажмите «Определить».</li><li>Выберите режим или задайте свой фильтр.</li><li>Нажмите «Старт» для начала мониторинга.</li><li>«Стоп» — завершить захват. Таблица показывает топ хостов.</li></ol>", guide);
        gl->setTextFormat(Qt::RichText);
        gl->setWordWrap(true);
        gv->addWidget(gl);
        root->addWidget(guide);
        setCentralWidget(central);

        qApp->setStyle("Fusion");
        QPalette p = qApp->palette();
        p.setColor(QPalette::Window, QColor(15,17,22));
        p.setColor(QPalette::WindowText, QColor(230,237,243));
        p.setColor(QPalette::Base, QColor(26,29,36));
        p.setColor(QPalette::AlternateBase, QColor(20,24,33));
        p.setColor(QPalette::ToolTipBase, QColor(230,237,243));
        p.setColor(QPalette::ToolTipText, QColor(15,17,22));
        p.setColor(QPalette::Text, QColor(230,237,243));
        p.setColor(QPalette::Button, QColor(26,29,36));
        p.setColor(QPalette::ButtonText, QColor(230,237,243));
        p.setColor(QPalette::BrightText, Qt::red);
        p.setColor(QPalette::Highlight, QColor(70,120,160));
        p.setColor(QPalette::HighlightedText, QColor(15,17,22));
        qApp->setPalette(p);
        QFont f = qApp->font();
        f.setPointSize(14);
        qApp->setFont(f);

        populateIfaces();
        connect(autoBtn_, &QPushButton::clicked, this, &MainWindow::autoSelectIface);
        connect(startBtn_, &QPushButton::clicked, this, &MainWindow::startCapture);
        connect(stopBtn_, &QPushButton::clicked, this, &MainWindow::stopCapture);

        timer_ = new QTimer(this);
        connect(timer_, &QTimer::timeout, this, &MainWindow::tick);
        timer_->start(1000);
    }

private slots:
    void autoSelectIface() {
        auto list = list_devices();
        for (const auto& name : list) {
            if (!name.contains("lo") && !name.contains("dbus") && !name.contains("nf") && !name.contains("bluetooth")) {
                int ix = ifaceBox_->findText(name);
                if (ix >= 0) { ifaceBox_->setCurrentIndex(ix); return; }
            }
        }
        if (ifaceBox_->count() > 0) ifaceBox_->setCurrentIndex(0);
    }

    void startCapture() {
        stopCapture();
        Config cfg;
        cfg.interface = ifaceBox_->currentText().toStdString();
        if (cfg.interface.empty()) return;
        std::string preset = presetBpf(modeBox_->currentIndex());
        std::string custom = filterEdit_->text().toStdString();
        if (!custom.empty()) cfg.bpf = custom; else if (!preset.empty()) cfg.bpf = preset;
        cfg.promisc = true; cfg.snaplen = 65535; cfg.timeout_ms = 1000;

        try {
            analyzer_ = std::make_shared<TopAnalyzer>(mtx_, bytes_, pkts_);
            session_ = std::make_shared<CaptureSession>(cfg);
            session_->start(analyzer_);
            lblStatus_->setText("запущен");
        } catch (const std::exception& e) {
            session_.reset();
            QString msg = QString::fromLocal8Bit(e.what());
            if (msg.contains("permission", Qt::CaseInsensitive) || msg.contains("Operation not permitted", Qt::CaseInsensitive) || msg.contains("не позволена", Qt::CaseInsensitive)) {
                msg += "\n\nРешение:\n1) выдать права бинарю (без sudo при запуске):\n   sudo setcap cap_net_raw,cap_net_admin+eip /tmp/PacketSniffer_qt\n   затем перезапустить /tmp/PacketSniffer_qt\n2) либо запустить под sudo:\n   sudo /tmp/PacketSniffer_qt";
            }
            QMessageBox::critical(this, "Ошибка", msg);
            lblStatus_->setText("ошибка");
        }
    }

    void stopCapture() {
        if (session_) { session_->stop(); session_.reset(); }
        lblStatus_->setText("остановлен");
        bytes_.clear(); pkts_.clear();
    }

    void tick() {
        if (!session_) return;
        auto s = session_->stats();
        lblPkts_->setText(QString::number(s.pkts_total));
        lblBytes_->setText(QString::number(s.bytes_total));
        lblTCP_->setText(QString::number(s.pkts_tcp));
        lblUDP_->setText(QString::number(s.pkts_udp));
        lblICMP_->setText(QString::number(s.pkts_icmp));
        double secs = 1.0; if (s.started_ts_usec) {
            quint64 now = QDateTime::currentMSecsSinceEpoch()*1000ULL; double d = (now - s.started_ts_usec)/1e6; if (d>0) secs = d;
        }
        lblPPS_->setText(QString::number((double)s.pkts_total / secs, 'f', 2));
        lblBPS_->setText(QString::number((double)s.bytes_total * 8.0 / secs, 'f', 2));
        updateTop();
    }

private:
    QLabel* makeKV(QGridLayout* grid, int row, const QString& k, const QString& v, int col=0) {
        auto* lk = new QLabel(k, this);
        auto* lv = new QLabel(v, this);
        grid->addWidget(lk, row, col);
        grid->addWidget(lv, row, col+1);
        return lv;
    }

    void populateIfaces() {
        ifaceBox_->clear();
        auto list = list_devices();
        ifaceBox_->addItems(list);
        autoSelectIface();
    }

    std::string presetBpf(int idx) {
        switch (idx) {
            case 1: return "tcp port 80 or tcp port 443";
            case 2: return "udp port 53 or tcp port 53";
            case 3: return "icmp or icmp6";
            case 4: return "(net 10.0.0.0/8) or (net 172.16.0.0/12) or (net 192.168.0.0/16)";
            default: return "";
        }
    }

    void updateTop() {
        std::vector<std::pair<std::string, unsigned long long>> v;
        {
            std::lock_guard<std::mutex> lk(mtx_);
            for (auto& kv : bytes_) v.emplace_back(kv.first, kv.second);
        }
        std::sort(v.begin(), v.end(), [](auto& a, auto& b){ return a.second > b.second; });
        if (v.size() > 20) v.resize(20);
        topTable_->setRowCount((int)v.size());
        for (int i = 0; i < (int)v.size(); ++i) {
            const auto& ip = v[i].first; unsigned long long b = v[i].second; unsigned long long p = 0;
            {
                std::lock_guard<std::mutex> lk(mtx_);
                auto it = pkts_.find(ip); if (it != pkts_.end()) p = it->second;
            }
            topTable_->setItem(i, 0, new QTableWidgetItem(QString::fromStdString(ip)));
            topTable_->setItem(i, 1, new QTableWidgetItem(QString::number(p)));
            topTable_->setItem(i, 2, new QTableWidgetItem(QString::number(b)));
        }
    }

    QComboBox* ifaceBox_{};
    QPushButton* autoBtn_{};
    QComboBox* modeBox_{};
    QLineEdit* filterEdit_{};
    QPushButton* startBtn_{};
    QPushButton* stopBtn_{};

    QLabel* lblStatus_{}; QLabel* lblPkts_{}; QLabel* lblBytes_{}; QLabel* lblTCP_{}; QLabel* lblUDP_{}; QLabel* lblICMP_{}; QLabel* lblPPS_{}; QLabel* lblBPS_{};

    QTableWidget* topTable_{};

    std::shared_ptr<CaptureSession> session_;
    std::shared_ptr<Analyzer> analyzer_;

    std::mutex mtx_;
    std::map<std::string, unsigned long long> bytes_;
    std::map<std::string, unsigned long long> pkts_;
    QTimer* timer_{};
};

int main(int argc, char** argv) {
    QApplication app(argc, argv);
    MainWindow w; w.resize(1100, 800); w.show();
    return app.exec();
}

#include "gui_main.moc"
