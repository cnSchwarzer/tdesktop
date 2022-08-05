#include "ui/painter.h"
#include "ui/widgets/buttons.h"
#include "window/window_session_controller.h"
#include <QtNetwork/QNetworkAccessManager>
#include <QtNetwork/QNetworkReply>
#include <QImage>
#include <QTimer>
#include <memory>
#include <string>
#include <atomic>

namespace Cu {

class BannerItem : public QObject  {
    std::unique_ptr<QNetworkAccessManager> _manager;
    void onFinish(QNetworkReply*);
    
public:
    bool ready = false;
    std::string title;
    std::string url;
    std::string imgUrl;
    QImage image;
    
    void start();
};

class BannerWidget : public QObject {
    std::atomic<int> _index = 0;
    std::vector<std::unique_ptr<BannerItem>> _items;
    std::unique_ptr<QNetworkAccessManager> _manager;
    QTimer _timer;
    void onFinish(QNetworkReply*);
    
public:
    void start();
    bool ready();
    int height();
    QString paint(Painter& p, int width);
    
    void next();
    void prev();
    void click(not_null<Window::SessionController*>);
};
}
