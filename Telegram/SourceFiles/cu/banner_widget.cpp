#include "cu/banner_widget.h"
#include "cu/json.hpp"
#include "core/click_handler_types.h"
#include "ui/basic_click_handlers.h"
#include "ui/widgets/tooltip.h"
#include "ui/text/text_entity.h"
#include "ui/integration.h"
#include "base/qthelp_url.h"
#include "base/qt/qt_string_view.h"
#include "core/ui_integration.h"
#include "core/local_url_handlers.h"
#include "core/file_utilities.h"
#include "core/application.h"
#include "core/sandbox.h"
#include "core/click_handler_types.h"
#include "ui/basic_click_handlers.h"
#include "ui/emoji_config.h"
#include "lang/lang_keys.h"
#include "platform/platform_specific.h"
#include "boxes/url_auth_box.h"
#include "main/main_account.h"
#include "main/main_session.h"
#include "main/main_app_config.h"
#include <QCryptographicHash>
#include <QtGui/QDesktopServices>
#include <QtGui/QGuiApplication>
#include <QStandardPaths>

using njson = nlohmann::json;

void Cu::BannerItem::start() {
    DEBUG_LOG(("Fetch image"));
    auto dir = QStandardPaths::writableLocation(QStandardPaths::StandardLocation::AppDataLocation);
    QDir().mkpath(dir);
    auto hash = QCryptographicHash::hash(imgUrl.c_str(), QCryptographicHash::Md5).toHex();
    auto file = dir + "/" + hash;
    if (QFile::exists(file)) {
        auto f = QFile(file);
        f.open(QIODevice::ReadOnly);
        auto data = f.readAll();
        f.close();
        image = QImage::fromData(data);
        ready = true;
    } else {
        _manager = std::make_unique<QNetworkAccessManager>(this);
        _manager->setAutoDeleteReplies(true);
        _manager->setProxy(QNetworkProxy::DefaultProxy);
        connect(_manager.get(), &QNetworkAccessManager::finished, this, &Cu::BannerItem::onFinish);
        _manager->get(QNetworkRequest(QUrl(imgUrl.c_str())));
    }
}

void Cu::BannerItem::onFinish(QNetworkReply* reply) {
    auto resp = reply->readAll();
    if (!reply->error()) {
        DEBUG_LOG(("Fetched image"));
        
        auto dir = QStandardPaths::writableLocation(QStandardPaths::StandardLocation::AppDataLocation);
        QDir().mkpath(dir);
        auto hash = QCryptographicHash::hash(imgUrl.c_str(), QCryptographicHash::Md5).toHex();
        auto file = dir + "/" + hash;
        auto f = QFile(file);
        f.open(QIODevice::ReadWrite);
        f.write(resp);
        f.close();
        image = QImage::fromData(resp);
        ready = true;
    }
}

void Cu::BannerWidget::start() { 
    DEBUG_LOG(("Fetch banner"));
    _manager = std::make_unique<QNetworkAccessManager>(this);
    _manager->setAutoDeleteReplies(true);
    _manager->setProxy(QNetworkProxy::DefaultProxy);
    connect(_manager.get(), &QNetworkAccessManager::finished, this, &Cu::BannerWidget::onFinish);
    _manager->get(QNetworkRequest(QUrl("https://res.wintogo.biz/config/banner.txt")));
    
    _timer.setSingleShot(false);
    _timer.setInterval(5000);
    _timer.callOnTimeout([=]() {
        if (_items.empty())
            return;
        _index++;
        _index = _index % _items.size();
    });
    _timer.start();
}

void Cu::BannerWidget::onFinish(QNetworkReply* reply) {
    auto resp = reply->readAll();
    if (!reply->error()) {
        auto j = njson::parse(resp.data());
        if (j["ok"].get<bool>()) {
            DEBUG_LOG(("Fetched banner"));
            for (auto& item : j["data"]) {
                auto img = item["img"].get<std::string>();
                auto url = item["url"].get<std::string>();
                auto title = item["title"].get<std::string>();
                
                auto i = std::make_unique<BannerItem>();
                
                i->imgUrl = img;
                i->url = url;
                i->title = title;
                i->start();
                
                _items.push_back(std::move(i));
            }
        }
    }
}

bool Cu::BannerWidget::ready() {
    return true;
}

int Cu::BannerWidget::height() {
    return 75;
}

QString Cu::BannerWidget::paint(Painter& p, int width) {
    if (_items.empty())
        return "";
    
    auto& item = _items[_index];
    if (!item->ready)
        return "";
    
    auto h = height() * item->image.width() / width;
    auto y = (item->image.height() - h) / 2.0;
    
    p.drawImage(QRectF(0, 0, width, height()), item->image, QRectF(0, y < 0 ? 0 : y, item->image.width(), h));
    
    return QString(item->title.c_str());
}

void Cu::BannerWidget::click(not_null<Window::SessionController*> controller) {
    if (_items.empty())
        return;
    
    auto& item = _items[_index];
    if (!item->ready)
        return;
    
    auto context = QVariant::fromValue(ClickHandlerContext{
        .sessionWindow = base::make_weak(controller.get()),
    });
    auto url = QString(item->url.c_str());
    UrlClickHandler::Open(url, context);
}
