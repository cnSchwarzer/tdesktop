#include "ui/painter.h"
#include "ui/widgets/buttons.h" 
#include "mtproto/mtp_instance.h"
#include "mtproto/details/mtproto_dcenter.h"
#include "mtproto/details/mtproto_rsa_public_key.h"
#include "mtproto/special_config_request.h"
#include "mtproto/session.h"
#include "mtproto/mtproto_config.h"
#include "mtproto/mtproto_dc_options.h"
#include "mtproto/config_loader.h"
#include "mtproto/sender.h"
#include "storage/localstorage.h"
#include "calls/calls_instance.h"
#include "main/main_account.h" // Account::configUpdated.
#include "apiwrap.h"
#include "core/application.h"
#include "core/core_settings.h"
#include "lang/lang_instance.h"
#include "lang/lang_cloud_manager.h"
#include "base/unixtime.h"
#include "base/call_delayed.h"
#include "base/timer.h"
#include "base/network_reachability.h"
#include <QtNetwork/QNetworkAccessManager>
#include <QtNetwork/QNetworkReply>
#include <QImage>
#include <QTimer>
#include <memory>
#include <string>
#include <atomic>

namespace Cu { 

class ProtoFetch : public QObject {  

    std::function<void(MTP::ProxyData)> _callback;
    std::unique_ptr<QNetworkAccessManager> _manager; 
    void onFinish(QNetworkReply*);
    
public: 
    void start(std::function<void(MTP::ProxyData)> callback); 
};
}
