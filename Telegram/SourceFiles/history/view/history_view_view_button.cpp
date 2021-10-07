/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#include "history/view/history_view_view_button.h"

#include "core/click_handler_types.h"
#include "data/data_user.h"
#include "history/view/history_view_cursor_state.h"
#include "lang/lang_keys.h"
#include "ui/click_handler.h"
#include "ui/effects/ripple_animation.h"
#include "ui/round_rect.h"
#include "ui/text/text_utilities.h" // Ui::Text::ToUpper
#include "window/window_session_controller.h"
#include "styles/style_chat.h"
#include "styles/style_widgets.h"
#include "styles/style_window.h"

namespace HistoryView {
namespace {

inline auto PeerToPhrase(not_null<PeerData*> peer) {
	const auto phrase = [&] {
		if (const auto user = peer->asUser()) {
			return user->isBot()
				? tr::lng_view_button_bot
				: tr::lng_view_button_user;
		} else if (peer->isChat()) {
			return tr::lng_view_button_group;
		} else if (peer->isChannel()) {
			return tr::lng_view_button_channel;
		}
		Unexpected("Invalid peer in ViewButton.");
	}()(tr::now);
	return Ui::Text::Upper(phrase);
}

} // namespace

struct ViewButton::Inner {
	Inner(not_null<PeerData*> peer, Fn<void()> updateCallback);
	void updateMask(int height);
	void toggleRipple(bool pressed);

	const style::margins &margins;
	const ClickHandlerPtr link;
	const Fn<void()> updateCallback;
	int lastWidth = 0;
	QPoint lastPoint;
	std::unique_ptr<Ui::RippleAnimation> ripple;
	Ui::Text::String text;
};

ViewButton::Inner::Inner(not_null<PeerData*> peer, Fn<void()> updateCallback)
: margins(st::historyViewButtonMargins)
, link(peer->openLink())
, updateCallback(std::move(updateCallback))
, text(st::historyViewButtonTextStyle, PeerToPhrase(peer)) {
}

void ViewButton::Inner::updateMask(int height) {
	ripple = std::make_unique<Ui::RippleAnimation>(
		st::defaultRippleAnimation,
		Ui::RippleAnimation::roundRectMask(
			QSize(lastWidth, height - margins.top() - margins.bottom()),
			st::roundRadiusLarge),
		updateCallback);
}

void ViewButton::Inner::toggleRipple(bool pressed) {
	if (ripple) {
		if (pressed) {
			ripple->add(lastPoint);
		} else {
			ripple->lastStop();
		}
	}
}

ViewButton::ViewButton(not_null<PeerData*> peer, Fn<void()> updateCallback)
: _inner(std::make_unique<Inner>(peer, std::move(updateCallback))) {
}

ViewButton::~ViewButton() {
}

void ViewButton::resized() const {
	_inner->updateMask(height());
}

int ViewButton::height() const {
	return st::historyViewButtonHeight;
}

void ViewButton::draw(
		Painter &p,
		const QRect &r,
		const Ui::ChatPaintContext &context) {
	const auto stm = context.messageStyle();

	if (_inner->ripple && !_inner->ripple->empty()) {
		const auto opacity = p.opacity();
		p.setOpacity(st::historyPollRippleOpacity);
		const auto colorOverride = &stm->msgWaveformInactive->c;
		_inner->ripple->paint(p, r.left(), r.top(), r.width(), colorOverride);
		p.setOpacity(opacity);
	}

	p.save();
	{
		PainterHighQualityEnabler hq(p);
		auto pen = stm->fwdTextPalette.linkFg->p;
		pen.setWidth(st::lineWidth);
		p.setPen(pen);
		p.setBrush(Qt::NoBrush);
		p.drawRoundedRect(r, st::roundRadiusLarge, st::roundRadiusLarge);

		_inner->text.drawElided(
			p,
			r.left(),
			r.top() + (r.height() - _inner->text.minHeight()) / 2,
			r.width(),
			1,
			style::al_center);
	}
	p.restore();
	if (_inner->lastWidth != r.width()) {
		_inner->lastWidth = r.width();
		resized();
	}
}

const ClickHandlerPtr &ViewButton::link() const {
	return _inner->link;
}

bool ViewButton::checkLink(const ClickHandlerPtr &other, bool pressed) {
	if (_inner->link != other) {
		return false;
	}
	_inner->toggleRipple(pressed);
	return true;
}

bool ViewButton::getState(
		QPoint point,
		const QRect &g,
		not_null<TextState*> outResult) const {
	if (!g.contains(point)) {
		return false;
	}
	outResult->link = _inner->link;
	_inner->lastPoint = point - g.topLeft();
	return true;
}

QRect ViewButton::countSponsoredRect(const QRect &r) const {
	return QRect(
		r.left(),
		r.top() + r.height() - height(),
		r.width(),
		height()) - _inner->margins;
}

} // namespace HistoryView