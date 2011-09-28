/*
 * Wi-Fi Display - WFD module
 * Copyright (c) 2011, Texas Instruments
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 * Alternatively, this software may be distributed under the terms of BSD
 * license.
 *
 * See README and COPYING for more details.
 */
#include "includes.h"
#include "common.h"
#include "common/ieee802_11_defs.h"
#include "common/ieee802_11_common.h"
#include "wpa_supplicant_i.h"
#include "config.h"
#include "ap.h"
#include "ap/hostapd.h"
#include "utils/list.h"
#include "wfd_i.h"


/**
 *  Device Info descriptor of associated device
 */
struct wfd_device_info_desc {
	struct dl_list list;
	int	associated;
	int expired;
	u8 dev_addr[ETH_ALEN];
	u8 assoc_bssid[ETH_ALEN];
	u16 device_info_bitmap;
	u16 maximum_tp;
	u8  coupled_sink_status_bitmap;
	u8  coupled_dev_addr[ETH_ALEN];
};

struct wfd_config {


	/**
	 *  Wi-Fi display type: 0 - source, 1 - primary sink,
	 *  2 - secondary sink, 3 - source/primary sink
	 */
	u8 type;

	/**
	* Coupled sink operation supported by source
	*/
	u8 coupled_sink_by_source;

	/**
	 * Coupled sink operation supported by sink
	 */
	u8 coupled_sink_by_sink;

	/**
	 *  Wi-Fi Display session is available.
	 */
	u8 session_available;

	/**
	 * Service discovery is supported
	 */
	u8 service_discovery;

	/**
	 *  Preferred connectivity. 0 - P2P, 1 - TDLS
	 */
	u8 preferred_connectivity;

	/**
	 * Content protection HDCP2.0 supported
	 */
	u8 content_protection;

	/**
	* Time synchronization using 802.1AS supported
	*/
	u8 time_sync;

	/**
	*  Session Management Control Port. Default 554
	*/
	u16 session_mgmt_port;

	/**
	 *  Device Maximum Throughput
	 */
	u16 dev_max_tp;
	/**
	 *  Wi-Fi Display functionality is enabled
	 */
	u8  enabled;

};

struct wfd_data {
	/**
	 *  cfg - WFD module configuration
	*/
	struct wfd_config *cfg;

	/**
	 *  Device Information bitmap
	 */

	u16 device_info;

	/**
	 *  Session management port
	 */
	u16 session_mgmt_port;

	/**
	 *  Device Maximum Throughput
	 */
	u16 dev_max_tp;

	/**
	 *  Associated BSSID
	 */
	u8 assoc_bssid[ETH_ALEN];

	u8 coupled_sink_status_bitmap;

	u8 enabled;

	u16 last_device_info;

	int associated;

	/**
	 * devices - List of known WFD devices
	 */
	struct dl_list devices;

};


static void wfd_buf_update_ie_len(struct wpabuf *buf, u8 *len)
{
	/* Update WFD IE length */
	*len = (u8 *)wpabuf_put(buf, 0) - len - 1;
}

void wfd_buf_add_device_info(struct wfd_data *wfd, struct wpabuf *buf)
{
	wpabuf_put_u8(buf, WFD_DEVICE_INFO_SUBELEM_ID);
	wpabuf_put_u8(buf, 6);
	wpabuf_put_be16(buf, wfd->device_info);
	wpabuf_put_be16(buf, wfd->session_mgmt_port);
	wpabuf_put_be16(buf, wfd->dev_max_tp);
}

static void wfd_buf_add_assoc_bssid(struct wfd_data *wfd, struct wpabuf *buf)
{
	wpabuf_put_u8(buf, WFD_ASSOC_BSSID_SUBELEM_ID);
	wpabuf_put_u8(buf, 6);
	wpabuf_put_data(buf, wfd->assoc_bssid, ETH_ALEN);
}

static void wfd_buf_add_coupled_sink(struct wfd_data *wfd, struct wpabuf *buf)
{
	wpabuf_put_u8(buf, WFD_COUPLED_SINK_INFO_SUBELEM_ID);
	wpabuf_put_u8(buf, 1);
	wpabuf_put_u8(buf, wfd->coupled_sink_status_bitmap);
}

static u8 *wfd_buf_add_ie_hdr(struct wpabuf *buf)
{
	u8 *len;

	wpabuf_put_u8(buf, WLAN_EID_VENDOR_SPECIFIC);
	len = wpabuf_put(buf, 1); /* IE length to be filled */
	wpabuf_put_be24(buf, OUI_WFA);
	wpabuf_put_u8(buf, WFD_OUI_TYPE);
	return len;
}

static void wfd_build_beacon_ies(struct wfd_data *wfd, struct wpabuf *buf)
{
	u8 *len;

	len = wfd_buf_add_ie_hdr(buf);
	wfd_buf_add_device_info(wfd, buf);

	if (wfd->associated)
		wfd_buf_add_assoc_bssid(wfd, buf);
	wfd_buf_add_coupled_sink(wfd, buf);

	wfd_buf_update_ie_len(buf, len);
}

static struct wpabuf *wfd_build_prob_resp_group(struct wfd_data *wfd)
{
	struct wpabuf *buf;

	buf = wpabuf_alloc(257);
	if (!buf)
		return NULL;
	wfd_build_prob_resp_ies(wfd, buf);
	return buf;
}

static struct wpabuf *wfd_build_beacon_group(struct wfd_data *wfd)
{
	struct wpabuf *buf;

	buf = wpabuf_alloc(257);
	if (!buf)
		return NULL;
	wfd_build_beacon_ies(wfd, buf);
	return buf;
}

/* Update information elements in beacon and probe responses */
static void wfd_ie_update(struct wpa_supplicant *wpa_s,
		struct wpabuf *beacon_ies, struct wpabuf *proberesp_ies)
{
	if (wpa_s->ap_iface) {
		struct hostapd_data *hapd = wpa_s->ap_iface->bss[0];
	if (beacon_ies) {
			wpabuf_free(hapd->wfd_beacon_ie);
			hapd->wfd_beacon_ie = beacon_ies;
		}
		wpabuf_free(hapd->wfd_probe_resp_ie);
		hapd->wfd_probe_resp_ie = proberesp_ies;
	} else {
		wpabuf_free(beacon_ies);
		wpabuf_free(proberesp_ies);
	}

}

static void wfd_check_and_update_ies(struct wpa_supplicant *wpa_s,
				struct wfd_data *wfd, int force)
{
	struct wpabuf *beacon_ie, *probresp_ie;

	if (!wfd->enabled)
		return;
	if (wfd->device_info == wfd->last_device_info && !force)
		return;
	probresp_ie = wfd_build_prob_resp_group(wfd);
	if (!probresp_ie)
		return;
	beacon_ie = wfd_build_beacon_group(wfd);
	if (!beacon_ie)
		return;
	wfd->last_device_info = wfd->device_info;
	wfd_ie_update(wpa_s, beacon_ie, probresp_ie);

	wpa_supplicant_ap_update_beacon(wpa_s);
}

static struct wfd_device_info_desc *wfd_find_device_info(struct wfd_data *wfd,
					const u8 *addr)
{
	struct wfd_device_info_desc *dev;

	dl_list_for_each(dev, &wfd->devices,
				struct wfd_device_info_desc, list) {
		if (os_memcmp(dev->dev_addr, addr, ETH_ALEN) == 0) {
			/* Device found */
			return dev;
		}
	}
	return NULL;
}

static void wfd_add_session_info(struct wfd_data *wfd, struct wpabuf *buf)
{
	struct wfd_device_info_desc *dev;
	int dev_count = 0;
	u8 *len = NULL;

	dl_list_for_each(dev, &wfd->devices,
			struct wfd_device_info_desc, list) {
	if (dev->associated) {
		if (dev_count == 0) {
			/* Fill WFD Session Information Subelement once */
				wpabuf_put_u8(buf,
						WFD_SESSION_INFO_SUBELEM_ID);
				/* IE length to be filled */
				len = wpabuf_put(buf, 1);
			}
			dev_count++;
			wpabuf_put_u8(buf, 23); /* Length */
			wpabuf_put_data(buf, dev->dev_addr, ETH_ALEN);
			wpabuf_put_data(buf, dev->assoc_bssid, ETH_ALEN);
			wpabuf_put_be16(buf, dev->device_info_bitmap);
			wpabuf_put_be16(buf, dev->maximum_tp);
			wpabuf_put_u8(buf, dev->coupled_sink_status_bitmap);
			wpabuf_put_data(buf, dev->coupled_dev_addr, ETH_ALEN);
		}
	}
	if (dev_count) {
		*len = 24*dev_count; /* Update subelement length */
		wpa_printf(MSG_DEBUG, "%s:...len = %d\n",
					__func__, 24*dev_count);

	}
}

void wfd_build_prob_resp_ies(struct wfd_data *wfd, struct wpabuf *buf)
{
	u8 *len;

	if (!wfd->enabled)
		return;
	len = wfd_buf_add_ie_hdr(buf);
	wfd_buf_add_device_info(wfd, buf);

	if (wfd->associated)
		wfd_buf_add_assoc_bssid(wfd, buf);

	wfd_buf_add_coupled_sink(wfd, buf);

	wfd_add_session_info(wfd, buf);
	wfd_buf_update_ie_len(buf, len);
}

void wfd_build_probe_req_ies(struct wfd_data *wfd, struct wpabuf *buf)
{
	u8 *len;

	if (!wfd->enabled)
		return;
	len = wfd_buf_add_ie_hdr(buf);
	wfd_buf_add_device_info(wfd, buf);

	/*wfd_buf_add_assoc_bssid(wfd, buf);- Removed from Test plan */
	wfd_buf_add_coupled_sink(wfd, buf);

	wfd_buf_update_ie_len(buf, len);
}


void wfd_build_go_neg_req_ie(struct wfd_data *wfd, struct wpabuf *buf)
{
	u8 *len;

	if (wfd->enabled) {
		len = wfd_buf_add_ie_hdr(buf);
		wfd_buf_add_device_info(wfd, buf);
		if (wfd->associated)
			wfd_buf_add_assoc_bssid(wfd, buf);
		wfd_buf_update_ie_len(buf, len);
	}
}

void wfd_build_prov_disc_req_ie(struct wfd_data *wfd, struct wpabuf *buf)
{
	u8 *len;

	if (wfd->enabled) {
		len = wfd_buf_add_ie_hdr(buf);
		wfd_buf_add_device_info(wfd, buf);
		if (wfd->associated)
			wfd_buf_add_assoc_bssid(wfd, buf);
		wfd_buf_update_ie_len(buf, len);
	}
}
/**
 *  Wi-Fi display set functions.
 */

void wfd_set_enabled(struct wfd_data *wfd, int enabled)
{
	wfd->enabled = enabled;
}

void  wfd_set_type(struct wfd_data *wfd, int type,
				struct wpa_supplicant *wpa_s)
{
	wfd->device_info &= ~WFD_TYPE_MASK;
	wfd->device_info |= (WFD_TYPE_MASK & type);
	wfd_check_and_update_ies(wpa_s, wfd, 0);
}

void wfd_set_coupled_sink_by_source(struct wfd_data *wfd,
				int supported, struct wpa_supplicant *wpa_s)
{
	if (supported)
		wfd->device_info |=  WFD_COUPLED_SINK_BY_SOURCE;
	else
		wfd->device_info &=  ~WFD_COUPLED_SINK_BY_SOURCE;
	wfd_check_and_update_ies(wpa_s, wfd, 0);
}

void wfd_set_coupled_sink_by_sink(struct wfd_data *wfd,
			int supported, struct wpa_supplicant *wpa_s)
{
	if (supported)
		wfd->device_info |=  WFD_COUPLED_SINK_BY_SINK;
	else
		wfd->device_info &=  ~WFD_COUPLED_SINK_BY_SINK;
	wfd_check_and_update_ies(wpa_s, wfd, 0);
}

void wfd_set_session_available(struct wfd_data *wfd,
			int available, struct wpa_supplicant *wpa_s)
{
	if (available)
		wfd->device_info |=  WFD_SESSION_AVAILABLE;
	else
		wfd->device_info &=  ~WFD_SESSION_AVAILABLE;
	wfd_check_and_update_ies(wpa_s, wfd, 0);
}

void wfd_set_service_discovery(struct wfd_data *wfd,
			int supported, struct wpa_supplicant *wpa_s)
{
	if (supported)
		wfd->device_info |=  WFD_SERVICE_DISCOVERY;
	else
		wfd->device_info &=  ~WFD_SERVICE_DISCOVERY;
	wfd_check_and_update_ies(wpa_s, wfd, 0);
}

void wfd_set_preferred_connectivity(struct wfd_data *wfd,
				int connectivity, struct wpa_supplicant *wpa_s)
{
	if (connectivity == WFD_CONNECTIVITY_TDLS)
		wfd->device_info |=  WFD_PREF_CON_TDLS;
	else
		wfd->device_info &=  ~WFD_PREF_CON_TDLS;
	wfd_check_and_update_ies(wpa_s, wfd, 0);
}

void wfd_set_content_protection(struct wfd_data *wfd,
		int supported, struct wpa_supplicant *wpa_s)
{
	if (supported)
		wfd->device_info |=  WFD_CONTENT_PROTECTION;
	else
		wfd->device_info &=  ~WFD_CONTENT_PROTECTION;
	wfd_check_and_update_ies(wpa_s, wfd, 0);
}

void wfd_set_time_sync(struct wfd_data *wfd,
			int supported, struct wpa_supplicant *wpa_s)
{
	if (supported)
		wfd->device_info |=  WFD_TIME_SYNC;
	else
		wfd->device_info &=  ~WFD_TIME_SYNC;
	wfd_check_and_update_ies(wpa_s, wfd, 0);
}

void wfd_set_session_mgmt_port(struct wfd_data *wfd,
			short port_num, struct wpa_supplicant *wpa_s)
{
	if (wfd->session_mgmt_port == port_num)
		return;
	wfd->session_mgmt_port = port_num;
	wfd_check_and_update_ies(wpa_s, wfd, 1);
}

void wfd_set_dev_max_tp(struct wfd_data *wfd,
			short max_throughput, struct wpa_supplicant *wpa_s)
{
	if (wfd->dev_max_tp == max_throughput)
		return;
	wfd->dev_max_tp = max_throughput;
	wfd_check_and_update_ies(wpa_s, wfd, 1);
}

int wfd_get_show_param(struct wfd_data *wfd, char *buf, size_t buflen)
{
	char *type;
	int res;
	char *pos, *end;
	struct wfd_device_info_desc *dev;
	int dev_count = 0;

	switch (wfd->device_info & WFD_TYPE_MASK) {
	case 0:
		type = "Source";
		break;
	case 1:
		type = "Primary Sink";
		break;
	case 2:
		type = "Secondary Sink";
		break;
	case 3:
		type = "Source/Primary Sink";
		break;
	}
	pos = buf;
	end = buf + buflen;
	res = os_snprintf(pos, end - pos,
			"%s\n"
			"Device Information: 0x%04x\n"
			"Type:%s\n"
			"Coupled sink supported by source:%s\n"
			"Coupled sink supported by sink:%s\n"
			"Session available:%s\n"
			"Service discovery enabled:%s\n"
			"Preferred connectivity:%s\n"
			"Content protection:%s\n"
			"Time synchronization:%s\n"
			"Session management port:%d\n"
			"Device maximum TP:%d\n",
			wfd->enabled ? "Enabled" : "Disabled",
			wfd->device_info,
			type,
			wfd->device_info &
				WFD_COUPLED_SINK_BY_SOURCE ? "Yes" : "No",
			wfd->device_info &
				WFD_COUPLED_SINK_BY_SINK ? "Yes" : "No",
			wfd->device_info &
				WFD_SESSION_AVAILABLE ? "Yes" : "No",
			wfd->device_info &
				WFD_SERVICE_DISCOVERY ? "Yes" : "No",
			wfd->device_info & WFD_PREF_CON_TDLS ? "TDLS" : "P2P",
			wfd->device_info &
				WFD_CONTENT_PROTECTION ? "Yes" : "No",
			wfd->device_info & WFD_TIME_SYNC ? "Yes" : "No",
			wfd->session_mgmt_port,
			wfd->dev_max_tp);

	pos += res;

	res = os_snprintf(pos, end - pos,
					"Associated BSSID="  MACSTR "\n",
					MAC2STR(wfd->assoc_bssid));

	if (res < 0 || res >= end - pos)
		return pos - buf;
	pos += res;

	dl_list_for_each(dev, &wfd->devices,
					struct wfd_device_info_desc, list) {
		if (!dev_count) {
			res = os_snprintf(pos, end - pos,
					"\nDiscovered devices:\n");
			if (res < 0 || res >= end - pos)
				return pos - buf;
			pos += res;
		}
		dev_count++;
		res = os_snprintf(pos, end - pos,
				MACSTR " Dev Info=0x%04x %s\n",
				MAC2STR(dev->dev_addr),
				dev->device_info_bitmap,
				dev->associated ?
					"Associated" : "Not Associated");

		if (res < 0 || res >= end - pos)
			return pos - buf;
		pos += res;
	}
	return pos - buf;
}

int wfd_get_dev_info(struct wfd_data *wfd, char *buf, size_t buflen)
{
	int res;
	char *pos, *end;

	pos = buf;
	end = buf + buflen;

	res = os_snprintf(pos, end - pos, "%04x\n", wfd->device_info);
	pos += res;

	return pos - buf;

}

int wfd_parse_ies(struct wpabuf *ie, struct wfd_peer_info *peer)
{
	const u8 *pos = wpabuf_head_u8(ie);
	const u8 *end = pos + wpabuf_len(ie);
	u8 type, len;


	while (pos < end) {
		type = *pos;
		pos++;
		len = *pos;
		if (len > end - pos) {
			wpa_printf(MSG_DEBUG,
					"Subelement %d overflow\n", type);
			return -1;
		}
		switch (type) {
		case WFD_DEVICE_INFO_SUBELEM_ID:
			peer->device_info_bitmap = WPA_GET_BE16(pos+1);
			peer->session_mng_port = WPA_GET_BE16(pos+3);
			peer->maximum_tp =  WPA_GET_BE16(pos+5);
			break;
		case WFD_ASSOC_BSSID_SUBELEM_ID:
			os_memcpy(peer->assoc_bssid, pos + 1, ETH_ALEN);
			break;
		case WFD_COUPLED_SINK_INFO_SUBELEM_ID:
			peer->coupled_sink_status_bitmap = *(pos + 1);
			break;
		case WFD_SESSION_INFO_SUBELEM_ID:

			break;
		default:
			wpa_printf(MSG_DEBUG,
					"Unsupported subelement %d\n", type);
		}
		pos += len + 1;

	}

	return 0;
}

int wfd_add_device(struct wfd_data *wfd,
			struct wfd_peer_info *peer, const u8 *addr)
{

	struct wfd_device_info_desc *dev;

	dev = wfd_find_device_info(wfd, addr);
	if (dev) {
		/* Update device information */
		dev->device_info_bitmap = peer->device_info_bitmap;
		os_memcpy(dev->assoc_bssid, peer->assoc_bssid, ETH_ALEN);
		dev->maximum_tp = peer->maximum_tp;
		dev->coupled_sink_status_bitmap =
			peer->coupled_sink_status_bitmap;
		return 0;
	}

	dev = os_zalloc(sizeof(*dev));
	if (dev == NULL)
		return -1;
	wpa_printf(MSG_DEBUG, "%s:" MACSTR " %p\n", __func__, MAC2STR(addr), dev);

	dl_list_add(&wfd->devices, &dev->list);
	os_memcpy(dev->dev_addr, addr, ETH_ALEN);
	dev->device_info_bitmap = peer->device_info_bitmap;
	os_memcpy(dev->assoc_bssid, peer->assoc_bssid, ETH_ALEN);
	dev->maximum_tp = peer->maximum_tp;
	dev->coupled_sink_status_bitmap = peer->coupled_sink_status_bitmap;
	/* Coupled device address ??? */

	return 0;
}

int wfd_device_free(struct wfd_data *wfd, const u8 *addr)
{
	struct wfd_device_info_desc *dev;

	dev = wfd_find_device_info(wfd, addr);
	if (!dev)
		return 0;
	wpa_printf(MSG_DEBUG, "%s:" MACSTR " associated=%d\n",
			__func__, MAC2STR(addr), dev->associated);
	/* Don't free accociated device from the list */
	if (dev->associated)	{
		dev->expired = 1;
		return 0;
	}
	if (dev) {
		dl_list_del(&dev->list);
		os_free(dev);
	}

	return 0;
}

void wfd_notify_dev_associated(void *ctx,
				struct wfd_data *wfd, const u8 *addr)
{
	struct wfd_device_info_desc *dev;
	struct wpa_supplicant *wpa_s = ctx;

	dev = wfd_find_device_info(wfd, addr);
	if (dev) {
		dev->associated = 1;
		wpa_printf(MSG_DEBUG, "%s:" MACSTR " Update IE\n",
				__func__, MAC2STR(addr));
		wfd_check_and_update_ies(wpa_s, wfd, 1);
	}
}

void wfd_notify_dev_diassociated(void *ctx,
				struct wfd_data *wfd, const u8 *addr)
{
	struct wfd_device_info_desc *dev;
	struct wpa_supplicant *wpa_s = ctx;

	dev = wfd_find_device_info(wfd, addr);
	if (dev) {
		dev->associated = 0;
		if (dev->expired) {
			dl_list_del(&dev->list);
			os_free(dev);
		}
		wpa_printf(MSG_DEBUG, "%s:" MACSTR " Update IE\n",
			__func__, MAC2STR(addr));
		wfd_check_and_update_ies(wpa_s, wfd, 1);
	}
}

/**
 *  WPA supplicant APIs part.
 */
int wfd_init(struct wpa_global *global, struct wpa_supplicant *wpa_s)
{
	struct wfd_config *cfg;
	struct wfd_data *wfd;
	struct wpa_config *conf = wpa_s->conf;

	wfd = os_zalloc(sizeof(struct wfd_data) + sizeof(*cfg));
	if (wfd == NULL)
		return -1;
	global->wfd = wfd;
	wfd->cfg = (struct wfd_config *) (global->wfd + 1);
	wfd->cfg->type = (u8)conf->wfd_type;
	wfd->cfg->coupled_sink_by_source =
			(u8)conf->wfd_coupled_sink_by_source;
	wfd->cfg->coupled_sink_by_sink = (u8)conf->wfd_coupled_sink_by_sink;
	wfd->cfg->session_available  = (u8)conf->wfd_session_available;
	wfd->cfg->service_discovery =  (u8)conf->wfd_service_discovery;
	wfd->cfg->preferred_connectivity =
			(u8)conf->wfd_preferred_connectivity;
	wfd->cfg->content_protection = (u8)conf->wfd_content_protection;
	wfd->cfg->time_sync = (u8)conf->wfd_time_sync;
	wfd->cfg->session_mgmt_port = (u16)conf->wfd_session_mgmt_port;
	wfd->cfg->dev_max_tp = (u16)conf->wfd_dev_max_tp;
	wfd->cfg->enabled = (u8)conf->wfd_enabled;

	wfd->enabled = (u8)conf->wfd_enabled;

	wfd->device_info &= ~WFD_TYPE_MASK;
	wfd->device_info |= (WFD_TYPE_MASK & wfd->cfg->type);

	if (conf->wfd_coupled_sink_by_source)
		wfd->device_info |=  WFD_COUPLED_SINK_BY_SOURCE;
	else
		wfd->device_info &=  ~WFD_COUPLED_SINK_BY_SOURCE;
	if (conf->wfd_coupled_sink_by_sink)
		wfd->device_info |=  WFD_COUPLED_SINK_BY_SINK;
	else
		wfd->device_info &=  ~WFD_COUPLED_SINK_BY_SINK;
	if (conf->wfd_session_available)
		wfd->device_info |=  WFD_SESSION_AVAILABLE;
	else
		wfd->device_info &=  ~WFD_SESSION_AVAILABLE;

	if (conf->wfd_service_discovery)
		wfd->device_info |=  WFD_SERVICE_DISCOVERY;
	else
		wfd->device_info &=  ~WFD_SERVICE_DISCOVERY;

	if (conf->wfd_preferred_connectivity == WFD_CONNECTIVITY_TDLS)
		wfd->device_info |=  WFD_PREF_CON_TDLS;
	else
		wfd->device_info &=  ~WFD_PREF_CON_TDLS;
	if (conf->wfd_content_protection)
		wfd->device_info |=  WFD_CONTENT_PROTECTION;
	else
		wfd->device_info &=  ~WFD_CONTENT_PROTECTION;
	if (conf->wfd_time_sync)
		wfd->device_info |=  WFD_TIME_SYNC;

	else
		wfd->device_info &=  ~WFD_TIME_SYNC;
	wfd->last_device_info = wfd->device_info;
	wfd->session_mgmt_port = (u16)conf->wfd_session_mgmt_port;
	wfd->dev_max_tp = (u16)conf->wfd_dev_max_tp;
	dl_list_init(&wfd->devices);
	return 0;
}


void wfd_connection_completed(struct wpa_supplicant *wpa_s)
{
	struct wpa_global *global = wpa_s->global;

	wpa_printf(MSG_DEBUG, "%s: wfd=%p\n", __func__, global->wfd);
	if (global->wfd == NULL)
		return;
	if (wpa_s->current_ssid) {
		if (wpa_s->current_ssid->bssid) {
			os_memcpy(global->wfd->assoc_bssid,
					wpa_s->current_ssid->bssid, ETH_ALEN);
			global->wfd->associated = 1;
			wfd_check_and_update_ies(wpa_s, global->wfd, 1);
		}
	}
}

void wfd_clear_connection(struct wpa_supplicant *wpa_s)
{
	struct wpa_global *global = wpa_s->global;
	wpa_printf(MSG_DEBUG, "%s: wfd=%p\n", __func__, global->wfd);

	if (global->wfd == NULL)
		return;

	os_memset(global->wfd->assoc_bssid, 0, ETH_ALEN);
	global->wfd->associated = 0;
	wfd_check_and_update_ies(wpa_s, global->wfd, 1);
}

void wfd_deinit(struct wpa_supplicant *wpa_s)
{
	struct wpa_global *global = wpa_s->global;
	struct wfd_device_info_desc *dev, *prev;
	struct wfd_data *wfd = global->wfd;

	if (wfd == NULL)
		return;

	dl_list_for_each_safe(dev, prev, &wfd->devices,
			struct wfd_device_info_desc, list) {
		dl_list_del(&dev->list);
		os_free(dev);
	}

	os_free(wfd);
	wfd = NULL;
}

