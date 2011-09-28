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

#ifndef WFD_I_H_
#define WFD_I_H_

#define WFD_TYPE_MASK			(BIT(0)|BIT(1))
#define WFD_COUPLED_SINK_BY_SOURCE	BIT(2)
#define WFD_COUPLED_SINK_BY_SINK	BIT(3)
#define WFD_SESSION_AVAILABLE		BIT(4)
#define WFD_SESSION_AVAILABLE_MASK	(BIT(4)|BIT(5))
#define WFD_SERVICE_DISCOVERY		BIT(6)
#define WFD_PREF_CON_TDLS		BIT(7)
#define WFD_CONTENT_PROTECTION		BIT(8)
#define WFD_TIME_SYNC			BIT(9)
#define WFD_CONNECTIVITY_P2P		0
#define WFD_CONNECTIVITY_TDLS		1

struct wfd_peer_info {
	/**
	 *  Wi-Fi display information subelements
	 */
	u16 device_info_bitmap;
	u16 session_mng_port;
	u16 maximum_tp;
	u8  assoc_bssid[ETH_ALEN];
	u8  coupled_sink_status_bitmap;
};

struct wfd_data;
struct wpa_supplicant;
struct wpa_global;

/* WFD module initialization/deinitialization */

/**
 * wfd_init - Initialize WFD module
 * @global: Pointer to global data from wpa_supplicant_init()
 * @wpa_s: Pointer to wpa_supplicant data
 * Returns: 0 - on success or -1 on failure
 *
 * This function is used to initialize global WFD module context.
 * The WFD module will keep a copy of the configuration data.
 * The context parameters are available until
 * the WFD module is deinitialized with wfd_deinit().
 */
int wfd_init(struct wpa_global *global, struct wpa_supplicant *wpa_s);
void wfd_deinit(struct wpa_supplicant *wpa_s);

/* WFD parameter set functions */

/**
 * wfd_set_type - Set WFD device type
 * @wfd: WFD module context
 * @type: Set parameter at WFD module context
 * @wpa_s: Pointer to wpa_supplicant data
 *
 * This function can be used to update the WFD module configuration
 */
void wfd_set_enabled(struct wfd_data *wfd, int enabled);
void wfd_set_type(struct wfd_data *wfd,
				int type, struct wpa_supplicant *wpa_s);
void wfd_set_coupled_sink_by_source(struct wfd_data *wfd,
				int supported, struct wpa_supplicant *wpa_s);
void wfd_set_coupled_sink_by_sink(struct wfd_data *wfd,
				int supported, struct wpa_supplicant *wpa_s);
void wfd_set_session_available(struct wfd_data *wfd,
				int available, struct wpa_supplicant *wpa_s);
void wfd_set_service_discovery(struct wfd_data *wfd,
				int supported, struct wpa_supplicant *wpa_s);
void wfd_set_preferred_connectivity(struct wfd_data *wfd,
			int connectivity, struct wpa_supplicant *wpa_s);
void wfd_set_content_protection(struct wfd_data *wfd,
				int supported, struct wpa_supplicant *wpa_s);
void wfd_set_time_sync(struct wfd_data *wfd,
				int supported, struct wpa_supplicant *wpa_s);
void wfd_set_session_mgmt_port(struct wfd_data *wfd,
				short port_num, struct wpa_supplicant *wpa_s);
void wfd_set_dev_max_tp(struct wfd_data *wfd,
			short max_throughput, struct wpa_supplicant *wpa_s);

/* WFD get functions */
/**
 * wfd_get_show_param - Show local configuration and peer list
 * @wfd: WFD module context
 * @buf: Buffer to put results
 * @reply_size: Size of result
 * Return: 0 - on success, 1 - on failure
 *
 * This function is used to reply WFD module information on
 * user requests
 */
int wfd_get_show_param(struct wfd_data *wfd, char *buf, size_t reply_size);
/**
 * wfd_get_dev_info - Get device info bitmap
 * @wfd: WFD module context
 * @buf: Buffer to put result
 * @reply_size: Size of result
 * Return: 0 - on success, 1 - on failure
 *
 * This function is used to get device info information bitmap
 * as hexadecimal string
 */
int wfd_get_dev_info(struct wfd_data *wfd, char *buf, size_t reply_size);

/* WFD IE build functions */
/**
 * wfd_build_prob_resp_ies - Add WFD IE to probe response
 * @wfd: WFD module context
 * @buf: wpabuf to be modified
 *
 * This function is used by P2P module to add WFD IE
 */
void wfd_build_prob_resp_ies(struct wfd_data *wfd, struct wpabuf *buf);
/**
 * wfd_build_probe_req_ies - Add WFD IE to probe request
 * @wfd: WFD module context
 * @buf: wpabuf to be modified
 *
 * This function is used by P2P module to add WFD IE
 */
void wfd_build_probe_req_ies(struct wfd_data *wfd, struct wpabuf *buf);
/**
 * wfd_build_go_neg_req_ie - Add WFD IE to GO negotiation request
 * @wfd: WFD module context
 * @buf: wpabuf to be modified
 *
 * This function is used by P2P module to add WFD IE
 */
void wfd_build_go_neg_req_ie(struct wfd_data *wfd, struct wpabuf *buf);

/**
 * wfd_build_prov_disc_req_ie - Add WFD IE to Provision Discovery
 * Request Action Frame
 * @wfd: WFD module context
 * @buf: wpabuf to be modified
 *
 * This function is used by P2P module to add WFD IE
 */
void wfd_build_prov_disc_req_ie(struct wfd_data *wfd, struct wpabuf *buf);
/**
 * wfd_parse_ies - Parse WFD IE
 * @ie: Pointer to information element
 * @peer: Pointer to parsed WFD peer structure
 * Return: 0 - on success, -1 - on failure
 *
 * This function is used by P2P module to add WFD IE
 */
int wfd_parse_ies(struct wpabuf *ie, struct wfd_peer_info *peer);
/**
 * wfd_notify_dev_associated - Notify WFD module about client association
 * @ctx: Pointer to the wpa_supplicant module context
 * @wfd: WFD module context
 * @addr: Address of associated device
 *
 * This function is called by GO upon WFD device association.
 * WFD module manages list of WFD discovered devices and marks
 * associated devices.
 */
void wfd_notify_dev_associated(void *ctx,
			struct wfd_data *wfd, const u8 *addr);
/**
 * wfd_notify_dev_associated - Notify WFD module about client disassotiation
 * @ctx: Pointer to the wpa_supplicant module context
 * @wfd: WFD module context
 * @addr: Address of diassociated device
 *
 * This function is called by GO upon WFD device disassociation.
 * WFD module manages list of WFD discovered devices and marks
 * the device as disassotiated
 */
void wfd_notify_dev_diassociated(void *ctx,
			struct wfd_data *wfd, const u8 *addr);
/**
 * wfd_add_device - Add WFD device information to WFD module
 * @wfd: WFD module context
 * @peer: parsed device information
 * @addr: device address
 *
 * This function is called upon discovering WFD device
 * WFD module adds device information to internal module list
 *
 */
int wfd_add_device(struct wfd_data *wfd,
		struct wfd_peer_info *peer, const u8 *addr);
/**
 * wfd_device_free - Free WFD information
 * @wfd: WFD module context
 * @addr: device address
 *
 * This function is called by P2P module when P2P device
 * has expired
 */
int wfd_device_free(struct wfd_data *wfd, const u8 *addr);
/**
 * wfd_connection_completed - Notify WFD module about connection completion
 * @wpa_s: Pointer to wpa_supplicant data
 *
 * This function is called by wpa_supplicant under changing of
 * operational state
 */
void wfd_connection_completed(struct wpa_supplicant *wpa_s);
/**
 * wfd_connection_completed - Notify WFD module about connection clearing
 * @wpa_s: Pointer to wpa_supplicant data
 *
 * This function is called by wpa_supplicant under changing of
 * operational state
 */
void wfd_clear_connection(struct wpa_supplicant *wpa_s);
/**
 * wfd_buf_add_device_info - Add device info IE to buffer
 * @wfd: WFD module context
 * @addr: device address
 *
 * This function is called by p2p under building of
 * service discovery request
 */
void wfd_buf_add_device_info(struct wfd_data *wfd, struct wpabuf *buf);
#endif /* WFD_I_H_ */
