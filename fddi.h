/* @(#) $Header: fddi.h,v 1.1 99/01/17 17:51:02 leres Exp $ (LBL) */
/* Support for IP-over-FDDI */

/*
 * 802.2 specific declarations
 */
struct llchdr {
	u_char llc_dsap;
	u_char llc_ssap;
	u_char llc_ctl;
};

struct snaphdr {
	u_char snap_oid[3];
	u_char snap_type[2];
};

struct fddi_header {
	u_char frame_ctl;
	u_char dst[6];
	u_char src[6];
	struct llchdr llc;
	struct snaphdr snap;
};
