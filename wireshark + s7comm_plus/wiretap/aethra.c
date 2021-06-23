/* aethra.c
 *
 * Wiretap Library
 * Copyright (c) 1998 by Gilbert Ramirez <gram@alumni.rice.edu>
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"
#include <errno.h>
#include <string.h>
#include "wtap-int.h"
#include "file_wrappers.h"
#include "aethra.h"

/* Magic number in Aethra PC108 files. */
#define MAGIC_SIZE	5

static const guchar aethra_magic[MAGIC_SIZE] = {
	'V', '0', '2', '0', '8'
};

/* Aethra file header. */
struct aethra_hdr {
	guchar	magic[MAGIC_SIZE];
	guint8	unknown1[39];	/* 5-43 */
	guchar	sw_vers[60];	/* 44-103 - software version string, not null-terminated */
	guint8	unknown2[118];	/* 104-221 */
	guint8	start_sec;	/* 222 - seconds of capture start time */
	guint8	start_min;	/* 223 - minutes of capture start time */
	guint8	start_hour;	/* 224 - hour of capture start time */
	guint8	unknown3[462];	/* 225-686 */
	guchar	xxx_string[37];	/* 687-723 - null-terminated short comment string? */
	guint8	unknown3_5[4];	/* 724-727 */
	guchar	yyy_string[4504];/* 728-5231 - null-terminated long comment string? */
	guint8	start_year[2];	/* 5232-5233 - year of capture start date */
	guint8	start_month[2];	/* 5234-5235 - month of capture start date */
	guint8	unknown4[2];	/* 5236-5237 */
	guint8	start_day[2];	/* 5238-5239 - day of capture start date */
	guint8	unknown5[8];	/* 5240-5247 */
	guchar	com_info[16];	/* 5248-5263 - COM port and speed, null-padded(?) */
	guint8	unknown6[107];	/* 5264-5370 */
	guchar	xxx_vers[41];	/* 5371-5411 - unknown version string (longer, null-padded?) */
};

/* Aethra record header.  Yes, the alignment is weird.
   All multi-byte fields are little-endian. */
struct aethrarec_hdr {
	guint8 rec_size[2];	/* record length, not counting the length itself */
	guint8 rec_type;	/* record type */
	guint8 timestamp[4];	/* milliseconds since start of capture */
	guint8 flags;		/* low-order bit: 0 = N->U, 1 = U->N */
};

/*
 * Record types.
 *
 * As the indications from the device and signalling messages appear not
 * to have the 8th bit set, and at least some B-channel records do, we
 * assume, for now, that the 8th bit indicates bearer information.
 *
 * 0x9F is the record type seen for B31 channel records; that might be
 * 0x80|31, so, for now, we assume that if the 8th bit is set, the B
 * channel number is in the low 7 bits.
 */
#define AETHRA_BEARER		0x80	/* bearer information */

#define AETHRA_DEVICE		0x00	/* indication from the monitoring device */
#define AETHRA_ISDN_LINK	0x01	/* information from the ISDN link */

/*
 * In AETHRA_DEVICE records, the flags field has what appears to
 * be a record subtype.
 */
#define AETHRA_DEVICE_STOP_MONITOR	0x00	/* Stop Monitor */
#define AETHRA_DEVICE_START_MONITOR	0x04	/* Start Monitor */
#define AETHRA_DEVICE_ACTIVATION	0x05	/* Activation */
#define AETHRA_DEVICE_START_CAPTURE	0x5F	/* Start Capture */

/*
 * In AETHRA_ISDN_LINK and bearer channel records, the flags field has
 * a direction flag and possibly some other bits.
 *
 * In AETHRA_ISDN_LINK records, at least some of the other bits are
 * a subtype.
 *
 * In bearer channel records, there are records with data and
 * "Constant Value" records with a single byte.  Data has a
 * flags value of 0x14 ORed with the direction flag, and Constant Value
 * records have a flags value of 0x16 ORed with the direction flag.
 * There are also records of an unknown type with 0x02, probably
 * ORed with the direction flag.
 */
#define AETHRA_U_TO_N				0x01	/* set for TE->NT */

#define AETHRA_ISDN_LINK_SUBTYPE		0xFE
#define AETHRA_ISDN_LINK_LAPD			0x00	/* LAPD frame */
#define AETHRA_ISDN_LINK_SA_BITS		0x2E	/* 2048K PRI Sa bits (G.704 section 2.3.2) */
#define AETHRA_ISDN_LINK_ALL_ALARMS_CLEARED	0x30	/* All Alarms Cleared */

typedef struct {
	time_t	start;
} aethra_t;

static gboolean aethra_read(wtap *wth, wtap_rec *rec, Buffer *buf, int *err,
    gchar **err_info, gint64 *data_offset);
static gboolean aethra_seek_read(wtap *wth, gint64 seek_off,
    wtap_rec *rec, Buffer *buf, int *err, gchar **err_info);
static gboolean aethra_read_rec_header(wtap *wth, FILE_T fh, struct aethrarec_hdr *hdr,
    wtap_rec *rec, int *err, gchar **err_info);

wtap_open_return_val aethra_open(wtap *wth, int *err, gchar **err_info)
{
	struct aethra_hdr hdr;
	struct tm tm;
	aethra_t *aethra;

	/* Read in the string that should be at the start of a "aethra" file */
	if (!wtap_read_bytes(wth->fh, hdr.magic, sizeof hdr.magic, err,
	    err_info)) {
		if (*err != WTAP_ERR_SHORT_READ)
			return WTAP_OPEN_ERROR;
		return WTAP_OPEN_NOT_MINE;
	}

	if (memcmp(hdr.magic, aethra_magic, sizeof aethra_magic) != 0)
		return WTAP_OPEN_NOT_MINE;

	/* Read the rest of the header. */
	if (!wtap_read_bytes(wth->fh, (char *)&hdr + sizeof hdr.magic,
	    sizeof hdr - sizeof hdr.magic, err, err_info))
		return WTAP_OPEN_ERROR;
	wth->file_type_subtype = WTAP_FILE_TYPE_SUBTYPE_AETHRA;
	aethra = (aethra_t *)g_malloc(sizeof(aethra_t));
	wth->priv = (void *)aethra;
	wth->subtype_read = aethra_read;
	wth->subtype_seek_read = aethra_seek_read;

	/*
	 * Convert the time stamp to a "time_t".
	 */
	tm.tm_year = pletoh16(&hdr.start_year) - 1900;
	tm.tm_mon = pletoh16(&hdr.start_month) - 1;
	tm.tm_mday = pletoh16(&hdr.start_day);
	tm.tm_hour = hdr.start_hour;
	tm.tm_min = hdr.start_min;
	tm.tm_sec = hdr.start_sec;
	tm.tm_isdst = -1;
	aethra->start = mktime(&tm);

	/*
	 * We've only seen ISDN files, so, for now, we treat all
	 * files as ISDN.
	 */
	wth->file_encap = WTAP_ENCAP_ISDN;
	wth->snapshot_length = 0;	/* not available in header */
	wth->file_tsprec = WTAP_TSPREC_MSEC;

	/*
	 * Add an IDB; we don't know how many interfaces were
	 * involved, so we just say one interface, about which
	 * we only know the link-layer type, snapshot length,
	 * and time stamp resolution.
	 */
	wtap_add_generated_idb(wth);

	return WTAP_OPEN_MINE;
}

#if 0
static guint packet = 0;
#endif

/* Read the next packet */
static gboolean aethra_read(wtap *wth, wtap_rec *rec, Buffer *buf, int *err,
    gchar **err_info, gint64 *data_offset)
{
	struct aethrarec_hdr hdr;

	/*
	 * Keep reading until we see an AETHRA_ISDN_LINK with a subtype
	 * of AETHRA_ISDN_LINK_LAPD record or get an end-of-file.
	 */
	for (;;) {
		*data_offset = file_tell(wth->fh);

		/* Read record header. */
		if (!aethra_read_rec_header(wth, wth->fh, &hdr, rec, err, err_info))
			return FALSE;

		/*
		 * XXX - if this is big, we might waste memory by
		 * growing the buffer to handle it.
		 */
		if (rec->rec_header.packet_header.caplen != 0) {
			if (!wtap_read_packet_bytes(wth->fh, buf,
			    rec->rec_header.packet_header.caplen, err, err_info))
				return FALSE;	/* Read error */
		}
#if 0
packet++;
#endif
		switch (hdr.rec_type) {

		case AETHRA_ISDN_LINK:
#if 0
fprintf(stderr, "Packet %u: type 0x%02x (AETHRA_ISDN_LINK)\n",
packet, hdr.rec_type);
#endif
			switch (hdr.flags & AETHRA_ISDN_LINK_SUBTYPE) {

			case AETHRA_ISDN_LINK_LAPD:
				/*
				 * The data is a LAPD frame.
				 */
#if 0
fprintf(stderr, "    subtype 0x%02x (AETHRA_ISDN_LINK_LAPD)\n", hdr.flags & AETHRA_ISDN_LINK_SUBTYPE);
#endif
				goto found;

			case AETHRA_ISDN_LINK_SA_BITS:
				/*
				 * These records have one data byte, which
				 * has the Sa bits in the lower 5 bits.
				 *
				 * XXX - what about stuff other than 2048K
				 * PRI lines?
				 */
#if 0
fprintf(stderr, "    subtype 0x%02x (AETHRA_ISDN_LINK_SA_BITS)\n", hdr.flags & AETHRA_ISDN_LINK_SUBTYPE);
#endif
				break;

			case AETHRA_ISDN_LINK_ALL_ALARMS_CLEARED:
				/*
				 * No data, just an "all alarms cleared"
				 * indication.
				 */
#if 0
fprintf(stderr, "    subtype 0x%02x (AETHRA_ISDN_LINK_ALL_ALARMS_CLEARED)\n", hdr.flags & AETHRA_ISDN_LINK_SUBTYPE);
#endif
				break;

			default:
#if 0
fprintf(stderr, "    subtype 0x%02x, packet_size %u, direction 0x%02x\n",
hdr.flags & AETHRA_ISDN_LINK_SUBTYPE, rec->rec_header.packet_header.caplen, hdr.flags & AETHRA_U_TO_N);
#endif
				break;
			}
			break;

		default:
#if 0
fprintf(stderr, "Packet %u: type 0x%02x, packet_size %u, flags 0x%02x\n",
packet, hdr.rec_type, rec->rec_header.packet_header.caplen, hdr.flags);
#endif
			break;
		}
	}

found:
	return TRUE;
}

static gboolean
aethra_seek_read(wtap *wth, gint64 seek_off, wtap_rec *rec,
    Buffer *buf, int *err, gchar **err_info)
{
	struct aethrarec_hdr hdr;

	if (file_seek(wth->random_fh, seek_off, SEEK_SET, err) == -1)
		return FALSE;

	if (!aethra_read_rec_header(wth, wth->random_fh, &hdr, rec, err,
	    err_info)) {
		if (*err == 0)
			*err = WTAP_ERR_SHORT_READ;
		return FALSE;
	}

	/*
	 * Read the packet data.
	 */
	if (!wtap_read_packet_bytes(wth->random_fh, buf, rec->rec_header.packet_header.caplen, err, err_info))
		return FALSE;	/* failed */

	return TRUE;
}

static gboolean
aethra_read_rec_header(wtap *wth, FILE_T fh, struct aethrarec_hdr *hdr,
    wtap_rec *rec, int *err, gchar **err_info)
{
	aethra_t *aethra = (aethra_t *)wth->priv;
	guint32 rec_size;
	guint32	packet_size;
	guint32	msecs;

	/* Read record header. */
	if (!wtap_read_bytes_or_eof(fh, hdr, sizeof *hdr, err, err_info))
		return FALSE;

	rec_size = pletoh16(hdr->rec_size);
	if (rec_size < (sizeof *hdr - sizeof hdr->rec_size)) {
		/* The record is shorter than a record header. */
		*err = WTAP_ERR_BAD_FILE;
		*err_info = g_strdup_printf("aethra: File has %u-byte record, less than minimum of %u",
		    rec_size,
		    (unsigned int)(sizeof *hdr - sizeof hdr->rec_size));
		return FALSE;
	}
	if (rec_size > WTAP_MAX_PACKET_SIZE_STANDARD) {
		/*
		 * Probably a corrupt capture file; return an error,
		 * so that our caller doesn't blow up trying to allocate
		 * space for an immensely-large packet.
		 */
		*err = WTAP_ERR_BAD_FILE;
		*err_info = g_strdup_printf("aethra: File has %u-byte packet, bigger than maximum of %u",
		    rec_size, WTAP_MAX_PACKET_SIZE_STANDARD);
		return FALSE;
	}

	packet_size = rec_size - (guint32)(sizeof *hdr - sizeof hdr->rec_size);

	msecs = pletoh32(hdr->timestamp);
	rec->rec_type = REC_TYPE_PACKET;
	rec->presence_flags = WTAP_HAS_TS;
	rec->ts.secs = aethra->start + (msecs / 1000);
	rec->ts.nsecs = (msecs % 1000) * 1000000;
	rec->rec_header.packet_header.caplen = packet_size;
	rec->rec_header.packet_header.len = packet_size;
	rec->rec_header.packet_header.pseudo_header.isdn.uton = (hdr->flags & AETHRA_U_TO_N);
	rec->rec_header.packet_header.pseudo_header.isdn.channel = 0;	/* XXX - D channel */

	return TRUE;
}

/*
 * Editor modelines  -  https://www.wireshark.org/tools/modelines.html
 *
 * Local variables:
 * c-basic-offset: 8
 * tab-width: 8
 * indent-tabs-mode: t
 * End:
 *
 * vi: set shiftwidth=8 tabstop=8 noexpandtab:
 * :indentSize=8:tabSize=8:noTabs=false:
 */
