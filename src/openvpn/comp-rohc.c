/*
 *  OpenVPN -- An application to securely tunnel IP networks
 *             over a single UDP port, with support for SSL/TLS-based
 *             session authentication and key exchange,
 *             packet encryption, packet authentication, and
 *             packet compression.
 *
 *  Copyright (C) 2002-2017 OpenVPN Technologies, Inc. <sales@openvpn.net>
 *  Copyright (C) 2010-2011 Didier Barvaux <didier@barvaux.org>
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License version 2
 *  as published by the Free Software Foundation.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License along
 *  with this program; if not, write to the Free Software Foundation, Inc.,
 *  51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#elif defined(_MSC_VER)
#include "config-msvc.h"
#endif

#include "syshead.h"

#if defined(ENABLE_ROHC)

#include "comp.h"
#include "error.h"
#include "misc.h"
#include "basic.h"
#include "proto.h"

#include "memdbg.h"

#include <rohc/rohc_buf.h>
#include <rohc/rohc_comp.h>
#include <rohc/rohc_decomp.h>


static const rohc_profile_t ROHC_PROFILES[] = {
    ROHC_PROFILE_UNCOMPRESSED,
    ROHC_PROFILE_RTP,
    ROHC_PROFILE_UDP,
    ROHC_PROFILE_ESP,
    ROHC_PROFILE_IP,
    ROHC_PROFILE_RTP_LLA,
    ROHC_PROFILE_TCP,
    ROHC_PROFILE_UDPLITE_RTP,
    ROHC_PROFILE_UDPLITE,
    -1
};

static int
rohc_random_cb(const struct rohc_comp *const comp,
               void *const user_context)
{
    return get_random();
}

#ifdef ENABLE_DEBUG
static void rohc_msg_cb(void *const priv_ctxt,
                        const rohc_trace_level_t level,
                        const rohc_trace_entity_t entity,
                        const int profile,
                        const char *const format, ...)
{
    va_list arglist;
    int flags;

    switch (level)
    {
        case ROHC_TRACE_ERROR:
            flags = LOGLEV(6, 5, M_DEBUG);
            break;
        case ROHC_TRACE_WARNING:
            flags = LOGLEV(7, 10, M_DEBUG);
            break;
        case ROHC_TRACE_INFO:
            flags = LOGLEV(8, 20, M_DEBUG);
            break;
        case ROHC_TRACE_DEBUG:
            flags = LOGLEV(9, 50, M_DEBUG);
            break;
        default:
            flags = LOGLEV(11, 70, M_DEBUG);
            break;
    }

    va_start(arglist, format);
    if (msg_test(flags))
    {
        x_msg_va(flags, format, arglist);
    }
    va_end(arglist);
}
#endif

static void
rohc_compress_init(struct compress_context *compctx)
{
    const rohc_profile_t *profile;
    rohc_cid_type_t cid_type;
    rohc_cid_t max_cid;

    msg(D_INIT_MEDIUM, "ROHC compression initializing");
    ASSERT(compctx->flags & COMP_F_SWAP);

    CLEAR(compctx->wu.rohc);

    if ((compctx->flags & COMP_F_ROHC_MANY_STREAMS))
    {
        cid_type = ROHC_LARGE_CID;
        max_cid = ROHC_LARGE_CID_MAX;
    }
    else
    {
        cid_type = ROHC_SMALL_CID;
        max_cid = ROHC_SMALL_CID_MAX;
    }


    /* prepare the compressor */
    compctx->wu.rohc.compressor = rohc_comp_new2(cid_type, max_cid, rohc_random_cb, NULL);
    if (compctx->wu.rohc.compressor == NULL)
    {
        msg(M_FATAL, "Cannot initialize ROHC compressor");
    }

    for (profile = ROHC_PROFILES; *profile != -1; profile++)
    {
        if (!rohc_comp_enable_profile(compctx->wu.rohc.compressor, *profile))
        {
            msg(D_COMP, "Cannot enable ROHC compress profile %s", rohc_get_profile_descr(*profile));
        }
        else
        {
            dmsg(D_COMP, "ROHC compress profile %s enabled", rohc_get_profile_descr(*profile));
        }
    }

    if (!rohc_comp_set_mrru(compctx->wu.rohc.compressor, 0))
    {
        msg(M_WARN, "Cannot disable ROHC segmentation");
    }

#ifdef ENABLE_DEBUG
    if (!rohc_comp_set_traces_cb2(compctx->wu.rohc.compressor, rohc_msg_cb, NULL))
    {
        msg(M_WARN, "Cannot set ROHC compressor log callback");
    }
#endif

    /* prepare the decompressor */
    compctx->wu.rohc.decompressor = rohc_decomp_new2(cid_type, max_cid, ROHC_U_MODE);
    if (compctx->wu.rohc.decompressor == NULL)
    {
        msg(M_FATAL, "Cannot initialize ROHC decompressor");
    }

    for (profile = ROHC_PROFILES; *profile != -1; profile++)
    {
        if (!rohc_decomp_enable_profile(compctx->wu.rohc.decompressor, *profile))
        {
            msg(D_COMP, "Cannot enable ROHC decompress profile %s", rohc_get_profile_descr(*profile));
        }
        else
        {
            dmsg(D_COMP, "ROHC decompress profile %s enabled", rohc_get_profile_descr(*profile));
        }
    }

#ifdef ENABLE_DEBUG
    if (!rohc_decomp_set_traces_cb2(compctx->wu.rohc.decompressor, rohc_msg_cb, NULL))
    {
        msg(M_WARN, "Cannot set ROHC decompressor log callback");
    }
#endif
}

static void
rohc_compress_uninit(struct compress_context *compctx)
{
    rohc_comp_free(compctx->wu.rohc.compressor);
    compctx->wu.rohc.compressor = NULL;

    rohc_decomp_free(compctx->wu.rohc.decompressor);
    compctx->wu.rohc.decompressor = NULL;
}

static void
rohc_compress(struct buffer *buf, struct buffer work,
              struct compress_context *compctx,
              const struct frame *frame, int tunnel_type)
{
    const size_t ps = PAYLOAD_SIZE(frame);
    const size_t ps_max = ps + COMP_EXTRA_BUFFER(ps);
    int iphdr_offset;
    uint8_t head_byte = NO_COMPRESS_BYTE_SWAP;

    if (BLEN(buf) <= 0)
    {
        return;
    }
    else if (BLEN(buf) > ps)
    {
        dmsg(D_COMP_ERRORS, "ROHC compression buffer overflow");
        buf_reset_len(buf);
        return;
    }

    /* check if the frame can be ROHC compressed */
    switch (get_tun_ip_ver(tunnel_type, buf, &iphdr_offset))
    {
        case 4:
        case 6:
            break;

        default:
            goto nocomp;
    }

    ASSERT(buf_init(&work, FRAME_HEADROOM(frame)));
    ASSERT(buf_safe(&work, ps_max));

    /* copy pre-IP data (i.e. Ethernet header) */
    if (iphdr_offset > 0)
    {
        ASSERT(buf_copy_n(&work, buf, iphdr_offset));
    }

    {
        rohc_status_t rohc_status;

        /* prepare buffers for ROHC */
        struct rohc_buf uncomp_buf = rohc_buf_init_full(BPTR(buf), BLEN(buf), 0);
        struct rohc_buf comp_buf = rohc_buf_init_empty(BPTR(&work), ps_max);

        /* compress the packet */
        rohc_status = rohc_compress4(compctx->wu.rohc.compressor,
                                     uncomp_buf, &comp_buf);
        switch (rohc_status)
        {
            case ROHC_STATUS_OK:
                ASSERT(buf_inc_len(&work, comp_buf.len));

                dmsg(D_COMP, "ROHC compress %d -> %d", BLEN(buf), BLEN(&work));
                compctx->pre_compress += BLEN(buf);
                compctx->post_compress += BLEN(&work);

                head_byte = ROHC_COMPRESS_BYTE;
                break;

            case ROHC_STATUS_SEGMENT:
                dmsg(D_COMP, "Skip multiple segments created by ROHC compression");
                break;

            case ROHC_STATUS_OUTPUT_TOO_SMALL:
                dmsg(D_COMP_ERRORS, "ROHC compression error: too large result");
                break;

            case ROHC_STATUS_ERROR:
                dmsg(D_COMP_ERRORS, "ROHC compression error");
                break;

            default:
                dmsg(D_COMP_ERRORS, "ROHC compression unknown error: %d", (int)rohc_status);
                break;
        }

        if (rohc_status != ROHC_STATUS_OK)
        {
            /* copy uncompressed data */
            ASSERT(buf_copy(&work, buf));
        }

        *buf = work;
    }

nocomp:
    /* store compression status */
    {
        uint8_t *head = BPTR(buf);

        /* move head byte of payload to tail */
        ASSERT(buf_write_u8(buf, *head));
        *head = head_byte;
    }
}

static void
rohc_decompress(struct buffer *buf, struct buffer work,
                struct compress_context *compctx,
                const struct frame *frame, int tunnel_type)
{
    const size_t max_decomp_size = EXPANDED_SIZE(frame);
    uint8_t c;

    if (BLEN(buf) <= 0)
    {
        return;
    }

    /* do unframing/swap (assumes buf->len > 0) */
    {
        uint8_t *head = BPTR(buf);
        c = *head;
        *head = *BLAST(buf);
        ASSERT(buf_inc_len(buf, -1));
    }

    if (c == ROHC_COMPRESS_BYTE) /* packet was compressed */
    {
        ASSERT(buf_init(&work, FRAME_HEADROOM(frame)));

        /* copy pre-IP data (i.e. Ethernet header) */
        if (tunnel_type == DEV_TYPE_TAP)
        {
            ASSERT(buf_copy_n(&work, buf, sizeof(struct openvpn_ethhdr)));
        }

        ASSERT(buf_safe(&work, max_decomp_size));

        {
            rohc_status_t rohc_status;

            /* prepare buffers for ROHC */
            struct rohc_buf comp_buf = rohc_buf_init_full(BPTR(buf), BLEN(buf), 0);
            struct rohc_buf uncomp_buf = rohc_buf_init_empty(BPTR(&work), max_decomp_size);

            /* compress the packet */
            rohc_status = rohc_decompress3(compctx->wu.rohc.decompressor,
                                           comp_buf, &uncomp_buf, NULL, NULL);
            switch (rohc_status)
            {
                case ROHC_STATUS_OK:
                    /* if ROHC segment or feedback-only packet */
                    if (rohc_buf_is_empty(uncomp_buf))
                    {
                        dmsg(D_COMP, "ROHC decompressed no IP packet");
                        buf_reset_len(buf);
                        return;
                    }
                    break;

                case ROHC_STATUS_NO_CONTEXT:
                    dmsg(D_COMP_ERRORS, "ROHC decompression error: no decompression "
                                        "context was found for the ROHC packet");
                    break;

                case ROHC_STATUS_OUTPUT_TOO_SMALL:
                    dmsg(D_COMP_ERRORS, "ROHC decompression error: too large result");
                    break;

                case ROHC_STATUS_MALFORMED:
                    dmsg(D_COMP_ERRORS, "ROHC decompression error: malformed packet");
                    break;

                case ROHC_STATUS_BAD_CRC:
                    dmsg(D_COMP_ERRORS, "ROHC decompression error: bad CRC");
                    break;

                case ROHC_STATUS_ERROR:
                default:
                    dmsg(D_COMP_ERRORS, "ROHC decompression error");
                    break;
            }

            if (rohc_status != ROHC_STATUS_OK)
            {
                buf_reset_len(buf);
                return;
            }

            ASSERT(buf_inc_len(&work, uncomp_buf.len));
        }

        dmsg(D_COMP, "ROHC decompress %d -> %d", BLEN(buf), BLEN(&work));
        compctx->pre_decompress += BLEN(buf);
        compctx->post_decompress += BLEN(&work);

        *buf = work;
    }
    else if (c == NO_COMPRESS_BYTE_SWAP) /* packet was not compressed */
    {
    }
    else
    {
        dmsg(D_COMP_ERRORS, "Bad ROHC decompression header byte: %d", (int)c);
        buf_reset_len(buf);
    }
}


const struct compress_alg rohc_alg = {
    "rohc",
    rohc_compress_init,
    rohc_compress_uninit,
    rohc_compress,
    rohc_decompress
};

#else  /* if defined(ENABLE_ROHC) */
static void
dummy(void)
{
}
#endif /* ENABLE_ROHC */
