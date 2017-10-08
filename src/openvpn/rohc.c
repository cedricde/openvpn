/*
 *  OpenVPN -- An application to securely tunnel IP networks
 *             over a single UDP port, with support for SSL/TLS-based
 *             session authentication and key exchange,
 *             packet encryption, packet authentication, and
 *             packet compression.
 *
 *  Copyright (C) 2002-2017 OpenVPN Technologies, Inc. <sales@openvpn.net>
 *  Copyright (C) 2010-2011 Didier Barvaux <didier@barvaux.org>
 *  Copyright (C) 2017 Cédric Delmas <cedricde@outlook.fr>
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

#include "basic.h"
#include "buffer.h"
#include "error.h"
#include "misc.h"
#include "occ.h"
#include "ping.h"
#include "proto.h"

#include "memdbg.h"

#include <rohc/rohc.h>
#include <rohc/rohc_buf.h>
#include <rohc/rohc_comp.h>
#include <rohc/rohc_decomp.h>


static const rohc_profile_t ROHC_PROFILES[] = {
    ROHC_PROFILE_UNCOMPRESSED,
    /* ROHC_PROFILE_RTP, */
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
            flags = LOGLEV(4, 5, M_DEBUG);
            break;
        case ROHC_TRACE_WARNING:
            flags = LOGLEV(5, 10, M_DEBUG);
            break;
        case ROHC_TRACE_INFO:
            flags = LOGLEV(6, 20, M_DEBUG);
            break;
        case ROHC_TRACE_DEBUG:
            flags = LOGLEV(7, 50, M_DEBUG);
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

struct rohc_context *
rohc_init(const struct rohc_options *opt)
{
    struct rohc_context *rohcctx;
    const rohc_profile_t *profile;
    rohc_cid_type_t cid_type;
    rohc_cid_t max_cid;

    if (!rohc_enabled(opt))
    {
        return NULL;
    }

    msg(D_INIT_MEDIUM, "ROHC compression initializing");

    max_cid = opt->max_contexts - 1;
    if (max_cid > ROHC_LARGE_CID_MAX)
    {
        msg(M_FATAL, "Maximum ROHC CID is too large");
    }
    else if (max_cid > ROHC_SMALL_CID_MAX)
    {
        cid_type = ROHC_LARGE_CID;
    }
    else
    {
        cid_type = ROHC_SMALL_CID;
    }

    ALLOC_OBJ_CLEAR(rohcctx, struct rohc_context);

    /* prepare the compressor */
    rohcctx->compressor = rohc_comp_new2(cid_type, max_cid, rohc_random_cb, NULL);
    if (rohcctx->compressor == NULL)
    {
        msg(M_FATAL, "Cannot initialize ROHC compressor");
    }

    for (profile = ROHC_PROFILES; *profile != -1; profile++)
    {
        if (!rohc_comp_enable_profile(rohcctx->compressor, *profile))
        {
            msg(D_COMP, "Cannot enable ROHC compress profile %s", rohc_get_profile_descr(*profile));
        }
        else
        {
            dmsg(D_COMP, "ROHC compress profile %s enabled", rohc_get_profile_descr(*profile));
        }
    }

    if (!rohc_comp_set_mrru(rohcctx->compressor, 0))
    {
        msg(M_WARN, "Cannot disable ROHC segmentation");
    }

#ifdef ENABLE_DEBUG
    if (!rohc_comp_set_traces_cb2(rohcctx->compressor, rohc_msg_cb, NULL))
    {
        msg(M_WARN, "Cannot set ROHC compressor log callback");
    }
#endif

    /* prepare the decompressor */
    rohcctx->decompressor = rohc_decomp_new2(cid_type, max_cid, ROHC_U_MODE);
    if (rohcctx->decompressor == NULL)
    {
        msg(M_FATAL, "Cannot initialize ROHC decompressor");
    }

    for (profile = ROHC_PROFILES; *profile != -1; profile++)
    {
        if (!rohc_decomp_enable_profile(rohcctx->decompressor, *profile))
        {
            msg(D_COMP, "Cannot enable ROHC decompress profile %s", rohc_get_profile_descr(*profile));
        }
        else
        {
            dmsg(D_COMP, "ROHC decompress profile %s enabled", rohc_get_profile_descr(*profile));
        }
    }

#ifdef ENABLE_DEBUG
    if (!rohc_decomp_set_traces_cb2(rohcctx->decompressor, rohc_msg_cb, NULL))
    {
        msg(M_WARN, "Cannot set ROHC decompressor log callback");
    }
#endif

    return rohcctx;
}

void
rohc_uninit(struct rohc_context *rohcctx)
{
    if (rohcctx)
    {
        rohc_comp_free(rohcctx->compressor);
        rohcctx->compressor = NULL;

        rohc_decomp_free(rohcctx->decompressor);
        rohcctx->decompressor = NULL;

        free(rohcctx);
    }
}

void
rohc_print_stats(const struct rohc_context *rohcctx, struct status_output *so)
{
    if (rohcctx)
    {
        status_printf(so, "ROHC pre-compress bytes," counter_format, rohcctx->pre_compress);
        status_printf(so, "ROHC post-compress bytes," counter_format, rohcctx->post_compress);
        status_printf(so, "ROHC pre-decompress bytes," counter_format, rohcctx->pre_decompress);
        status_printf(so, "ROHC post-decompress bytes," counter_format, rohcctx->post_decompress);
    }
}

void
rohc_generate_peer_info_string(const struct rohc_options *opt, struct buffer *out)
{
    if (opt)
    {
        buf_printf(out, "IV_ROHC=%u\n", opt->max_contexts);
    }
}

void
rohc_compress(struct buffer *buf, struct buffer work,
              struct rohc_context *rohcctx,
              const struct frame *frame, int tunnel_type)
{
    const size_t ps = PAYLOAD_SIZE(frame);
    int iphdr_offset = 0;

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

    /* check if the packet is an internal one */
    if (is_ping_msg(buf)
#ifdef ENABLE_OCC
        || is_occ_msg(buf)
#endif
       )
    {
        /* skip compression for non-IP packets */
        return;
    }

    /* check if the frame can be ROHC compressed */
    switch (get_tun_ip_ver(tunnel_type, buf, &iphdr_offset))
    {
        case 4:
        case 6:
            break;

        default:
            return;
    }

    ASSERT(buf_init(&work, FRAME_HEADROOM(frame)));
    ASSERT(buf_safe(&work, ps + COMP_EXTRA_BUFFER(ps)));

    /* copy pre-IP data (i.e. Ethernet header) */
    if (iphdr_offset > 0)
    {
        ASSERT(buf_copy_n(&work, buf, iphdr_offset));
        ASSERT(buf_advance(&work, iphdr_offset));
    }

    {
        /* prepare buffers for ROHC */
        struct rohc_buf uncomp_buf = rohc_buf_init_full(BPTR(buf), BLEN(buf), 0);
        struct rohc_buf comp_buf = rohc_buf_init_empty(BPTR(&work), BCAP(&work));

        /* compress the packet */
        rohc_status_t rohc_status = rohc_compress4(rohcctx->compressor, uncomp_buf, &comp_buf);
        switch (rohc_status)
        {
            case ROHC_STATUS_OK:
                ASSERT(buf_inc_len(&work, comp_buf.len));

                dmsg(D_COMP, "ROHC compress %d -> %d", BLEN(buf), BLEN(&work));
                rohcctx->pre_compress += BLEN(buf);
                rohcctx->post_compress += BLEN(&work);

                /* return to start of pre-IP data */
                if (iphdr_offset > 0)
                {
                    ASSERT(buf_prepend(&work, iphdr_offset));

                    /* replace Ethertype */
                    if (tunnel_type == DEV_TYPE_TAP)
                    {
                        struct openvpn_ethhdr *eh = (struct openvpn_ethhdr *) BPTR(buf);
                        eh->proto = htons(ROHC_ETHERTYPE);
                    }
                }

                *buf = work;
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
    }
}

void
rohc_decompress(struct buffer *buf, struct buffer work,
                struct rohc_context *rohcctx,
                const struct frame *frame, int tunnel_type)
{
    uint8_t c;

    if (BLEN(buf) <= 0)
    {
        return;
    }

    /* check if the frame is ROHC compressed */
    if (tunnel_type == DEV_TYPE_TAP)
    {
        const struct openvpn_ethhdr *eh = (const struct openvpn_ethhdr *) BPTR(buf);

        if (BLEN(buf) < sizeof(struct openvpn_ethhdr) || ntohs(eh->proto) != ROHC_ETHERTYPE)
        {
            return;
        }
    }


    ASSERT(buf_init(&work, FRAME_HEADROOM(frame)));
    ASSERT(buf_safe(&work, EXPANDED_SIZE(frame)));

    /* copy pre-IP data (i.e. Ethernet header) */
    if (tunnel_type == DEV_TYPE_TAP)
    {
        ASSERT(buf_copy_n(&work, buf, sizeof(struct openvpn_ethhdr)));
        ASSERT(buf_advance(&work, sizeof(struct openvpn_ethhdr)));
    }

    {
        rohc_status_t rohc_status;

        /* prepare buffers for ROHC */
        struct rohc_buf comp_buf = rohc_buf_init_full(BPTR(buf), BLEN(buf), 0);
        struct rohc_buf uncomp_buf = rohc_buf_init_empty(BPTR(&work), BCAP(&work));

        /* compress the packet */
        rohc_status = rohc_decompress3(rohcctx->decompressor, comp_buf, &uncomp_buf, NULL, NULL);
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
                dmsg(D_COMP, "ROHC decompression error: no decompression "
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
    rohcctx->pre_decompress += BLEN(buf);
    rohcctx->post_decompress += BLEN(&work);

    if (tunnel_type == DEV_TYPE_TAP)
    {
        int ip_ver;

        /* extract IP version from IP header */
        ASSERT(BLEN(&work) >= 1);
        ip_ver = OPENVPN_IPH_GET_VER(*BPTR(&work));

        /* return to start of pre-IP data */
        ASSERT(buf_prepend(&work, sizeof(struct openvpn_ethhdr)));

        /* replace Ethertype */
        {
            struct openvpn_ethhdr *eh = (struct openvpn_ethhdr *) BPTR(&work);
            switch (ip_ver)
            {
                case 4:
                    eh->proto = htons(OPENVPN_ETH_P_IPV4);
                    break;
                case 6:
                    eh->proto = htons(OPENVPN_ETH_P_IPV6);
                    break;
            }
        }
    }

    *buf = work;
}

#else  /* if defined(ENABLE_ROHC) */
static void
dummy(void)
{
}
#endif /* ENABLE_ROHC */
