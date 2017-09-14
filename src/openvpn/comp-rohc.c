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

#include "memdbg.h"

#include <rohc/rohc_buf.h>
#include <rohc/rohc_comp.h>
#include <rohc/rohc_decomp.h>


static int
rohc_random_cb(const struct rohc_comp *const comp,
               void *const user_context)
{
    return get_random();
}

static void
rohc_compress_init(struct compress_context *compctx)
{
    rohc_cid_type_t cid_type;
    rohc_cid_t max_cid;

    msg(D_INIT_MEDIUM, "ROHC compression initializing");
    ASSERT(!(compctx->flags & COMP_F_SWAP));

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

    if (!rohc_comp_enable_profiles(compctx->wu.rohc.compressor,
                                   ROHC_PROFILE_UNCOMPRESSED,
                                   ROHC_PROFILE_RTP,
                                   ROHC_PROFILE_UDP,
                                   ROHC_PROFILE_ESP,
                                   ROHC_PROFILE_IP,
                                   ROHC_PROFILE_RTP_LLA,
                                   ROHC_PROFILE_TCP,
                                   ROHC_PROFILE_UDPLITE_RTP,
                                   ROHC_PROFILE_UDPLITE,
                                   -1))
    {
        msg(M_FATAL, "Cannot enable ROHC profiles");
    }


    /* prepare the decompressor */
    compctx->wu.rohc.decompressor = rohc_decomp_new2(cid_type, max_cid, ROHC_U_MODE);
    if (compctx->wu.rohc.decompressor == NULL)
    {
        msg(M_FATAL, "Cannot initialize ROHC decompressor");
    }
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
rohc_compress(struct buffer *buf,
              struct buffer work,
              struct compress_context *compctx,
              const struct frame *frame)
{
    const size_t ps = PAYLOAD_SIZE(frame);
    const size_t ps_max = ps + COMP_EXTRA_BUFFER(ps);

    if (buf->len <= 0)
    {
        return;
    }

    ASSERT(buf_init(&work, FRAME_HEADROOM(frame)));
    ASSERT(buf_safe(&work, ps_max));

    if (buf->len > ps)
    {
        dmsg(D_COMP_ERRORS, "ROHC compression buffer overflow");
        buf->len = 0;
        return;
    }

    {
        rohc_status_t rohc_status;
        bool compressed;

        /* prepare buffers for ROHC */
        struct rohc_buf uncomp_buf = rohc_buf_init_full(BPTR(buf), BLEN(buf), 0);
        struct rohc_buf comp_buf = rohc_buf_init_empty(BPTR(&work), ps_max);

        /* compress the packet */
        rohc_status = rohc_compress4(compctx->wu.rohc.compressor, uncomp_buf, &comp_buf);
        switch (rohc_status)
        {
        case ROHC_STATUS_OK:
            compressed = true;
            break;

        case ROHC_STATUS_SEGMENT:
            dmsg(D_COMP, "Skip multiple segments created by ROHC compression");
            compressed = false;
            break;

        case ROHC_STATUS_OUTPUT_TOO_SMALL:
            dmsg(D_COMP_ERRORS, "ROHC compression error: too large result");
            buf->len = 0;
            return;

        case ROHC_STATUS_ERROR:
        default:
            dmsg(D_COMP_ERRORS, "ROHC compression error");
            buf->len = 0;
            return;
        }

        ASSERT(buf_safe(&work, comp_buf.len));
        work.len = comp_buf.len;

        dmsg(D_COMP, "ROHC compress %d -> %d", buf->len, work.len);
        compctx->pre_compress += buf->len;
        compctx->post_compress += work.len;

        /* store compression status */
        {
            uint8_t *head = BPTR(buf);
            uint8_t *tail = BEND(buf);
            ASSERT(buf_safe(buf, 1));
            ++buf->len;

            /* move head byte of payload to tail */
            *tail = *head;
            *head = (compressed ? ROHC_COMPRESS_BYTE : NO_COMPRESS_BYTE_SWAP);
        }
    }
}

static void
rohc_decompress(struct buffer *buf,
                struct buffer work,
                struct compress_context *compctx,
                const struct frame *frame)
{
    const size_t max_decomp_size = EXPANDED_SIZE(frame);
    uint8_t c;

    if (buf->len <= 0)
    {
        return;
    }

    ASSERT(buf_init(&work, FRAME_HEADROOM(frame)));

    /* do unframing/swap (assumes buf->len > 0) */
    {
        uint8_t *head = BPTR(buf);
        c = *head;
        --buf->len;
        *head = *BEND(buf);
    }

    if (c == ROHC_COMPRESS_BYTE) /* packet was compressed */
    {
        rohc_status_t rohc_status;

        ASSERT(buf_safe(&work, max_decomp_size));

        /* prepare buffers for ROHC */
        struct rohc_buf comp_buf = rohc_buf_init_full(BPTR(buf), BLEN(buf), 0);
        struct rohc_buf uncomp_buf = rohc_buf_init_empty(BPTR(&work), max_decomp_size);

        /* compress the packet */
        rohc_status = rohc_decompress3(compctx->wu.rohc.decompressor,
                                       comp_buf, &uncomp_buf, NULL, NULL);
        switch (rohc_status)
        {
        case ROHC_STATUS_OK:
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
            buf->len = 0;
            return;
        }

        ASSERT(buf_safe(&work, uncomp_buf.len));
        work.len = uncomp_buf.len;

        dmsg(D_COMP, "ROHC decompress %d -> %d", buf->len, work.len);
        compctx->pre_decompress += buf->len;
        compctx->post_decompress += work.len;

        *buf = work;
    }
    else if (c == NO_COMPRESS_BYTE_SWAP) /* packet was not compressed */
    {
    }
    else
    {
        dmsg(D_COMP_ERRORS, "Bad ROHC decompression header byte: %d", (int)c);
        buf->len = 0;
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
