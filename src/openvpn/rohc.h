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

#ifndef OPENVPN_ROHC_H
#define OPENVPN_ROHC_H


#ifdef ENABLE_ROHC

/* Configuration for ROHC */
struct rohc_options
{
    unsigned int max_contexts;
};


/* Maximum number of contexts with small CID space */
#define ROHC_MAX_CONTEXTS_SMALL 16

/* Maximum number of contexts with large CID space */
#define ROHC_MAX_CONTEXTS_LARGE 16384


/* Forward declaration of ROHC library structures and functions */
struct rohc_comp;
struct rohc_decomp;
extern char * rohc_version(void);

/* Context for active ROHC session */
struct rohc_context
{
    struct rohc_comp *compressor;
    struct rohc_decomp *decompressor;

    /* statistics */
    counter_type pre_decompress;
    counter_type post_decompress;
    counter_type pre_compress;
    counter_type post_compress;
};

struct rohc_context *rohc_init(const struct rohc_options *opt);
void rohc_uninit(struct rohc_context *rohcctx);

void rohc_compress(struct buffer *buf, struct buffer work,
                   struct rohc_context *rohcctx,
                   const struct frame *frame, int tunnel_type);
void rohc_decompress(struct buffer *buf, struct buffer work,
                     struct rohc_context *rohcctx,
                     const struct frame *frame, int tunnel_type);

void rohc_print_stats(const struct rohc_context *rohcctx, struct status_output *so);

void rohc_generate_peer_info_string(const struct rohc_options *opt, struct buffer *out);

static inline bool
rohc_enabled(const struct rohc_options *info)
{
    return info->max_contexts != 0;
}

#endif /* ENABLE_ROHC */
#endif
