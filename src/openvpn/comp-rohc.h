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

#ifndef OPENVPN_COMP_ROHC_H
#define OPENVPN_COMP_ROHC_H

#if defined(ENABLE_ROHC)

#include "buffer.h"

/* ROHC specific compression flags */
#define COMP_F_ROHC_MANY_STREAMS (1<<4) /* handle more than 15 streams */

extern const struct compress_alg rohc_alg;

struct rohc_workspace
{
    struct rohc_comp *compressor;
    struct rohc_decomp *decompressor;
};

#endif /* ENABLE_ROHC */
#endif
