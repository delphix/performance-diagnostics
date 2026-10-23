#
# Copyright 2026 Delphix. All rights reserved.
#
# SPDX-License-Identifier: GPL-2.0-or-later
#

""" BCC compatibility cflags
The cflags every stbtrace probe needs so that BCC/Clang can compile the
kernel headers it pulls in.  Defined here, rather than in each template,
so that there is one place to update when the next kernel change needs a
workaround.

bpf/compat/linux/ns/ns_common_types.h must be force-included ahead of
every other cflag, so that its include guards take effect before any
other header is read.  It is -include rather than -I because BCC
overrides -I paths with its own internal linux-aws headers path.
"""

import os

#
# The header sits under bpf/ beside this module's lib/ directory, both in a
# repo checkout and under the install prefix.
#
_base_dir = os.path.dirname(os.path.abspath(__file__)) + "/../"

compat_cflags = ["-include",
                 _base_dir + "bpf/compat/linux/ns/ns_common_types.h"]
