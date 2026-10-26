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
other header is read.  It is -include rather than -I because BCC's own
kernel header include paths take precedence over user -I flags.
"""

import os

#
# The header sits under bpf/ beside this module's lib/ directory, both in a
# repo checkout and under the install prefix.
#
_base_dir = os.path.dirname(os.path.abspath(__file__)) + "/../"

#
# Clang warns that the kernel's anonymous "struct __filename_head;" member in
# fs.h declares nothing.  The warning is harmless, but any stderr output from
# a probe is logged as an error by the analytics collector.
#
compat_cflags = ["-include",
                 _base_dir + "bpf/compat/linux/ns/ns_common_types.h",
                 "-Wno-missing-declarations"]
