# Copyright: (c) 2021, Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type  # noqa (fixes E402 for the imports below)

import sys


# TODO: Remove once Python 2.7 is dropped, use 'raise Blah() from err' instead.
# Slightly modified from six.reraise to make calling it simpler and more like raise Excp() from err.
if sys.version_info[0] == 3:
    def reraise(exc, inner=None):
        exc.__cause__ = inner[1] if inner else sys.exc_info()[1]
        raise exc

else:
    def _exec(_code_, _globs_=None, _locs_=None):
        """Execute code in a namespace."""
        frame = sys._getframe(1)
        _globs_ = frame.f_globals
        _locs_ = frame.f_locals
        del frame

        exec("""exec _code_ in _globs_, _locs_""")

    _exec("def reraise(exc, inner=None):\n    raise exc, None, inner[2] if inner else sys.exc_info()[2]")
