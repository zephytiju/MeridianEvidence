# SPDX-License-Identifier: Apache-2.0

from meridian_storage.evidence import __version__


def test_package_version() -> None:
    assert __version__ == "1.0.0"
