#!/usr/bin/env sh
# SPDX-License-Identifier: AGPL-3.0-or-later

set -eu

/usr/bin/entrypoint-init.sh

exec "$@"
