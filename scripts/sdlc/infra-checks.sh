#!/bin/sh
# SPDX-FileCopyrightText: 2026 boob.yang
set -eu
test -r "$1"
conftest test --policy "${2:-policy}" -- "$1"
