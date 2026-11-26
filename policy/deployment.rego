# SPDX-FileCopyrightText: 2026 boob.yang
package main

import rego.v1

deny contains "deployment visibility must be private" if {
    input.visibility != "private"
}
