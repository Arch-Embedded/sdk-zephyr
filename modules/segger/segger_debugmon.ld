/*
 * Copyright (c) 2026 Arch-Embedded B.V.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

/* Let Let DebugMon_Handler() be called in place of z_arm_debug_monitor() by default. */
PROVIDE(z_arm_debug_monitor = DebugMon_Handler);