/*
 *    Space Packet Protocol Packet Layer release 001
 *
 *    This is BETA software, it may break your machine, fail randomly and
 *    maybe have a lot of problems.  It works enough that its going to space.
 *
 *    This module:
 *              This module is free software; you can redistribute it and/or
 *              modify it under the terms of the GNU General Public License
 *              as published by the Free Software Foundation; either version
 *              2 of the License, or (at your option) any later version.
 *
 *      History
 *      SPP 001         Jacob Holtom and Jacob Willis   Wrote the initial implementation
 *
 *      Authors: Jacob Holtom <jacob@holtom.me>
 *               Jacob Willis <willisj2@byu.edu>
 *
 */
#include <linux/mm.h>
#include <linux/sysctl.h>
#include <linux/init.h>
#include <net/spp.h>

static int min_timer[] = {1 * HZ };
static int max_timer[] = {300 * HZ};

static struct ctl_table_header *spp_table_header;

static struct ctl_table spp_table[] = {
    {
        .procname = "idle_timer",
        .data = &sysctl_spp_idle_timer,
        .maxlen = sizeof(int),
        .mode = 0644,
        .proc_handler = proc_dointvec_minmax,
        .extra1 = &min_timer,
        .extra2 = &max_timer,
    },
    { }
};

static struct ctl_path spp_path[] = {
    { .procname = "net", },
    { .procname = "spp", },
    { }
};

void __init spp_register_sysctl(void)
{
    spp_table_header = register_sysctl_paths(spp_path, spp_table);
}
void spp_unregister_sysctl(void)
{
    unregister_sysctl_table(spp_table_header);
}
