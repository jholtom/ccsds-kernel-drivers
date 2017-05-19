/* sysctl for SPP - Jacob Holtom */
#include <linux/mm.h>
#include <linux/sysctl.h>
#include <linux/init.h>
#include <net/spp.h>

static int min_window[] = {1}, max_window = {7}; //Based on ROSE protocol, may need to change

static struct ctl_table_header *spp_table_header;

static struct ctl_table spp_table[] = {
    {
        .procname = "window_size",
        .data = &sysctl_spp_window_size,
        .maxlen = sizeof(int),
        .mode = 0644,
        .proc_handler = proc_dointvec_minmax,
        .extra1 = &min_window,
        .extra2 = &max_window
    },
    { }
};

void __init spp_register_sysctl(void)
{
    spp_table_header = register_net_sysctl(&init_net, "net/spp", spp_table);
}
void spp_unregister_sysctl(void)
{
    unregister_net_sysctl_table(spp_table_header);
}
