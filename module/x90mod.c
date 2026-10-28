#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("X90 SELinux state patch");

/* Pass the runtime selinux_state address as two signed 32-bit halves.  The
 * TV's param_ops_int CRC is known from the vendor modules, so no ulong
 * module-parameter symbol is needed. */
static int addr_lo;
static int addr_hi;
module_param(addr_lo, int, 0);
module_param(addr_hi, int, 0);

static int __init x90_init(void)
{
    unsigned long a;
    volatile unsigned char *p;

    a = ((unsigned long)(unsigned int)addr_hi << 32) |
        (unsigned long)(unsigned int)addr_lo;
    if (!a)
        return 0;
    p = (volatile unsigned char *)a;
    p[0] = 0;   /* selinux_state.disabled: keep labels, only enforce=0 */
    p[1] = 0;   /* selinux_state.enforcing: permissive */
    return 0;
}

static void __exit x90_exit(void)
{
}

module_init(x90_init);
module_exit(x90_exit);
