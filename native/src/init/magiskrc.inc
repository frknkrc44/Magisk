#include <magisk.hpp>
#include <selinux.hpp>

#define quote(s) #s
#define str(s) quote(s)

constexpr char MAGISK_RC[] =
"\n"

"on post-fs-data\n"
"    start logd\n"
"    rm " UNBLOCKFILE "\n"
"    exec u:r:" SEPOL_PROC_DOMAIN ":s0 root root -- %1$s/magisk --post-fs-data\n"
"\n"
"    wait " UNBLOCKFILE " " str(POST_FS_DATA_WAIT_TIME) "\n"
"    rm " UNBLOCKFILE "\n"
"\n"

"    exec u:r:" SEPOL_PROC_DOMAIN ":s0 root root -- %1$s/magisk --service\n"
"\n"

"on property:sys.boot_completed=1\n"

"    exec %1$s/magisk --boot-complete\n"
"\n"

"on property:init.svc.zygote=restarting\n"
"    exec %1$s/magisk --zygote-restart\n"
"\n"

"on property:init.svc.zygote=stopped\n"
"    exec %1$s/magisk --zygote-restart\n"
"\n"

"on property:sys.boot_completed=1 && property:sys.oem_unlock_allowed=*\n"
"    exec u:r:" SEPOL_PROC_DOMAIN ":s0 root root -- %1$s/magisk resetprop -n sys.oem_unlock_allowed 0\n"
"\n"

"on property:sys.boot_completed=1 && property:init.svc.adbd=*\n"
"    exec u:r:" SEPOL_PROC_DOMAIN ":s0 root root -- %1$s/magisk resetprop -n init.svc.adbd stopped\n"
"\n"
;
