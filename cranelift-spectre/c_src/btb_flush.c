#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>
#define HFI_EMULATION3
#include "../../../../hw_isol_gem5/tests/test-progs/hfi/hfi.h"


#define COOL_DEVICE_NAME "cool"
#define COOL_DEVICE_PATH "/dev/" COOL_DEVICE_NAME

#define COOL_IOCTL_MAGIC_NUMBER (long)0xc31

#define COOL_IOCTL_CMD_BTBF _IOR(COOL_IOCTL_MAGIC_NUMBER, 1, size_t)

int btbf = -1;

void btb_flush() {
    if(btbf < 0) {
        btbf = open(COOL_DEVICE_PATH, 0);
        if(btbf < 0) {
            printf("Can't find btb flush device.\nPlease insmod cool.ko first.\n");
            abort();
        }
    }
    if(ioctl(btbf, COOL_IOCTL_CMD_BTBF, 0) < 0) {
        printf("Failed to execute ibpb.\n");
        abort();
    }
}

_Thread_local hfi_sandbox hfi_config;

void invoke_hfi_enter_sandbox(){
    memset(&hfi_config, 0, sizeof(hfi_sandbox));

    // we should be filling this with real data but this is a perf experiment only
    hfi_config.is_trusted_sandbox = false;
    hfi_config.data_ranges[0].base_mask = 0;
    hfi_config.data_ranges[0].ignore_mask = 0xffffffffffffffff;
    hfi_config.data_ranges[0].readable = true;
    hfi_config.data_ranges[0].writeable = true;
    hfi_config.code_ranges[0].base_mask = 0;
    hfi_config.code_ranges[0].ignore_mask = 0xffffffffffffffff;
    hfi_set_sandbox_metadata(&hfi_config);
    hfi_enter_sandbox();
}

void invoke_hfi_exit_sandbox(){
    hfi_exit_sandbox();
}