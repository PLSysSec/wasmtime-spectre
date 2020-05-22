#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>


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