/*
 * SPDX-FileCopyrightText: Copyright (c) 2024 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: MIT
 *
 * CXL P2P DMA Test - Userspace launcher
 *
 * This test demonstrates the CXL P2PDMA flow:
 * 1. CPU registers a CXL buffer
 * 2. GPU initiates P2P DMA request
 * 3. Data is transferred between GPU and CXL memory
 *
 * Build: gcc -o cxl_p2p_test cxl_p2p_test.c
 * Run: ./cxl_p2p_test
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <errno.h>
#include <time.h>

/* NVIDIA RM ioctl definitions */
#define NV_IOCTL_MAGIC      'F'
#define NV_ESC_RM_CONTROL   _IOWR(NV_IOCTL_MAGIC, 0x2a, NVOS54_PARAMETERS)
#define NV_ESC_RM_ALLOC     _IOWR(NV_IOCTL_MAGIC, 0x2b, NVOS21_PARAMETERS)
#define NV_ESC_RM_FREE      _IOWR(NV_IOCTL_MAGIC, 0x29, NVOS00_PARAMETERS)

/* NV status codes */
#define NV_OK                           0x00000000
#define NV_ERR_INVALID_ARGUMENT         0x00000003
#define NV_ERR_NOT_SUPPORTED            0x00000056
#define NV_ERR_OBJECT_NOT_FOUND         0x00000057
#define NV_ERR_INVALID_STATE            0x00000005

/* Control command IDs */
#define NV0000_CTRL_CMD_SYSTEM_GET_P2P_CAPS_V2    0x00000127
#define NV0000_CTRL_CMD_GPU_GET_ATTACHED_IDS      0x00000201
#define NV0000_CTRL_CMD_GPU_GET_PROBED_IDS        0x00000214
#define NV0000_CTRL_CMD_GPU_ATTACH_IDS            0x00000215
#define NV2080_CTRL_CMD_BUS_GET_CXL_INFO          0x20801833
#define NV2080_CTRL_CMD_BUS_CXL_P2P_DMA_REQUEST   0x20801834
#define NV2080_CTRL_CMD_BUS_REGISTER_CXL_BUFFER   0x20801835
#define NV2080_CTRL_CMD_BUS_UNREGISTER_CXL_BUFFER 0x20801836

/* GPU defines */
#define NV0000_CTRL_GPU_MAX_ATTACHED_GPUS         32
#define NV0000_CTRL_GPU_MAX_PROBED_GPUS           32
#define NV0000_CTRL_GPU_ATTACH_ALL_PROBED_IDS     0x0000ffff
#define NV0000_CTRL_GPU_INVALID_ID                0xffffffff

/* Class IDs */
#define NV01_ROOT                       0x00000000
#define NV01_DEVICE_0                   0x00000080
#define NV20_SUBDEVICE_0                0x00002080

/* DMA flags */
#define CXL_P2P_DMA_FLAG_GPU_TO_CXL  0x0
#define CXL_P2P_DMA_FLAG_CXL_TO_GPU  0x1
#define CXL_P2P_DMA_FLAG_ASYNC       0x2

/* Test buffer size */
#define TEST_BUFFER_SIZE (4 * 1024 * 1024)  /* 4 MB */

/* NVOS parameter structures */
typedef struct {
    uint32_t hClient;
    uint32_t hObject;
    uint32_t cmd;
    uint32_t flags;
    uint64_t params;  /* Already 8-byte aligned due to prior 16 bytes */
    uint32_t paramsSize;
    uint32_t status;
} NVOS54_PARAMETERS;

typedef struct {
    uint32_t hRoot;
    uint32_t hObjectParent;
    uint32_t hObjectNew;
    uint32_t hClass;
    uint64_t pAllocParms;
    uint32_t paramsSize;
    uint32_t status;
} NVOS21_PARAMETERS;

typedef struct {
    uint32_t hRoot;
    uint32_t hObjectParent;
    uint32_t hObjectOld;
    uint32_t status;
} NVOS00_PARAMETERS;

/* CXL info structure */
typedef struct {
    uint8_t  bIsLinkUp;
    uint8_t  bMemoryExpander;
    uint32_t nrLinks;
    uint32_t maxNrLinks;
    uint32_t linkMask;
    uint32_t perLinkBwMBps;
    uint32_t cxlVersion;
    uint32_t remoteType;
} NV2080_CTRL_CMD_BUS_GET_CXL_INFO_PARAMS;

/* CXL P2P DMA request structure */
typedef struct {
    uint64_t cxlBufferHandle;
    uint64_t gpuOffset;
    uint64_t cxlOffset;
    uint64_t size;
    uint32_t flags;
    uint32_t transferId;
} NV2080_CTRL_CMD_BUS_CXL_P2P_DMA_REQUEST_PARAMS;

/* CXL register buffer structure */
typedef struct {
    uint64_t baseAddress;
    uint64_t size;
    uint32_t cxlVersion;
    uint64_t bufferHandle;
} NV2080_CTRL_CMD_BUS_REGISTER_CXL_BUFFER_PARAMS;

/* CXL unregister buffer structure */
typedef struct {
    uint64_t bufferHandle;
} NV2080_CTRL_CMD_BUS_UNREGISTER_CXL_BUFFER_PARAMS;

/* CXL buffer handle */
typedef struct {
    void    *cpuVirtAddr;
    uint64_t physAddr;
    size_t   size;
    uint64_t kernelHandle;  /* Handle returned by kernel registration */
} CxlBufferHandle;

/* Device allocation parameters */
typedef struct {
    uint32_t deviceId;
    uint32_t hClientShare;
    uint32_t hTargetClient;
    uint32_t hTargetDevice;
    uint32_t flags;
    uint64_t vaSpaceSize __attribute__((aligned(8)));
    uint64_t vaStartInternal __attribute__((aligned(8)));
    uint64_t vaLimitInternal __attribute__((aligned(8)));
    uint32_t vaMode;
} NV0080_ALLOC_PARAMETERS;

/* Subdevice allocation parameters */
typedef struct {
    uint32_t subDeviceId;
} NV2080_ALLOC_PARAMETERS;

/* GPU attach parameters */
typedef struct {
    uint32_t gpuIds[NV0000_CTRL_GPU_MAX_PROBED_GPUS];
    uint32_t failedId;
} NV0000_CTRL_GPU_ATTACH_IDS_PARAMS;

/* GPU get attached IDs parameters */
typedef struct {
    uint32_t gpuIds[NV0000_CTRL_GPU_MAX_ATTACHED_GPUS];
} NV0000_CTRL_GPU_GET_ATTACHED_IDS_PARAMS;

/* GPU get probed IDs parameters */
typedef struct {
    uint32_t gpuIds[NV0000_CTRL_GPU_MAX_PROBED_GPUS];
    uint32_t excludedGpuIds[NV0000_CTRL_GPU_MAX_PROBED_GPUS];
} NV0000_CTRL_GPU_GET_PROBED_IDS_PARAMS;

/* RM client state */
typedef struct {
    int      fd;          /* Control device fd (/dev/nvidiactl) */
    int      gpu_fd;      /* GPU device fd (/dev/nvidia0) */
    uint32_t hClient;
    uint32_t hDevice;
    uint32_t hSubDevice;
} RmClient;

/*
 * Perform RM control call via ioctl
 */
static int rm_control(RmClient *client, uint32_t hObject, uint32_t cmd,
                      void *params, uint32_t paramsSize)
{
    NVOS54_PARAMETERS ctrl;
    int ret;

    memset(&ctrl, 0, sizeof(ctrl));
    ctrl.hClient = client->hClient;
    ctrl.hObject = hObject;
    ctrl.cmd = cmd;
    ctrl.flags = 0;
    ctrl.params = (uint64_t)(uintptr_t)params;
    ctrl.paramsSize = paramsSize;
    ctrl.status = 0;

    ret = ioctl(client->fd, NV_ESC_RM_CONTROL, &ctrl);
    if (ret < 0) {
        printf("  ioctl failed: %s (errno=%d)\n", strerror(errno), errno);
        return -1;
    }

    if (ctrl.status != NV_OK) {
        printf("  RM control failed: status=0x%x\n", ctrl.status);
        return ctrl.status;
    }

    return 0;
}

/*
 * Allocate RM object
 */
static int rm_alloc(RmClient *client, uint32_t hParent, uint32_t hObject,
                    uint32_t hClass, void *allocParams, uint32_t paramsSize)
{
    NVOS21_PARAMETERS alloc;
    int ret;

    memset(&alloc, 0, sizeof(alloc));
    /* For root client allocation, hRoot should be the new handle we're allocating */
    if (hClass == NV01_ROOT) {
        alloc.hRoot = hObject;  /* Client handle we're allocating */
        alloc.hObjectParent = hObject;  /* For root, parent is itself */
        alloc.hObjectNew = hObject;  /* Object being allocated */
    } else {
        alloc.hRoot = client->hClient;
        alloc.hObjectParent = hParent;
        alloc.hObjectNew = hObject;
    }
    alloc.hClass = hClass;
    alloc.pAllocParms = (uint64_t)(uintptr_t)allocParams;
    alloc.paramsSize = paramsSize;
    alloc.status = 0;

    printf("  rm_alloc: hRoot=0x%x hParent=0x%x hObject=0x%x hClass=0x%x paramsSize=%u\n",
           alloc.hRoot, alloc.hObjectParent, alloc.hObjectNew, alloc.hClass, alloc.paramsSize);

    ret = ioctl(client->fd, NV_ESC_RM_ALLOC, &alloc);
    if (ret < 0) {
        printf("  ioctl alloc failed: %s (errno=%d)\n", strerror(errno), errno);
        return -1;
    }

    if (alloc.status != NV_OK) {
        printf("  RM alloc failed: status=0x%x\n", alloc.status);
        return alloc.status;
    }

    return 0;
}

/*
 * Free RM object
 */
static int rm_free(RmClient *client, uint32_t hParent, uint32_t hObject)
{
    NVOS00_PARAMETERS free_params;
    int ret;

    memset(&free_params, 0, sizeof(free_params));
    free_params.hRoot = client->hClient;
    free_params.hObjectParent = hParent;
    free_params.hObjectOld = hObject;
    free_params.status = 0;

    ret = ioctl(client->fd, NV_ESC_RM_FREE, &free_params);
    if (ret < 0) {
        return -1;
    }

    return free_params.status;
}

/*
 * Initialize RM client - allocate client, device, and subdevice
 */
static int rm_init(RmClient *client)
{
    int ret;
    NV0080_ALLOC_PARAMETERS deviceParams;
    NV2080_ALLOC_PARAMETERS subdevParams;
    NV0000_CTRL_GPU_GET_PROBED_IDS_PARAMS probedParams;
    NV0000_CTRL_GPU_ATTACH_IDS_PARAMS attachParams;
    uint32_t gpuId = 0;
    int foundGpu = 0;

    /* Allocate client (root object) */
    client->hClient = 0xcaf10001;  /* Use RM-style handle */
    ret = rm_alloc(client, 0, client->hClient, NV01_ROOT, NULL, 0);
    if (ret != 0) {
        printf("  Failed to allocate RM client\n");
        return ret;
    }
    printf("  RM client allocated: 0x%x\n", client->hClient);

    /* Get probed GPU IDs */
    memset(&probedParams, 0, sizeof(probedParams));
    ret = rm_control(client, client->hClient, NV0000_CTRL_CMD_GPU_GET_PROBED_IDS,
                     &probedParams, sizeof(probedParams));
    if (ret != 0) {
        printf("  Failed to get probed GPU IDs\n");
        rm_free(client, 0, client->hClient);
        return ret;
    }

    /* Find first valid GPU ID */
    printf("  Probed GPU IDs: ");
    for (int i = 0; i < 4; i++) {
        printf("0x%x ", probedParams.gpuIds[i]);
    }
    printf("...\n");

    for (int i = 0; i < NV0000_CTRL_GPU_MAX_PROBED_GPUS; i++) {
        if (probedParams.gpuIds[i] != NV0000_CTRL_GPU_INVALID_ID) {
            gpuId = probedParams.gpuIds[i];
            printf("  Found probed GPU ID: 0x%x (index %d)\n", gpuId, i);
            foundGpu = 1;
            break;
        }
    }

    if (!foundGpu) {
        printf("  No probed GPUs found\n");
        rm_free(client, 0, client->hClient);
        return -1;
    }

    /* Attach the GPU - use ATTACH_ALL_PROBED_IDS to ensure GPU groups are created */
    memset(&attachParams, 0, sizeof(attachParams));
    attachParams.gpuIds[0] = NV0000_CTRL_GPU_ATTACH_ALL_PROBED_IDS;
    ret = rm_control(client, client->hClient, NV0000_CTRL_CMD_GPU_ATTACH_IDS,
                     &attachParams, sizeof(attachParams));
    if (ret != 0) {
        printf("  Warning: Failed to attach GPUs (status=0x%x), continuing anyway\n", ret);
        /* Continue - GPU might already be attached */
    } else {
        printf("  GPUs attached successfully\n");
    }

    /* Open GPU device file - required for device allocation permission check */
    client->gpu_fd = open("/dev/nvidia0", O_RDWR);
    if (client->gpu_fd < 0) {
        printf("  Warning: Failed to open /dev/nvidia0: %s\n", strerror(errno));
        printf("  Device allocation may fail without GPU device file access\n");
        /* Continue anyway - might work on some systems */
    } else {
        printf("  GPU device file opened (fd=%d)\n", client->gpu_fd);
    }

    /* Allocate device with proper parameters */
    client->hDevice = 0xcaf10002;
    memset(&deviceParams, 0, sizeof(deviceParams));
    deviceParams.deviceId = 0;  /* Device instance 0 (first attached GPU) */
    printf("  Device params size: %zu bytes, deviceId=%u\n", sizeof(deviceParams), deviceParams.deviceId);
    ret = rm_alloc(client, client->hClient, client->hDevice, NV01_DEVICE_0,
                   &deviceParams, sizeof(deviceParams));
    if (ret != 0) {
        printf("  Failed to allocate device\n");
        rm_free(client, 0, client->hClient);
        return ret;
    }
    printf("  Device allocated: 0x%x\n", client->hDevice);

    /* Allocate subdevice with proper parameters */
    client->hSubDevice = 0xcaf10003;
    memset(&subdevParams, 0, sizeof(subdevParams));
    subdevParams.subDeviceId = 0;  /* First subdevice */
    ret = rm_alloc(client, client->hDevice, client->hSubDevice, NV20_SUBDEVICE_0,
                   &subdevParams, sizeof(subdevParams));
    if (ret != 0) {
        printf("  Failed to allocate subdevice\n");
        rm_free(client, client->hClient, client->hDevice);
        rm_free(client, 0, client->hClient);
        return ret;
    }
    printf("  Subdevice allocated: 0x%x\n", client->hSubDevice);

    return 0;
}

/*
 * Cleanup RM client
 */
static void rm_cleanup(RmClient *client)
{
    if (client->hSubDevice) {
        rm_free(client, client->hDevice, client->hSubDevice);
    }
    if (client->hDevice) {
        rm_free(client, client->hClient, client->hDevice);
    }
    if (client->hClient) {
        rm_free(client, 0, client->hClient);
    }
    if (client->gpu_fd >= 0) {
        close(client->gpu_fd);
        client->gpu_fd = -1;
    }
}

/*
 * Allocate CXL buffer
 */
static CxlBufferHandle *allocate_cxl_buffer(size_t size)
{
    CxlBufferHandle *handle = malloc(sizeof(CxlBufferHandle));
    if (!handle) {
        perror("malloc");
        return NULL;
    }

    /* Try huge pages first */
    handle->cpuVirtAddr = mmap(NULL, size,
                               PROT_READ | PROT_WRITE,
                               MAP_PRIVATE | MAP_ANONYMOUS | MAP_HUGETLB,
                               -1, 0);

    if (handle->cpuVirtAddr == MAP_FAILED) {
        handle->cpuVirtAddr = mmap(NULL, size,
                                   PROT_READ | PROT_WRITE,
                                   MAP_PRIVATE | MAP_ANONYMOUS,
                                   -1, 0);
        if (handle->cpuVirtAddr == MAP_FAILED) {
            perror("mmap");
            free(handle);
            return NULL;
        }
        printf("  Using regular pages\n");
    } else {
        printf("  Using huge pages\n");
    }

    if (mlock(handle->cpuVirtAddr, size) != 0) {
        perror("mlock");
    }

    handle->size = size;
    handle->physAddr = (uint64_t)(uintptr_t)handle->cpuVirtAddr;
    handle->kernelHandle = 0;

    return handle;
}

/*
 * Free CXL buffer
 */
static void free_cxl_buffer(CxlBufferHandle *handle)
{
    if (handle) {
        if (handle->cpuVirtAddr && handle->cpuVirtAddr != MAP_FAILED) {
            munlock(handle->cpuVirtAddr, handle->size);
            munmap(handle->cpuVirtAddr, handle->size);
        }
        free(handle);
    }
}

/*
 * Initialize test pattern
 */
static void init_test_pattern(void *buffer, size_t size, uint8_t seed)
{
    uint8_t *p = (uint8_t *)buffer;
    for (size_t i = 0; i < size; i++) {
        p[i] = (uint8_t)((i + seed) & 0xFF);
    }
}

/*
 * Verify test pattern
 */
static int verify_test_pattern(void *buffer, size_t size, uint8_t seed)
{
    uint8_t *p = (uint8_t *)buffer;
    int errors = 0;
    size_t first_error = (size_t)-1;
    size_t last_error = 0;
    int zero_count = 0;

    for (size_t i = 0; i < size; i++) {
        uint8_t expected = (uint8_t)((i + seed) & 0xFF);
        if (p[i] != expected) {
            if (errors < 10) {
                printf("  Mismatch at offset %zu: expected 0x%02x, got 0x%02x\n",
                       i, expected, p[i]);
            }
            if (first_error == (size_t)-1)
                first_error = i;
            last_error = i;
            if (p[i] == 0)
                zero_count++;
            errors++;
        }
    }

    if (errors > 0) {
        printf("  Error range: offset %zu - %zu\n", first_error, last_error);
        printf("  Bytes that are zero: %d / %d errors\n", zero_count, errors);
        printf("  Error span: %zu bytes (%.2f pages)\n",
               last_error - first_error + 1, (last_error - first_error + 1) / 4096.0);
    }

    return errors;
}

/*
 * Query CXL info via RM control
 */
static int query_cxl_info(RmClient *client, NV2080_CTRL_CMD_BUS_GET_CXL_INFO_PARAMS *info)
{
    int ret;

    printf("  Calling NV2080_CTRL_CMD_BUS_GET_CXL_INFO (0x%x)\n", NV2080_CTRL_CMD_BUS_GET_CXL_INFO);

    memset(info, 0, sizeof(*info));

    ret = rm_control(client, client->hSubDevice, NV2080_CTRL_CMD_BUS_GET_CXL_INFO,
                     info, sizeof(*info));

    return ret;
}

/*
 * Register CXL buffer with kernel
 */
static int register_cxl_buffer(RmClient *client, CxlBufferHandle *handle, uint32_t cxlVersion)
{
    NV2080_CTRL_CMD_BUS_REGISTER_CXL_BUFFER_PARAMS params;
    int ret;

    printf("  Calling NV2080_CTRL_CMD_BUS_REGISTER_CXL_BUFFER (0x%x)\n",
           NV2080_CTRL_CMD_BUS_REGISTER_CXL_BUFFER);

    memset(&params, 0, sizeof(params));
    params.baseAddress = (uint64_t)(uintptr_t)handle->cpuVirtAddr;
    params.size = handle->size;
    params.cxlVersion = cxlVersion;
    params.bufferHandle = 0;

    printf("    baseAddress: 0x%lx\n", params.baseAddress);
    printf("    size: %lu bytes\n", params.size);
    printf("    cxlVersion: %u\n", params.cxlVersion);

    ret = rm_control(client, client->hSubDevice, NV2080_CTRL_CMD_BUS_REGISTER_CXL_BUFFER,
                     &params, sizeof(params));

    if (ret == 0) {
        handle->kernelHandle = params.bufferHandle;
        printf("    bufferHandle: 0x%lx\n", handle->kernelHandle);
    }

    return ret;
}

/*
 * Unregister CXL buffer from RM
 */
static int unregister_cxl_buffer(RmClient *client, CxlBufferHandle *handle)
{
    NV2080_CTRL_CMD_BUS_UNREGISTER_CXL_BUFFER_PARAMS params;
    int ret;

    if (handle->kernelHandle == 0) {
        return 0;  /* Nothing to unregister */
    }

    printf("  Calling NV2080_CTRL_CMD_BUS_UNREGISTER_CXL_BUFFER (0x%x)\n",
           NV2080_CTRL_CMD_BUS_UNREGISTER_CXL_BUFFER);

    memset(&params, 0, sizeof(params));
    params.bufferHandle = handle->kernelHandle;

    printf("    bufferHandle: 0x%lx\n", params.bufferHandle);

    ret = rm_control(client, client->hSubDevice, NV2080_CTRL_CMD_BUS_UNREGISTER_CXL_BUFFER,
                     &params, sizeof(params));

    if (ret == 0) {
        handle->kernelHandle = 0;
        printf("  OK: Buffer unregistered\n");
    }

    return ret;
}

/*
 * Initiate CXL P2P DMA transfer via RM control
 */
static int cxl_p2p_dma_transfer(RmClient *client, CxlBufferHandle *handle,
                                uint64_t gpuOffset, uint64_t cxlOffset,
                                uint64_t size, uint32_t flags)
{
    NV2080_CTRL_CMD_BUS_CXL_P2P_DMA_REQUEST_PARAMS params;
    int ret;

    printf("  Calling NV2080_CTRL_CMD_BUS_CXL_P2P_DMA_REQUEST (0x%x)\n",
           NV2080_CTRL_CMD_BUS_CXL_P2P_DMA_REQUEST);

    memset(&params, 0, sizeof(params));
    /* Use the kernel handle returned by register_cxl_buffer */
    params.cxlBufferHandle = handle->kernelHandle;
    params.gpuOffset = gpuOffset;
    params.cxlOffset = cxlOffset;
    params.size = size;
    params.flags = flags;
    params.transferId = 0;

    printf("    cxlBufferHandle: 0x%lx\n", params.cxlBufferHandle);
    printf("    gpuOffset: 0x%lx\n", params.gpuOffset);
    printf("    cxlOffset: 0x%lx\n", params.cxlOffset);
    printf("    size: %lu bytes\n", params.size);
    printf("    flags: 0x%x (%s)\n", params.flags,
           (flags & CXL_P2P_DMA_FLAG_CXL_TO_GPU) ? "CXL->GPU" : "GPU->CXL");

    ret = rm_control(client, client->hSubDevice, NV2080_CTRL_CMD_BUS_CXL_P2P_DMA_REQUEST,
                     &params, sizeof(params));

    if (ret == 0) {
        printf("    transferId: %u\n", params.transferId);
    }

    return ret;
}

/*
 * Main test function
 */
int main(int argc, char *argv[])
{
    RmClient client;
    CxlBufferHandle *cxlBuffer = NULL;
    NV2080_CTRL_CMD_BUS_GET_CXL_INFO_PARAMS cxlInfo;
    int result = 0;
    size_t testSize = TEST_BUFFER_SIZE;

    memset(&client, 0, sizeof(client));
    client.gpu_fd = -1;  /* Initialize to invalid fd */

    printf("=== CXL P2P DMA Test ===\n\n");

    /* Print structure sizes for debugging */
    printf("Structure sizes:\n");
    printf("  NVOS21_PARAMETERS: %zu bytes\n", sizeof(NVOS21_PARAMETERS));
    printf("  NVOS54_PARAMETERS: %zu bytes\n", sizeof(NVOS54_PARAMETERS));
    printf("  NV0080_ALLOC_PARAMETERS: %zu bytes\n", sizeof(NV0080_ALLOC_PARAMETERS));
    printf("  NV2080_ALLOC_PARAMETERS: %zu bytes\n\n", sizeof(NV2080_ALLOC_PARAMETERS));

    /* Parse command line */
    if (argc > 1) {
        testSize = atol(argv[1]);
        if (testSize == 0 || testSize > 1024 * 1024 * 1024) {
            printf("Invalid buffer size. Using default: %zu\n", (size_t)TEST_BUFFER_SIZE);
            testSize = TEST_BUFFER_SIZE;
        }
    }

    printf("Test buffer size: %zu bytes (%.2f MB)\n\n", testSize, testSize / (1024.0 * 1024.0));

    /* Step 1: Open NVIDIA device */
    printf("Step 1: Opening NVIDIA control device\n");
    client.fd = open("/dev/nvidiactl", O_RDWR);
    if (client.fd < 0) {
        perror("  open /dev/nvidiactl");
        printf("  Make sure NVIDIA driver is loaded and you have permissions\n");
        return 1;
    }
    printf("  OK: Control device opened (fd=%d)\n\n", client.fd);

    /* Step 2: Initialize RM client */
    printf("Step 2: Initializing RM client\n");
    if (rm_init(&client) != 0) {
        printf("  FAILED: Cannot initialize RM client\n");
        result = 1;
        goto cleanup;
    }
    printf("  OK: RM client initialized\n\n");

    /* Step 3: Query CXL info */
    printf("Step 3: Querying CXL capabilities\n");
    if (query_cxl_info(&client, &cxlInfo) != 0) {
        printf("  Note: CXL info query failed (expected if not implemented)\n");
        /* Continue anyway for testing */
    } else {
        printf("  CXL Version: %u\n", cxlInfo.cxlVersion);
        printf("  Link Up: %s\n", cxlInfo.bIsLinkUp ? "Yes" : "No");
        printf("  Memory Expander: %s\n", cxlInfo.bMemoryExpander ? "Yes" : "No");
        printf("  Max Links: %u\n", cxlInfo.maxNrLinks);
    }
    printf("\n");

    /* Step 4: Allocate CXL buffer */
    printf("Step 4: Allocating CXL buffer (CPU side)\n");
    cxlBuffer = allocate_cxl_buffer(testSize);
    if (!cxlBuffer) {
        printf("  FAILED: Cannot allocate CXL buffer\n");
        result = 1;
        goto cleanup;
    }
    printf("  OK: Buffer allocated at %p\n", cxlBuffer->cpuVirtAddr);
    printf("  DEBUG: CxlBufferHandle struct at %p (size=%zu)\n", (void *)cxlBuffer, sizeof(*cxlBuffer));
    printf("  DEBUG: Data buffer range: %p - %p\n",
           cxlBuffer->cpuVirtAddr, (char *)cxlBuffer->cpuVirtAddr + testSize);
    printf("\n");

    /* Step 5: Initialize test data */
    printf("Step 5: Initializing test pattern\n");
    init_test_pattern(cxlBuffer->cpuVirtAddr, testSize, 0xAB);
    printf("  OK: Test pattern initialized\n");

    /* Verify pattern before DMA */
    printf("  Verifying pattern before DMA:\n");
    int pre_errors = verify_test_pattern(cxlBuffer->cpuVirtAddr, testSize, 0xAB);
    if (pre_errors > 0) {
        printf("  WARNING: %d errors in pattern before DMA!\n", pre_errors);
    } else {
        printf("  Pattern correct before DMA\n");
    }
    printf("\n");

    /* Step 6: Register CXL buffer with kernel */
    printf("Step 6: Registering CXL buffer with kernel\n");
    if (register_cxl_buffer(&client, cxlBuffer, cxlInfo.cxlVersion) != 0) {
        printf("  FAILED: Cannot register CXL buffer\n");
        result = 1;
        goto cleanup;
    }
    printf("  OK: Buffer registered with kernel\n\n");

    /* Step 7: Test GPU -> CXL transfer */
    printf("Step 7: Testing GPU -> CXL P2P DMA transfer\n");
    printf("  DEBUG before Step 7: cpuVirtAddr=%p, kernelHandle=0x%lx\n",
           cxlBuffer->cpuVirtAddr, cxlBuffer->kernelHandle);
    if (cxl_p2p_dma_transfer(&client, cxlBuffer, 0, 0, testSize, CXL_P2P_DMA_FLAG_GPU_TO_CXL) != 0) {
        printf("  Transfer returned error (expected if not fully implemented)\n");
    } else {
        printf("  OK: Transfer completed\n");
    }
    printf("  DEBUG after Step 7: cpuVirtAddr=%p, kernelHandle=0x%lx\n",
           cxlBuffer->cpuVirtAddr, cxlBuffer->kernelHandle);

    /* Check data after first transfer */
    printf("  Checking data after GPU->CXL transfer:\n");
    int after7_errors = verify_test_pattern(cxlBuffer->cpuVirtAddr, testSize, 0xAB);
    if (after7_errors > 0) {
        printf("  WARNING: %d errors after Step 7\n", after7_errors);
    } else {
        printf("  Data intact after Step 7\n");
    }
    printf("\n");

    /* Step 8: Test CXL -> GPU transfer */
    printf("Step 8: Testing CXL -> GPU P2P DMA transfer\n");
    printf("  DEBUG before Step 8: cpuVirtAddr=%p, kernelHandle=0x%lx\n",
           cxlBuffer->cpuVirtAddr, cxlBuffer->kernelHandle);
    if (cxl_p2p_dma_transfer(&client, cxlBuffer, 0, 0, testSize, CXL_P2P_DMA_FLAG_CXL_TO_GPU) != 0) {
        printf("  Transfer returned error (expected if not fully implemented)\n");
    } else {
        printf("  OK: Transfer completed\n");
    }
    printf("  DEBUG after Step 8: cpuVirtAddr=%p, kernelHandle=0x%lx\n",
           cxlBuffer->cpuVirtAddr, cxlBuffer->kernelHandle);

    /* Check data after second transfer */
    printf("  Checking data after CXL->GPU transfer:\n");
    int after8_errors = verify_test_pattern(cxlBuffer->cpuVirtAddr, testSize, 0xAB);
    if (after8_errors > 0) {
        printf("  WARNING: %d errors after Step 8\n", after8_errors);
    } else {
        printf("  Data intact after Step 8\n");
    }
    printf("\n");

    /* Step 9: Verify data integrity */
    printf("Step 9: Verifying data integrity\n");
    printf("  DEBUG before verify: cpuVirtAddr=%p\n", cxlBuffer->cpuVirtAddr);
    if (cxlBuffer->cpuVirtAddr == NULL) {
        printf("  ERROR: cpuVirtAddr is NULL! Memory corruption detected.\n");
        result = 1;
        goto cleanup;
    }

    /* Hex dump first 256 bytes to see actual content */
    printf("  First 256 bytes of buffer:\n");
    for (int row = 0; row < 16; row++) {
        printf("    %04x: ", row * 16);
        uint8_t *p = (uint8_t *)cxlBuffer->cpuVirtAddr + row * 16;
        for (int col = 0; col < 16; col++) {
            printf("%02x ", p[col]);
        }
        printf("\n");
    }
    printf("\n");

    /* Check a few specific locations to find error pattern */
    printf("  Scanning for first 20 errors to find pattern:\n");
    int found = 0;
    for (size_t i = 0; i < testSize && found < 20; i++) {
        uint8_t *p = (uint8_t *)cxlBuffer->cpuVirtAddr;
        uint8_t expected = (uint8_t)((i + 0xAB) & 0xFF);
        if (p[i] != expected) {
            printf("    Error at offset 0x%06zx (%zu): expected 0x%02x, got 0x%02x\n",
                   i, i, expected, p[i]);
            found++;
        }
    }

    int errors = verify_test_pattern(cxlBuffer->cpuVirtAddr, testSize, 0xAB);
    if (errors > 0) {
        printf("  %d errors found in data\n", errors);
    } else {
        printf("  OK: Data integrity verified\n");
    }
    printf("\n");

cleanup:
    printf("Cleanup:\n");

    if (cxlBuffer) {
        /* Unregister before freeing */
        if (cxlBuffer->kernelHandle != 0) {
            unregister_cxl_buffer(&client, cxlBuffer);
        }
        free_cxl_buffer(cxlBuffer);
        printf("  Buffer freed\n");
    }

    rm_cleanup(&client);
    printf("  RM objects freed\n");

    if (client.fd >= 0) {
        close(client.fd);
        printf("  Device closed\n");
    }

    printf("\n=== Test %s ===\n", result == 0 ? "COMPLETED" : "FAILED");

    return result;
}
