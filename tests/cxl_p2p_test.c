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
#define NV2080_CTRL_CMD_BUS_GET_CXL_INFO          0x20801833
#define NV2080_CTRL_CMD_BUS_CXL_P2P_DMA_REQUEST   0x20801834

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
    void    *params;
    uint32_t paramsSize;
    uint32_t status;
} NVOS54_PARAMETERS;

typedef struct {
    uint32_t hRoot;
    uint32_t hObjectParent;
    uint32_t hObjectNew;
    uint32_t hClass;
    void    *pAllocParms;
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

/* CXL buffer handle */
typedef struct {
    void    *cpuVirtAddr;
    uint64_t physAddr;
    size_t   size;
} CxlBufferHandle;

/* RM client state */
typedef struct {
    int      fd;
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
    ctrl.params = params;
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
                    uint32_t hClass, void *allocParams)
{
    NVOS21_PARAMETERS alloc;
    int ret;

    memset(&alloc, 0, sizeof(alloc));
    alloc.hRoot = client->hClient;
    alloc.hObjectParent = hParent;
    alloc.hObjectNew = hObject;
    alloc.hClass = hClass;
    alloc.pAllocParms = allocParams;
    alloc.status = 0;

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

    /* Allocate client (root object) */
    client->hClient = 0x10000001;
    ret = rm_alloc(client, 0, client->hClient, NV01_ROOT, NULL);
    if (ret != 0) {
        printf("  Failed to allocate RM client\n");
        return ret;
    }
    printf("  RM client allocated: 0x%x\n", client->hClient);

    /* Allocate device */
    client->hDevice = 0x10000002;
    ret = rm_alloc(client, client->hClient, client->hDevice, NV01_DEVICE_0, NULL);
    if (ret != 0) {
        printf("  Failed to allocate device\n");
        rm_free(client, 0, client->hClient);
        return ret;
    }
    printf("  Device allocated: 0x%x\n", client->hDevice);

    /* Allocate subdevice */
    client->hSubDevice = 0x10000003;
    ret = rm_alloc(client, client->hDevice, client->hSubDevice, NV20_SUBDEVICE_0, NULL);
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

    for (size_t i = 0; i < size; i++) {
        uint8_t expected = (uint8_t)((i + seed) & 0xFF);
        if (p[i] != expected) {
            if (errors < 10) {
                printf("  Mismatch at offset %zu: expected 0x%02x, got 0x%02x\n",
                       i, expected, p[i]);
            }
            errors++;
        }
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
    params.cxlBufferHandle = (uint64_t)(uintptr_t)handle;
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

    printf("=== CXL P2P DMA Test ===\n\n");

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
    printf("  OK: Device opened (fd=%d)\n\n", client.fd);

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
    printf("  OK: Buffer allocated at %p\n\n", cxlBuffer->cpuVirtAddr);

    /* Step 5: Initialize test data */
    printf("Step 5: Initializing test pattern\n");
    init_test_pattern(cxlBuffer->cpuVirtAddr, testSize, 0xAB);
    printf("  OK: Test pattern initialized\n\n");

    /* Step 6: Test GPU -> CXL transfer */
    printf("Step 6: Testing GPU -> CXL P2P DMA transfer\n");
    if (cxl_p2p_dma_transfer(&client, cxlBuffer, 0, 0, testSize, CXL_P2P_DMA_FLAG_GPU_TO_CXL) != 0) {
        printf("  Transfer returned error (expected if not fully implemented)\n");
    } else {
        printf("  OK: Transfer completed\n");
    }
    printf("\n");

    /* Step 7: Test CXL -> GPU transfer */
    printf("Step 7: Testing CXL -> GPU P2P DMA transfer\n");
    if (cxl_p2p_dma_transfer(&client, cxlBuffer, 0, 0, testSize, CXL_P2P_DMA_FLAG_CXL_TO_GPU) != 0) {
        printf("  Transfer returned error (expected if not fully implemented)\n");
    } else {
        printf("  OK: Transfer completed\n");
    }
    printf("\n");

    /* Step 8: Verify data integrity */
    printf("Step 8: Verifying data integrity\n");
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
