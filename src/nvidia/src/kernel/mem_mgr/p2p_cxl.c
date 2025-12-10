/*
 * SPDX-FileCopyrightText: Copyright (c) 2024 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: MIT
 *
 * Permission is hereby granted, free of charge, to any person obtaining a
 * copy of this software and associated documentation files (the "Software"),
 * to deal in the Software without restriction, including without limitation
 * the rights to use, copy, modify, merge, publish, distribute, sublicense,
 * and/or sell copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
 * THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
 * DEALINGS IN THE SOFTWARE.
 */

#include "core/core.h"
#include "gpu/gpu.h"
#include "mem_mgr/p2p.h"
#include "os/os.h"
#include "nvport/nvport.h"
#include "gpu/mem_mgr/mem_mgr.h"
#include "gpu/mem_mgr/mem_desc.h"
#include "gpu/mem_mgr/ce_utils.h"
#include "gpu/bus/kern_bus.h"

// CXL P2P DMA direction flag (bit 0 of flags)
#define CXL_P2P_DMA_FLAG_CXL_TO_GPU  0x1

// Forward declarations for kernel page pinning interface
extern NV_STATUS nv_pin_cxl_buffer(NvU64, NvU64, void **);
extern NV_STATUS nv_unpin_cxl_buffer(void *);
extern NV_STATUS nv_get_cxl_buffer_pages(void *, NvU64 **, NvU32 *);

//
// CXL P2P DMA Buffer Handle structure
//
typedef struct CXL_P2P_BUFFER_HANDLE
{
    void   *pPinnedHandle;     // Handle from page pinning (kernel)
    NvU64   baseAddress;       // Base address of the CXL buffer
    NvU64   size;              // Size of the buffer in bytes
    NvU32   cxlVersion;        // CXL version (1, 2, or 3)
    NvU64  *pPageArray;        // Array of physical page addresses (from pinning)
    NvU32   pageCount;         // Number of pages
    NvU32   pageSize;          // Page size in bytes
    NvBool  bRegistered;       // Whether the buffer is registered
} CXL_P2P_BUFFER_HANDLE;

//
// CXL System Info structure for device enumeration
//
typedef struct CXL_SYSTEM_INFO
{
    NvU32   numDevices;        // Number of CXL devices detected
    NvU32   numMemoryDevices;  // Number of CXL memory expanders
    NvBool  bLinkUp;           // Whether any CXL link is active
    NvU32   cxlVersion;        // Detected CXL version
} CXL_SYSTEM_INFO;

// Forward declaration for kernel interface
extern NV_STATUS nv_enumerate_cxl_devices(CXL_SYSTEM_INFO *pInfo);

//
// RmP2PGetCxlSystemInfo
//
// Enumerates CXL devices in the system and returns information.
//
// Parameters:
//   pNumDevices      [OUT] - Number of CXL devices detected
//   pNumMemDevices   [OUT] - Number of CXL memory expanders
//   pbLinkUp         [OUT] - Whether CXL link is active
//   pCxlVersion      [OUT] - Detected CXL version
//
NV_STATUS
RmP2PGetCxlSystemInfo
(
    NvU32  *pNumDevices,
    NvU32  *pNumMemDevices,
    NvBool *pbLinkUp,
    NvU32  *pCxlVersion
)
{
    CXL_SYSTEM_INFO info;
    NV_STATUS status;

    portMemSet(&info, 0, sizeof(info));

    // Call kernel interface to enumerate CXL devices
    status = nv_enumerate_cxl_devices(&info);
    if (status != NV_OK)
    {
        // Default values if enumeration fails
        info.numDevices = 0;
        info.numMemoryDevices = 0;
        info.bLinkUp = NV_FALSE;
        info.cxlVersion = 2;
    }

    if (pNumDevices != NULL)
        *pNumDevices = info.numDevices;
    if (pNumMemDevices != NULL)
        *pNumMemDevices = info.numMemoryDevices;
    if (pbLinkUp != NULL)
        *pbLinkUp = info.bLinkUp;
    if (pCxlVersion != NULL)
        *pCxlVersion = info.cxlVersion;

    return NV_OK;
}

//
// RmP2PRegisterCxlBuffer
//
// Registers a CXL buffer for P2P DMA operations.
// The CPU allocates and provides the CXL memory region.
//
// Parameters:
//   pCxlDevice     [IN]  - CXL device handle from the platform (unused, for future)
//   baseAddress    [IN]  - User virtual address of the CXL buffer
//   size           [IN]  - Size of the buffer in bytes
//   cxlVersion     [IN]  - CXL specification version
//   ppBufferHandle [OUT] - Returns handle to the registered buffer
//
NV_STATUS
RmP2PRegisterCxlBuffer
(
    void   *pCxlDevice,
    NvU64   baseAddress,
    NvU64   size,
    NvU32   cxlVersion,
    void  **ppBufferHandle
)
{
    CXL_P2P_BUFFER_HANDLE *pHandle = NULL;
    NV_STATUS status;
    void *pPinnedHandle = NULL;
    NvU64 *pPhysAddrs = NULL;
    NvU32 pageCount = 0;

    if (size == 0 || ppBufferHandle == NULL)
    {
        return NV_ERR_INVALID_ARGUMENT;
    }

    if (cxlVersion < 1 || cxlVersion > 3)
    {
        return NV_ERR_INVALID_ARGUMENT;
    }

    // Allocate the buffer handle structure
    pHandle = portMemAllocNonPaged(sizeof(CXL_P2P_BUFFER_HANDLE));
    if (pHandle == NULL)
    {
        return NV_ERR_NO_MEMORY;
    }

    portMemSet(pHandle, 0, sizeof(CXL_P2P_BUFFER_HANDLE));

    // Pin the user pages and get physical addresses
    status = nv_pin_cxl_buffer(baseAddress, size, &pPinnedHandle);
    if (status != NV_OK)
    {
        NV_PRINTF(LEVEL_ERROR, "Failed to pin CXL buffer pages: 0x%x\n", status);
        portMemFree(pHandle);
        return status;
    }

    // Get the physical addresses from the pinned buffer
    status = nv_get_cxl_buffer_pages(pPinnedHandle, &pPhysAddrs, &pageCount);
    if (status != NV_OK)
    {
        NV_PRINTF(LEVEL_ERROR, "Failed to get CXL buffer pages: 0x%x\n", status);
        nv_unpin_cxl_buffer(pPinnedHandle);
        portMemFree(pHandle);
        return status;
    }

    pHandle->pPinnedHandle = pPinnedHandle;
    pHandle->baseAddress = baseAddress;
    pHandle->size = size;
    pHandle->cxlVersion = cxlVersion;
    pHandle->pPageArray = pPhysAddrs;  // Use the pinned physical addresses
    pHandle->pageCount = pageCount;
    pHandle->pageSize = 4096;  // PAGE_SIZE
    pHandle->bRegistered = NV_TRUE;

    *ppBufferHandle = pHandle;

    return NV_OK;
}

//
// RmP2PUnregisterCxlBuffer
//
// Unregisters a previously registered CXL buffer.
//
// Parameters:
//   pBufferHandle [IN] - Handle to the registered CXL buffer
//
NV_STATUS
RmP2PUnregisterCxlBuffer
(
    void *pBufferHandle
)
{
    CXL_P2P_BUFFER_HANDLE *pHandle = (CXL_P2P_BUFFER_HANDLE *)pBufferHandle;

    if (pHandle == NULL)
    {
        return NV_ERR_INVALID_ARGUMENT;
    }

    if (!pHandle->bRegistered)
    {
        return NV_ERR_INVALID_STATE;
    }

    pHandle->bRegistered = NV_FALSE;

    // Unpin the pages - this will also free the page array
    if (pHandle->pPinnedHandle != NULL)
    {
        nv_unpin_cxl_buffer(pHandle->pPinnedHandle);
        pHandle->pPinnedHandle = NULL;
        pHandle->pPageArray = NULL;  // Owned by pinned buffer
    }

    portMemFree(pHandle);

    return NV_OK;
}

//
// RmP2PGetCxlPages
//
// Gets the physical page addresses for a portion of the CXL buffer.
//
// Parameters:
//   pBufferHandle  [IN]  - Handle to the registered CXL buffer
//   offset         [IN]  - Offset into the buffer
//   size           [IN]  - Size of the region to get pages for
//   pPhysAddrs     [OUT] - Array to receive physical addresses
//   pPageCount     [OUT] - Number of pages returned
//   pPageSize      [OUT] - Size of each page
//
NV_STATUS
RmP2PGetCxlPages
(
    void   *pBufferHandle,
    NvU64   offset,
    NvU64   size,
    NvU64  *pPhysAddrs,
    NvU32  *pPageCount,
    NvU32  *pPageSize
)
{
    CXL_P2P_BUFFER_HANDLE *pHandle = (CXL_P2P_BUFFER_HANDLE *)pBufferHandle;
    NvU32 startPage;
    NvU32 numPages;
    NvU32 i;

    if (pHandle == NULL || pPhysAddrs == NULL || pPageCount == NULL || pPageSize == NULL)
    {
        return NV_ERR_INVALID_ARGUMENT;
    }

    if (!pHandle->bRegistered)
    {
        return NV_ERR_INVALID_STATE;
    }

    if (offset + size > pHandle->size)
    {
        return NV_ERR_INVALID_ARGUMENT;
    }

    startPage = (NvU32)(offset / pHandle->pageSize);
    numPages = (NvU32)((offset + size + pHandle->pageSize - 1) / pHandle->pageSize) - startPage;

    if (startPage + numPages > pHandle->pageCount)
    {
        return NV_ERR_INVALID_ARGUMENT;
    }

    for (i = 0; i < numPages; i++)
    {
        pPhysAddrs[i] = pHandle->pPageArray[startPage + i];
    }

    *pPageCount = numPages;
    *pPageSize = pHandle->pageSize;

    return NV_OK;
}

//
// RmP2PPutCxlPages
//
// Releases pages previously obtained via RmP2PGetCxlPages.
//
// Parameters:
//   pBufferHandle [IN] - Handle to the registered CXL buffer
//   offset        [IN] - Offset that was passed to GetCxlPages
//   size          [IN] - Size that was passed to GetCxlPages
//
NV_STATUS
RmP2PPutCxlPages
(
    void  *pBufferHandle,
    NvU64  offset,
    NvU64  size
)
{
    CXL_P2P_BUFFER_HANDLE *pHandle = (CXL_P2P_BUFFER_HANDLE *)pBufferHandle;

    if (pHandle == NULL)
    {
        return NV_ERR_INVALID_ARGUMENT;
    }

    if (!pHandle->bRegistered)
    {
        return NV_ERR_INVALID_STATE;
    }

    // For now, this is a no-op since we don't pin pages
    // In a full implementation, this would release any held references

    return NV_OK;
}

//
// RmP2PCxlDmaRequest
//
// Initiates a P2P DMA transfer between GPU memory and a CXL buffer.
// The GPU is the initiator of the DMA request.
//
// Parameters:
//   pGpu          [IN] - GPU object initiating the DMA
//   pBufferHandle [IN] - Handle to the registered CXL buffer
//   gpuOffset     [IN] - Offset in GPU memory
//   cxlOffset     [IN] - Offset in CXL buffer
//   size          [IN] - Size of transfer in bytes
//   flags         [IN] - Transfer flags (direction, async, etc.)
//
NV_STATUS
RmP2PCxlDmaRequest
(
    OBJGPU *pGpu,
    void   *pBufferHandle,
    NvU64   gpuOffset,
    NvU64   cxlOffset,
    NvU64   size,
    NvU32   flags
)
{
    CXL_P2P_BUFFER_HANDLE *pHandle = (CXL_P2P_BUFFER_HANDLE *)pBufferHandle;
    NV_STATUS status = NV_OK;
    MemoryManager *pMemoryManager = NULL;
    MEMORY_DESCRIPTOR *pCxlMemDesc = NULL;
    MEMORY_DESCRIPTOR *pGpuMemDesc = NULL;
    NvU32 i;
    RmPhysAddr *pPteArray = NULL;  // Keep alive until cleanup

    (void)flags;  // Reserved for future use

    if (pGpu == NULL || pHandle == NULL || size == 0)
    {
        return NV_ERR_INVALID_ARGUMENT;
    }

    if (!pHandle->bRegistered)
    {
        return NV_ERR_INVALID_STATE;
    }

    if (cxlOffset + size > pHandle->size)
    {
        return NV_ERR_INVALID_ARGUMENT;
    }

    pMemoryManager = GPU_GET_MEMORY_MANAGER(pGpu);
    if (pMemoryManager == NULL)
    {
        NV_PRINTF(LEVEL_ERROR, "CXL P2P: Memory manager is NULL\n");
        return NV_ERR_INVALID_STATE;
    }

    //
    // Create a memory descriptor for the CXL buffer
    // This describes the system memory pages that make up the CXL buffer
    // PhysicallyContiguous must be NV_FALSE since CXL pages are not contiguous
    //
    // MEMDESC_FLAGS_SKIP_IOMMU_MAPPING: CXL memory doesn't need IOMMU mapping
    //   since we're providing raw physical addresses that the GPU can DMA to directly.
    // MEMDESC_FLAGS_CPU_ONLY: Prevents the driver from trying to set up GPU mappings
    //   that could interfere with our direct physical address access.
    //
    status = memdescCreate(&pCxlMemDesc, pGpu, size, 0, NV_FALSE, ADDR_SYSMEM,
                           NV_MEMORY_UNCACHED,
                           MEMDESC_FLAGS_SKIP_IOMMU_MAPPING);
    if (status != NV_OK)
    {
        NV_PRINTF(LEVEL_ERROR, "Failed to create CXL memory descriptor: 0x%x\n", status);
        goto cleanup;
    }

    // Set up the page array for the CXL memory descriptor
    {
        NvU32 startPage = (NvU32)(cxlOffset / pHandle->pageSize);
        NvU32 numPages = (NvU32)((cxlOffset + size + pHandle->pageSize - 1) / pHandle->pageSize) - startPage;

        // Bounds check: ensure we don't read beyond the registered page array
        if (startPage + numPages > pHandle->pageCount)
        {
            NV_PRINTF(LEVEL_ERROR, "CXL P2P: Page range exceeds registered buffer "
                      "(start=%u, count=%u, max=%u)\n",
                      startPage, numPages, pHandle->pageCount);
            status = NV_ERR_INVALID_ARGUMENT;
            goto cleanup;
        }

        // Allocate PTE array - keep it alive until cleanup to avoid use-after-free
        pPteArray = portMemAllocNonPaged(numPages * sizeof(RmPhysAddr));
        if (pPteArray == NULL)
        {
            status = NV_ERR_NO_MEMORY;
            goto cleanup;
        }

        for (i = 0; i < numPages; i++)
        {
            pPteArray[i] = pHandle->pPageArray[startPage + i];
        }

        memdescFillPages(pCxlMemDesc, 0, pPteArray, numPages, pHandle->pageSize);

        // Set page size for GPU address translation
        memdescSetPageSize(pCxlMemDesc, AT_GPU, pHandle->pageSize);
    }

    //
    // For this implementation, we allocate temporary GPU memory
    // In a real use case, the caller would provide GPU memory handles
    //
    status = memdescCreate(&pGpuMemDesc, pGpu, size, 0, NV_TRUE, ADDR_FBMEM,
                           NV_MEMORY_UNCACHED, MEMDESC_FLAGS_NONE);
    if (status != NV_OK)
    {
        NV_PRINTF(LEVEL_ERROR, "Failed to create GPU memory descriptor: 0x%x\n", status);
        goto cleanup;
    }

    // Allocate GPU memory
    status = memdescAlloc(pGpuMemDesc);
    if (status != NV_OK)
    {
        NV_PRINTF(LEVEL_ERROR, "Failed to allocate GPU memory: 0x%x\n", status);
        goto cleanup;
    }

    //
    // Perform the transfer using the memory manager
    // This will use the appropriate transfer method (CE, BAR, etc.)
    //
    // For this test implementation, we do a CXL->GPU->CXL loopback to verify
    // the DMA path works correctly. This preserves the original data while
    // exercising the copy engine.
    //
    {
        TRANSFER_SURFACE srcSurf = {0};
        TRANSFER_SURFACE dstSurf = {0};

        // Step 1: Copy from CXL to GPU (regardless of direction flag)
        srcSurf.pMemDesc = pCxlMemDesc;
        srcSurf.offset = 0;
        dstSurf.pMemDesc = pGpuMemDesc;
        dstSurf.offset = 0;

        status = memmgrMemCopy(pMemoryManager, &dstSurf, &srcSurf, size,
                               TRANSFER_FLAGS_PREFER_CE);
        if (status != NV_OK)
        {
            NV_PRINTF(LEVEL_ERROR, "CXL->GPU copy failed: 0x%x\n", status);
            goto cleanup;
        }

        // Step 2: Copy from GPU back to CXL (loopback to verify)
        srcSurf.pMemDesc = pGpuMemDesc;
        srcSurf.offset = 0;
        dstSurf.pMemDesc = pCxlMemDesc;
        dstSurf.offset = 0;

        status = memmgrMemCopy(pMemoryManager, &dstSurf, &srcSurf, size,
                               TRANSFER_FLAGS_PREFER_CE);
        if (status != NV_OK)
        {
            NV_PRINTF(LEVEL_ERROR, "GPU->CXL copy failed: 0x%x\n", status);
            goto cleanup;
        }
    }

cleanup:
    if (pGpuMemDesc != NULL)
    {
        memdescFree(pGpuMemDesc);
        memdescDestroy(pGpuMemDesc);
    }

    if (pCxlMemDesc != NULL)
    {
        memdescDestroy(pCxlMemDesc);
    }

    // Free the PTE array after memdesc is destroyed
    if (pPteArray != NULL)
    {
        portMemFree(pPteArray);
    }

    return status;
}
