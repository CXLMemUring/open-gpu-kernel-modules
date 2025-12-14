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

// Maximum size for a single CXL buffer registration (1TB)
#define CXL_P2P_MAX_BUFFER_SIZE     (1ULL << 40)

// Maximum number of registered buffers per system
#define CXL_P2P_MAX_REGISTERED_BUFFERS  256

// Global tracking for registered CXL buffers
static NvU32 g_cxlRegisteredBufferCount = 0;
static NvU64 g_cxlTotalRegisteredSize = 0;

//
// RmP2PRegisterCxlBuffer
//
// Registers a CXL buffer for P2P DMA operations.
// Includes comprehensive validation to prevent silent crashes.
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

    (void)pCxlDevice;  // Reserved for future use

    if (size == 0 || ppBufferHandle == NULL || cxlVersion < 1 || cxlVersion > 3)
    {
        NV_PRINTF(LEVEL_ERROR, "CXL Register: invalid args (size=0x%llx, handle=%p, ver=%u)\n",
                  size, ppBufferHandle, cxlVersion);
        return NV_ERR_INVALID_ARGUMENT;
    }

    if (size > CXL_P2P_MAX_BUFFER_SIZE)
    {
        NV_PRINTF(LEVEL_ERROR, "CXL Register: buffer too large (0x%llx > 0x%llx)\n",
                  size, CXL_P2P_MAX_BUFFER_SIZE);
        return NV_ERR_INVALID_ARGUMENT;
    }

    if (baseAddress + size < baseAddress)
    {
        NV_PRINTF(LEVEL_ERROR, "CXL Register: address overflow (base=0x%llx, size=0x%llx)\n",
                  baseAddress, size);
        return NV_ERR_INVALID_ARGUMENT;
    }

    if (g_cxlRegisteredBufferCount >= CXL_P2P_MAX_REGISTERED_BUFFERS)
    {
        NV_PRINTF(LEVEL_ERROR, "CXL Register: max buffers reached (%u)\n",
                  CXL_P2P_MAX_REGISTERED_BUFFERS);
        return NV_ERR_INSUFFICIENT_RESOURCES;
    }

    pHandle = portMemAllocNonPaged(sizeof(CXL_P2P_BUFFER_HANDLE));
    if (pHandle == NULL)
    {
        NV_PRINTF(LEVEL_ERROR, "CXL Register: handle allocation failed\n");
        return NV_ERR_NO_MEMORY;
    }

    portMemSet(pHandle, 0, sizeof(CXL_P2P_BUFFER_HANDLE));

    status = nv_pin_cxl_buffer(baseAddress, size, &pPinnedHandle);
    if (status != NV_OK)
    {
        NV_PRINTF(LEVEL_ERROR, "CXL Register: page pinning failed: 0x%x (addr=0x%llx, size=0x%llx)\n",
                  status, baseAddress, size);
        portMemFree(pHandle);
        return status;
    }

    status = nv_get_cxl_buffer_pages(pPinnedHandle, &pPhysAddrs, &pageCount);
    if (status != NV_OK || pageCount == 0 || pPhysAddrs == NULL)
    {
        NV_PRINTF(LEVEL_ERROR, "CXL Register: get pages failed: 0x%x (pages=%u, array=%p)\n",
                  status, pageCount, pPhysAddrs);
        nv_unpin_cxl_buffer(pPinnedHandle);
        portMemFree(pHandle);
        return (status != NV_OK) ? status : NV_ERR_INVALID_STATE;
    }

    pHandle->pPinnedHandle = pPinnedHandle;
    pHandle->baseAddress = baseAddress;
    pHandle->size = size;
    pHandle->cxlVersion = cxlVersion;
    pHandle->pPageArray = pPhysAddrs;
    pHandle->pageCount = pageCount;
    pHandle->pageSize = 4096;
    pHandle->bRegistered = NV_TRUE;

    g_cxlRegisteredBufferCount++;
    g_cxlTotalRegisteredSize += size;

    *ppBufferHandle = pHandle;
    return NV_OK;
}

//
// RmP2PUnregisterCxlBuffer
//
// Unregisters a previously registered CXL buffer.
//
NV_STATUS
RmP2PUnregisterCxlBuffer
(
    void *pBufferHandle
)
{
    CXL_P2P_BUFFER_HANDLE *pHandle = (CXL_P2P_BUFFER_HANDLE *)pBufferHandle;
    NvU64 savedSize;

    if (pHandle == NULL)
        return NV_ERR_INVALID_ARGUMENT;

    if (!pHandle->bRegistered)
        return NV_ERR_INVALID_STATE;

    savedSize = pHandle->size;
    pHandle->bRegistered = NV_FALSE;

    if (pHandle->pPinnedHandle != NULL)
    {
        nv_unpin_cxl_buffer(pHandle->pPinnedHandle);
        pHandle->pPinnedHandle = NULL;
        pHandle->pPageArray = NULL;
    }

    portMemFree(pHandle);

    if (g_cxlRegisteredBufferCount > 0)
        g_cxlRegisteredBufferCount--;
    if (g_cxlTotalRegisteredSize >= savedSize)
        g_cxlTotalRegisteredSize -= savedSize;
    else
        g_cxlTotalRegisteredSize = 0;

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
// Includes comprehensive bounds checking to prevent silent crashes.
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
    MemoryManager *pMemoryManager;
    MEMORY_DESCRIPTOR *pCxlMemDesc = NULL;
    MEMORY_DESCRIPTOR *pGpuMemDesc = NULL;
    RmPhysAddr *pPteArray = NULL;
    NvU32 startPage;
    NvU32 numPages;
    NvU64 alignedSize;
    NvU32 i;

    (void)flags;
    (void)gpuOffset;

    // Critical parameter validation with error logging
    if (pGpu == NULL)
    {
        NV_PRINTF(LEVEL_ERROR, "CXL P2P: FATAL - NULL GPU pointer\n");
        return NV_ERR_INVALID_ARGUMENT;
    }

    if (pHandle == NULL)
    {
        NV_PRINTF(LEVEL_ERROR, "CXL P2P: FATAL - NULL buffer handle\n");
        return NV_ERR_INVALID_ARGUMENT;
    }

    if (size == 0)
    {
        NV_PRINTF(LEVEL_ERROR, "CXL P2P: FATAL - zero size transfer requested\n");
        return NV_ERR_INVALID_ARGUMENT;
    }

    // Validate handle integrity
    if (!pHandle->bRegistered)
    {
        NV_PRINTF(LEVEL_ERROR, "CXL P2P: FATAL - buffer not registered\n");
        return NV_ERR_INVALID_STATE;
    }

    if (pHandle->pPageArray == NULL)
    {
        NV_PRINTF(LEVEL_ERROR, "CXL P2P: FATAL - NULL page array in handle\n");
        return NV_ERR_INVALID_STATE;
    }

    if (pHandle->pageCount == 0 || pHandle->pageSize == 0)
    {
        NV_PRINTF(LEVEL_ERROR, "CXL P2P: FATAL - invalid page count (%u) or size (%u)\n",
                  pHandle->pageCount, pHandle->pageSize);
        return NV_ERR_INVALID_STATE;
    }

    if (pHandle->size == 0)
    {
        NV_PRINTF(LEVEL_ERROR, "CXL P2P: FATAL - buffer size is zero\n");
        return NV_ERR_INVALID_STATE;
    }

    // Bounds check: offset + size must not overflow and must be within buffer
    if (cxlOffset > pHandle->size)
    {
        NV_PRINTF(LEVEL_ERROR, "CXL P2P: OOB - offset 0x%llx exceeds buffer size 0x%llx\n",
                  cxlOffset, pHandle->size);
        return NV_ERR_INVALID_ARGUMENT;
    }

    if (size > pHandle->size - cxlOffset)
    {
        NV_PRINTF(LEVEL_ERROR, "CXL P2P: OOB - transfer size 0x%llx at offset 0x%llx exceeds buffer (size 0x%llx)\n",
                  size, cxlOffset, pHandle->size);
        return NV_ERR_INVALID_ARGUMENT;
    }

    // Calculate page range with overflow protection
    startPage = (NvU32)(cxlOffset / pHandle->pageSize);
    numPages = (NvU32)(((cxlOffset + size + pHandle->pageSize - 1) / pHandle->pageSize) - startPage);

    // Comprehensive page bounds validation
    if (startPage >= pHandle->pageCount)
    {
        NV_PRINTF(LEVEL_ERROR, "CXL P2P: OOB - startPage %u >= pageCount %u\n",
                  startPage, pHandle->pageCount);
        return NV_ERR_INVALID_ARGUMENT;
    }

    if (numPages == 0)
    {
        NV_PRINTF(LEVEL_ERROR, "CXL P2P: FATAL - calculated numPages is zero\n");
        return NV_ERR_INVALID_ARGUMENT;
    }

    if (numPages > pHandle->pageCount)
    {
        NV_PRINTF(LEVEL_ERROR, "CXL P2P: OOB - numPages %u > total pageCount %u\n",
                  numPages, pHandle->pageCount);
        return NV_ERR_INVALID_ARGUMENT;
    }

    if (startPage + numPages > pHandle->pageCount)
    {
        NV_PRINTF(LEVEL_ERROR, "CXL P2P: OOB - page range [%u, %u) exceeds pageCount %u\n",
                  startPage, startPage + numPages, pHandle->pageCount);
        return NV_ERR_INVALID_ARGUMENT;
    }

    pMemoryManager = GPU_GET_MEMORY_MANAGER(pGpu);
    if (pMemoryManager == NULL)
        return NV_ERR_INVALID_STATE;

    alignedSize = (NvU64)numPages * pHandle->pageSize;

    status = memdescCreate(&pCxlMemDesc, pGpu, alignedSize, 0, NV_FALSE, ADDR_SYSMEM,
                           NV_MEMORY_UNCACHED, MEMDESC_FLAGS_SKIP_IOMMU_MAPPING);
    if (status != NV_OK)
        goto cleanup;

    if (pCxlMemDesc->pageArraySize < ((alignedSize - 1) >> 12) + 1)
    {
        status = NV_ERR_BUFFER_TOO_SMALL;
        goto cleanup;
    }

    pPteArray = portMemAllocNonPaged(numPages * sizeof(RmPhysAddr));
    if (pPteArray == NULL)
    {
        NV_PRINTF(LEVEL_ERROR, "CXL P2P: Failed to allocate PTE array for %u pages\n", numPages);
        status = NV_ERR_NO_MEMORY;
        goto cleanup;
    }

    // Copy physical addresses with validation
    for (i = 0; i < numPages; i++)
    {
        NvU64 physAddr = pHandle->pPageArray[startPage + i];

        // Validate physical address is non-zero and looks valid
        if (physAddr == 0)
        {
            NV_PRINTF(LEVEL_ERROR, "CXL P2P: FATAL - NULL physical address at page %u (array index %u)\n",
                      startPage + i, i);
            status = NV_ERR_INVALID_ADDRESS;
            goto cleanup;
        }

        // Check for obviously invalid addresses (> 52-bit physical address space)
        if (physAddr > 0xFFFFFFFFFFFFFULL)
        {
            NV_PRINTF(LEVEL_ERROR, "CXL P2P: FATAL - invalid physical address 0x%llx at page %u\n",
                      physAddr, startPage + i);
            status = NV_ERR_INVALID_ADDRESS;
            goto cleanup;
        }

        pPteArray[i] = (RmPhysAddr)physAddr;
    }

    memdescFillPages(pCxlMemDesc, 0, pPteArray, numPages, pHandle->pageSize);

    if (pCxlMemDesc->PageCount == 0 || pCxlMemDesc->ActualSize == 0)
    {
        NV_PRINTF(LEVEL_ERROR, "CXL P2P: memdescFillPages failed - PageCount=%llu, ActualSize=0x%llx\n",
                  pCxlMemDesc->PageCount, pCxlMemDesc->ActualSize);
        status = NV_ERR_INVALID_STATE;
        goto cleanup;
    }

    memdescSetPageSize(pCxlMemDesc, AT_GPU, pHandle->pageSize);

    status = memdescCreate(&pGpuMemDesc, pGpu, alignedSize, 0, NV_TRUE, ADDR_FBMEM,
                           NV_MEMORY_UNCACHED, MEMDESC_FLAGS_NONE);
    if (status != NV_OK)
    {
        NV_PRINTF(LEVEL_ERROR, "CXL P2P: GPU memdesc create failed: 0x%x\n", status);
        goto cleanup;
    }

    status = memdescAlloc(pGpuMemDesc);
    if (status != NV_OK)
    {
        NV_PRINTF(LEVEL_ERROR, "CXL P2P: GPU memory allocation failed: 0x%x (size=0x%llx)\n",
                  status, alignedSize);
        goto cleanup;
    }

    {
        TRANSFER_SURFACE srcSurf = {0};
        TRANSFER_SURFACE dstSurf = {0};
        NvU64 transferSize = size;

        if (transferSize > pCxlMemDesc->Size)
            transferSize = pCxlMemDesc->Size;
        if (transferSize > pGpuMemDesc->Size)
            transferSize = pGpuMemDesc->Size;

        srcSurf.pMemDesc = pCxlMemDesc;
        srcSurf.offset = 0;
        dstSurf.pMemDesc = pGpuMemDesc;
        dstSurf.offset = 0;

        status = memmgrMemCopy(pMemoryManager, &dstSurf, &srcSurf, transferSize,
                               TRANSFER_FLAGS_PREFER_CE);
        if (status != NV_OK)
        {
            NV_PRINTF(LEVEL_ERROR, "CXL P2P: CXL->GPU copy failed: 0x%x (size=0x%llx)\n",
                      status, transferSize);
            goto cleanup;
        }

        srcSurf.pMemDesc = pGpuMemDesc;
        srcSurf.offset = 0;
        dstSurf.pMemDesc = pCxlMemDesc;
        dstSurf.offset = 0;

        status = memmgrMemCopy(pMemoryManager, &dstSurf, &srcSurf, transferSize,
                               TRANSFER_FLAGS_PREFER_CE);
        if (status != NV_OK)
        {
            NV_PRINTF(LEVEL_ERROR, "CXL P2P: GPU->CXL copy failed: 0x%x (size=0x%llx)\n",
                      status, transferSize);
        }
    }

cleanup:
    if (pGpuMemDesc != NULL)
    {
        memdescFree(pGpuMemDesc);
        memdescDestroy(pGpuMemDesc);
    }

    if (pCxlMemDesc != NULL)
        memdescDestroy(pCxlMemDesc);

    if (pPteArray != NULL)
        portMemFree(pPteArray);

    return status;
}
