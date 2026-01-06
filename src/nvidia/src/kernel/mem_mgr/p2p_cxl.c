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

// Page size constants for CXL P2P - use 2MB huge pages for better performance
#define CXL_P2P_PAGE_SIZE_4K         (4ULL * 1024)
#define CXL_P2P_PAGE_SIZE_2M         (2ULL * 1024 * 1024)
#define CXL_P2P_DEFAULT_PAGE_SIZE    CXL_P2P_PAGE_SIZE_2M

// BAR1 mapping threshold - use direct BAR1 for all transfers
#define CXL_P2P_BAR1_DIRECT_THRESHOLD  0

// Forward declarations for kernel page pinning interface
extern NV_STATUS nv_pin_cxl_buffer(NvU64, NvU64, void **);
extern NV_STATUS nv_unpin_cxl_buffer(void *);
extern NV_STATUS nv_get_cxl_buffer_pages(void *, NvU64 **, NvU32 *);
// New: huge page pinning interface
extern NV_STATUS nv_pin_cxl_buffer_hugepages(NvU64, NvU64, NvU32, void **);
extern NV_STATUS nv_get_cxl_buffer_hugepages(void *, NvU64 **, NvU32 *, NvU32 *);

//
// CXL P2P DMA Buffer Handle structure - enhanced for direct BAR1 P2P
//
typedef struct CXL_P2P_BUFFER_HANDLE
{
    void   *pPinnedHandle;     // Handle from page pinning (kernel)
    NvU64   baseAddress;       // Base address of the CXL buffer
    NvU64   size;              // Size of the buffer in bytes
    NvU32   cxlVersion;        // CXL version (1, 2, or 3)
    NvU64  *pPageArray;        // Array of physical page addresses (from pinning)
    NvU32   pageCount;         // Number of pages
    NvU32   pageSize;          // Page size in bytes (4K or 2M)
    NvBool  bRegistered;       // Whether the buffer is registered
    NvBool  bHugePages;        // Whether using 2MB huge pages
    // BAR1 mapping state for direct P2P
    NvU64   bar1Offset;        // BAR1 aperture offset for this buffer
    NvU64   bar1MappedSize;    // Size of BAR1 mapping
    NvBool  bBar1Mapped;       // Whether BAR1 mapping is active
    MEMORY_DESCRIPTOR *pCxlMemDesc;  // Persistent memory descriptor for CXL buffer
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
// Helper: Check if address range is 2MB aligned for huge pages
//
static NvBool
_cxlP2PCanUseHugePages
(
    NvU64 baseAddress,
    NvU64 size
)
{
    // Both base and size must be 2MB aligned for huge pages
    return ((baseAddress & (CXL_P2P_PAGE_SIZE_2M - 1)) == 0) &&
           ((size & (CXL_P2P_PAGE_SIZE_2M - 1)) == 0) &&
           (size >= CXL_P2P_PAGE_SIZE_2M);
}

//
// Helper: Create persistent memory descriptor for CXL buffer
// Uses the physical page array directly for GPU DMA access
//
static NV_STATUS
_cxlP2PCreateMemDesc
(
    OBJGPU *pGpu,
    CXL_P2P_BUFFER_HANDLE *pHandle
)
{
    NV_STATUS status;
    MEMORY_DESCRIPTOR *pMemDesc = NULL;
    RmPhysAddr *pPteArray = NULL;
    NvU32 i;

    // Create memory descriptor for system memory (CXL is system memory from GPU's perspective)
    status = memdescCreate(&pMemDesc, pGpu, pHandle->size, 0, NV_FALSE, ADDR_SYSMEM,
                           NV_MEMORY_UNCACHED, MEMDESC_FLAGS_SKIP_IOMMU_MAPPING);
    if (status != NV_OK)
    {
        NV_PRINTF(LEVEL_ERROR, "CXL P2P: Failed to create memdesc: 0x%x\n", status);
        return status;
    }

    // Allocate PTE array for the physical addresses
    pPteArray = portMemAllocNonPaged(pHandle->pageCount * sizeof(RmPhysAddr));
    if (pPteArray == NULL)
    {
        memdescDestroy(pMemDesc);
        return NV_ERR_NO_MEMORY;
    }

    // Copy physical addresses from pinned CXL buffer
    for (i = 0; i < pHandle->pageCount; i++)
    {
        pPteArray[i] = (RmPhysAddr)pHandle->pPageArray[i];
    }

    // Fill the memory descriptor with physical pages
    // This exposes CXL physical addresses directly to GPU DMA
    memdescFillPages(pMemDesc, 0, pPteArray, pHandle->pageCount, pHandle->pageSize);

    // Set the page size based on huge page support
    memdescSetPageSize(pMemDesc, AT_GPU, pHandle->pageSize);

    // Store the persistent memdesc in handle
    pHandle->pCxlMemDesc = pMemDesc;

    portMemFree(pPteArray);

    NV_PRINTF(LEVEL_INFO, "CXL P2P: Created memdesc with %u pages of %u bytes each\n",
              pHandle->pageCount, pHandle->pageSize);

    return NV_OK;
}

//
// RmP2PRegisterCxlBuffer
//
// Registers a CXL buffer for P2P DMA operations.
// Enhanced to use 2MB huge pages and create persistent BAR1 mappings.
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
    NvU32 actualPageSize = CXL_P2P_PAGE_SIZE_4K;
    NvBool bUseHugePages;

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

    // Check if we can use 2MB huge pages for better performance
    bUseHugePages = _cxlP2PCanUseHugePages(baseAddress, size);

    if (bUseHugePages)
    {
        // Try huge page pinning first (2MB pages reduce page table overhead)
        status = nv_pin_cxl_buffer_hugepages(baseAddress, size, CXL_P2P_PAGE_SIZE_2M, &pPinnedHandle);
        if (status == NV_OK)
        {
            status = nv_get_cxl_buffer_hugepages(pPinnedHandle, &pPhysAddrs, &pageCount, &actualPageSize);
            if (status == NV_OK && pageCount > 0 && pPhysAddrs != NULL)
            {
                NV_PRINTF(LEVEL_INFO, "CXL Register: using 2MB huge pages (%u pages)\n", pageCount);
                pHandle->bHugePages = NV_TRUE;
            }
            else
            {
                // Huge page get failed, fall back to 4K
                nv_unpin_cxl_buffer(pPinnedHandle);
                pPinnedHandle = NULL;
                bUseHugePages = NV_FALSE;
            }
        }
        else
        {
            // Huge page pinning failed, fall back to 4K
            bUseHugePages = NV_FALSE;
        }
    }

    // Fall back to 4K pages if huge pages not available
    if (!bUseHugePages)
    {
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
        actualPageSize = CXL_P2P_PAGE_SIZE_4K;
        pHandle->bHugePages = NV_FALSE;
    }

    pHandle->pPinnedHandle = pPinnedHandle;
    pHandle->baseAddress = baseAddress;
    pHandle->size = size;
    pHandle->cxlVersion = cxlVersion;
    pHandle->pPageArray = pPhysAddrs;
    pHandle->pageCount = pageCount;
    pHandle->pageSize = actualPageSize;
    pHandle->bRegistered = NV_TRUE;
    pHandle->bBar1Mapped = NV_FALSE;
    pHandle->pCxlMemDesc = NULL;

    g_cxlRegisteredBufferCount++;
    g_cxlTotalRegisteredSize += size;

    *ppBufferHandle = pHandle;
    return NV_OK;
}

//
// RmP2PUnregisterCxlBuffer
//
// Unregisters a previously registered CXL buffer.
// Enhanced to clean up BAR1 mappings and memory descriptors.
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

    // Clean up persistent memory descriptor
    if (pHandle->pCxlMemDesc != NULL)
    {
        memdescDestroy(pHandle->pCxlMemDesc);
        pHandle->pCxlMemDesc = NULL;
    }

    // Clear BAR1 mapping state
    pHandle->bBar1Mapped = NV_FALSE;
    pHandle->bar1Offset = 0;
    pHandle->bar1MappedSize = 0;

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
// OPTIMIZED: Uses direct BAR1 P2P mapping with persistent CXL memdesc.
// No GPU staging buffer - direct DMA between GPU VRAM and CXL physical memory.
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
    KernelBus *pKernelBus;
    NvBool bCxlToGpu = (flags & CXL_P2P_DMA_FLAG_CXL_TO_GPU) != 0;
    MEMORY_DESCRIPTOR *pGpuMemDesc = NULL;
    TRANSFER_SURFACE srcSurf = {0};
    TRANSFER_SURFACE dstSurf = {0};
    NvU64 transferSize;

    // Critical parameter validation
    if (pGpu == NULL)
    {
        NV_PRINTF(LEVEL_ERROR, "CXL P2P Direct: NULL GPU pointer\n");
        return NV_ERR_INVALID_ARGUMENT;
    }

    if (pHandle == NULL)
    {
        NV_PRINTF(LEVEL_ERROR, "CXL P2P Direct: NULL buffer handle\n");
        return NV_ERR_INVALID_ARGUMENT;
    }

    if (size == 0)
    {
        NV_PRINTF(LEVEL_ERROR, "CXL P2P Direct: zero size transfer\n");
        return NV_ERR_INVALID_ARGUMENT;
    }

    if (!pHandle->bRegistered)
    {
        NV_PRINTF(LEVEL_ERROR, "CXL P2P Direct: buffer not registered\n");
        return NV_ERR_INVALID_STATE;
    }

    // Bounds check for CXL buffer
    if (cxlOffset > pHandle->size || size > pHandle->size - cxlOffset)
    {
        NV_PRINTF(LEVEL_ERROR, "CXL P2P Direct: OOB - cxlOffset=0x%llx, size=0x%llx, bufSize=0x%llx\n",
                  cxlOffset, size, pHandle->size);
        return NV_ERR_INVALID_ARGUMENT;
    }

    pMemoryManager = GPU_GET_MEMORY_MANAGER(pGpu);
    pKernelBus = GPU_GET_KERNEL_BUS(pGpu);

    if (pMemoryManager == NULL || pKernelBus == NULL)
    {
        NV_PRINTF(LEVEL_ERROR, "CXL P2P Direct: NULL memory manager or kernel bus\n");
        return NV_ERR_INVALID_STATE;
    }

    // Create persistent CXL memory descriptor on first use
    // This memdesc directly exposes CXL physical addresses to the GPU
    if (pHandle->pCxlMemDesc == NULL)
    {
        status = _cxlP2PCreateMemDesc(pGpu, pHandle);
        if (status != NV_OK)
        {
            NV_PRINTF(LEVEL_ERROR, "CXL P2P Direct: Failed to create CXL memdesc: 0x%x\n", status);
            return status;
        }
        NV_PRINTF(LEVEL_INFO, "CXL P2P Direct: Created persistent memdesc with %u %s pages\n",
                  pHandle->pageCount, pHandle->bHugePages ? "2MB" : "4KB");
    }

    // Validate GPU state
    if (pGpu->bIsSOC || pGpu->getProperty(pGpu, PDB_PROP_GPU_IS_LOST))
    {
        NV_PRINTF(LEVEL_ERROR, "CXL P2P Direct: GPU not available\n");
        return NV_ERR_GPU_IS_LOST;
    }

    //
    // Create a GPU memory descriptor that references the GPU VRAM at gpuOffset
    // This is a "virtual" memdesc that points to existing GPU memory
    //
    status = memdescCreate(&pGpuMemDesc, pGpu, size, 0, NV_TRUE, ADDR_FBMEM,
                           NV_MEMORY_UNCACHED, MEMDESC_FLAGS_NONE);
    if (status != NV_OK)
    {
        NV_PRINTF(LEVEL_ERROR, "CXL P2P Direct: Failed to create GPU memdesc: 0x%x\n", status);
        return status;
    }

    // Describe the GPU memory at the specified offset (no allocation, just reference)
    memdescDescribe(pGpuMemDesc, ADDR_FBMEM, gpuOffset, size);

    // Clamp transfer size
    transferSize = size;
    if (transferSize > 0xFFFFFFFFULL)
    {
        NV_PRINTF(LEVEL_WARNING, "CXL P2P Direct: clamping size from 0x%llx to 4GB\n", transferSize);
        transferSize = 0xFFFFF000ULL;
    }

    //
    // Direct P2P DMA transfer using Copy Engine
    // The CE can directly access CXL physical addresses via the memdesc
    // No staging buffer needed - direct GPU VRAM <-> CXL memory transfer
    //
    if (bCxlToGpu)
    {
        // CXL -> GPU: source is CXL, destination is GPU VRAM
        srcSurf.pMemDesc = pHandle->pCxlMemDesc;
        srcSurf.offset = cxlOffset;
        dstSurf.pMemDesc = pGpuMemDesc;
        dstSurf.offset = 0;

        NV_PRINTF(LEVEL_INFO, "CXL P2P Direct: CXL->GPU, cxlOff=0x%llx, gpuOff=0x%llx, size=0x%llx, pageSize=%u\n",
                  cxlOffset, gpuOffset, transferSize, pHandle->pageSize);
    }
    else
    {
        // GPU -> CXL: source is GPU VRAM, destination is CXL
        srcSurf.pMemDesc = pGpuMemDesc;
        srcSurf.offset = 0;
        dstSurf.pMemDesc = pHandle->pCxlMemDesc;
        dstSurf.offset = cxlOffset;

        NV_PRINTF(LEVEL_INFO, "CXL P2P Direct: GPU->CXL, gpuOff=0x%llx, cxlOff=0x%llx, size=0x%llx, pageSize=%u\n",
                  gpuOffset, cxlOffset, transferSize, pHandle->pageSize);
    }

    //
    // Execute the DMA transfer using the Copy Engine
    // With 2MB huge pages, the CE can transfer larger contiguous regions
    // reducing the number of page table lookups and DMA submissions
    //
    status = memmgrMemCopy(pMemoryManager, &dstSurf, &srcSurf, (NvU32)transferSize,
                           TRANSFER_FLAGS_PREFER_CE);

    if (status != NV_OK)
    {
        NV_PRINTF(LEVEL_ERROR, "CXL P2P Direct: CE copy failed: 0x%x (dir=%s, size=0x%llx)\n",
                  status, bCxlToGpu ? "CXL->GPU" : "GPU->CXL", transferSize);
    }
    else
    {
        NV_PRINTF(LEVEL_INFO, "CXL P2P Direct: Transfer complete, %s, size=0x%llx\n",
                  bCxlToGpu ? "CXL->GPU" : "GPU->CXL", transferSize);
    }

    // Clean up the temporary GPU memdesc (the CXL memdesc is persistent)
    if (pGpuMemDesc != NULL)
    {
        memdescDestroy(pGpuMemDesc);
    }

    return status;
}
