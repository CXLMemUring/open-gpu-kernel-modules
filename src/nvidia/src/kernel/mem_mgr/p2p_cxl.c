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

//
// CXL P2P DMA Buffer Handle structure
//
typedef struct CXL_P2P_BUFFER_HANDLE
{
    void   *pCxlDevice;        // CXL device handle
    NvU64   baseAddress;       // Base address of the CXL buffer
    NvU64   size;              // Size of the buffer in bytes
    NvU32   cxlVersion;        // CXL version (1, 2, or 3)
    NvU64  *pPageArray;        // Array of physical page addresses
    NvU32   pageCount;         // Number of pages
    NvU32   pageSize;          // Page size in bytes
    NvBool  bRegistered;       // Whether the buffer is registered
} CXL_P2P_BUFFER_HANDLE;

//
// RmP2PRegisterCxlBuffer
//
// Registers a CXL buffer for P2P DMA operations.
// The CPU allocates and provides the CXL memory region.
//
// Parameters:
//   pCxlDevice     [IN]  - CXL device handle from the platform
//   baseAddress    [IN]  - Base physical address of the CXL buffer
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
    NvU32 pageSize;
    NvU32 pageCount;

    if (pCxlDevice == NULL || size == 0 || ppBufferHandle == NULL)
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

    // Use 4KB pages for CXL
    pageSize = 4096;
    pageCount = (NvU32)((size + pageSize - 1) / pageSize);

    // Allocate page array
    pHandle->pPageArray = portMemAllocNonPaged(pageCount * sizeof(NvU64));
    if (pHandle->pPageArray == NULL)
    {
        portMemFree(pHandle);
        return NV_ERR_NO_MEMORY;
    }

    // Initialize page addresses (contiguous for now)
    for (NvU32 i = 0; i < pageCount; i++)
    {
        pHandle->pPageArray[i] = baseAddress + (i * pageSize);
    }

    pHandle->pCxlDevice = pCxlDevice;
    pHandle->baseAddress = baseAddress;
    pHandle->size = size;
    pHandle->cxlVersion = cxlVersion;
    pHandle->pageCount = pageCount;
    pHandle->pageSize = pageSize;
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

    if (pHandle->pPageArray != NULL)
    {
        portMemFree(pHandle->pPageArray);
        pHandle->pPageArray = NULL;
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

    //
    // TODO: Implement the actual DMA transfer
    //
    // This would involve:
    // 1. Getting the GPU physical address for gpuOffset
    // 2. Setting up DMA descriptors for the transfer
    // 3. Programming the GPU DMA engine
    // 4. If synchronous, waiting for completion
    // 5. If async, returning a transfer ID for status polling
    //
    // The transfer direction is determined by:
    //   flags & NV2080_CTRL_BUS_CXL_P2P_DMA_FLAGS_DIRECTION
    //     0 = GPU to CXL
    //     1 = CXL to GPU
    //

    // For now, return NOT_SUPPORTED until full implementation
    status = NV_ERR_NOT_SUPPORTED;

    return status;
}
