/*******************************************************************************
    Extended Memory Manager - Driver Integration Hooks

    This file provides the actual integration points for the Extended Memory
    Manager into the NVIDIA GPU driver.
*******************************************************************************/

#include "kernel/gpu/extended_memory_manager.h"
#include "gpu/mem_mgr/mem_mgr.h"
#include "gpu/gpu.h"
#include "nvos.h"
#include "nvport/nvport.h"

// Module parameters
static NvU64 extended_dram_size_mb = 32768; // 32GB default
static char *extended_redirect_mode = "dma";

// Global instance
static ExtendedMemoryManager *g_extended_mgr = NULL;
static NvBool g_extended_memory_enabled = NV_FALSE;

// Original function pointers for hooking
static NV_STATUS (*orig_memmgrGetUsableMemSize)(OBJGPU *, MemoryManager *, NvU64 *) = NULL;
static NV_STATUS (*orig_memmgrAllocMemory)(OBJGPU *, MemoryManager *, NvU64, void **, NvU32) = NULL;

/*!
 * @brief Initialize the Extended Memory Manager subsystem
 *
 * @param[in] pGpu          GPU object pointer
 * @param[in] pMemoryManager Memory manager object
 *
 * @returns NV_STATUS
 */
NV_STATUS
extmemInitialize
(
    OBJGPU *pGpu,
    MemoryManager *pMemoryManager
)
{
    NV_STATUS status = NV_OK;
    NvU64 vram_size;
    NvU64 dram_size;
    RedirectMode mode;

    if (g_extended_mgr != NULL)
    {
        NV_PRINTF(LEVEL_WARNING, "Extended Memory Manager already initialized\n");
        return NV_OK;
    }

    // Get actual VRAM size
    vram_size = pMemoryManager->Ram.fbTotalMemSizeMb * (1024 * 1024);

    // Get DRAM size from module parameter
    dram_size = extended_dram_size_mb * (1024 * 1024);

    // Parse redirect mode
    if (portStringCompare(extended_redirect_mode, "cxl", 3) == 0)
    {
        mode = REDIRECT_MODE_CXL_REQUEST;
    }
    else
    {
        mode = REDIRECT_MODE_CUDAMEMCPY_DMA;
    }

    // Create and initialize the Extended Memory Manager
    g_extended_mgr = getExtendedMemoryManager();
    if (g_extended_mgr == NULL)
    {
        NV_PRINTF(LEVEL_ERROR, "Failed to create Extended Memory Manager\n");
        return NV_ERR_NO_MEMORY;
    }

    status = g_extended_mgr->initialize(vram_size, dram_size, mode);
    if (status != NV_OK)
    {
        NV_PRINTF(LEVEL_ERROR, "Failed to initialize Extended Memory Manager: 0x%x\n", status);
        delete g_extended_mgr;
        g_extended_mgr = NULL;
        return status;
    }

    g_extended_memory_enabled = NV_TRUE;

    NV_PRINTF(LEVEL_NOTICE,
              "Extended Memory Manager initialized:\n"
              "  VRAM: %llu MB\n"
              "  DRAM: %llu MB\n"
              "  Total: %llu MB\n"
              "  Mode: %s\n",
              vram_size / (1024 * 1024),
              dram_size / (1024 * 1024),
              (vram_size + dram_size) / (1024 * 1024),
              extended_redirect_mode);

    // Dump initial memory layout
    g_extended_mgr->dumpMemoryLayout();

    return NV_OK;
}

/*!
 * @brief Shutdown the Extended Memory Manager subsystem
 *
 * @param[in] pGpu          GPU object pointer
 * @param[in] pMemoryManager Memory manager object
 */
void
extmemShutdown
(
    OBJGPU *pGpu,
    MemoryManager *pMemoryManager
)
{
    if (g_extended_mgr != NULL)
    {
        NvU64 dma_transfers, cxl_requests, bytes;

        // Get final statistics
        g_extended_mgr->getStatistics(&dma_transfers, &cxl_requests, &bytes);

        NV_PRINTF(LEVEL_NOTICE,
                  "Extended Memory Manager shutdown statistics:\n"
                  "  DMA Transfers: %llu\n"
                  "  CXL Requests: %llu\n"
                  "  Total Bytes Transferred: %llu MB\n",
                  dma_transfers, cxl_requests, bytes / (1024 * 1024));

        g_extended_mgr->shutdown();
        delete g_extended_mgr;
        g_extended_mgr = NULL;
    }

    g_extended_memory_enabled = NV_FALSE;
}

/*!
 * @brief Hook for reporting GPU memory size
 *
 * This function intercepts memory size queries and reports the
 * extended size (VRAM + DRAM) when extended memory is enabled.
 *
 * @param[in]  pGpu          GPU object pointer
 * @param[in]  pMemoryManager Memory manager object
 * @param[out] pSize         Memory size in bytes
 *
 * @returns NV_STATUS
 */
NV_STATUS
extmemGetUsableMemSize
(
    OBJGPU *pGpu,
    MemoryManager *pMemoryManager,
    NvU64 *pSize
)
{
    if (g_extended_memory_enabled && g_extended_mgr != NULL)
    {
        NvU64 total_size, available_size;
        NV_STATUS status = g_extended_mgr->reportFakedMemorySize(&total_size, &available_size);

        if (status == NV_OK)
        {
            *pSize = total_size;
            return NV_OK;
        }
    }

    // Fall back to original implementation
    if (orig_memmgrGetUsableMemSize != NULL)
    {
        return orig_memmgrGetUsableMemSize(pGpu, pMemoryManager, pSize);
    }

    // Default behavior if no original function
    *pSize = pMemoryManager->Ram.fbUsableMemSize;
    return NV_OK;
}

/*!
 * @brief Hook for memory allocation
 *
 * This function intercepts memory allocation requests and handles
 * allocations that exceed VRAM size by using DRAM.
 *
 * @param[in]  pGpu          GPU object pointer
 * @param[in]  pMemoryManager Memory manager object
 * @param[in]  size          Size to allocate
 * @param[out] ppMemory      Pointer to allocated memory
 * @param[in]  flags         Allocation flags
 *
 * @returns NV_STATUS
 */
NV_STATUS
extmemAllocateMemory
(
    OBJGPU *pGpu,
    MemoryManager *pMemoryManager,
    NvU64 size,
    void **ppMemory,
    NvU32 flags
)
{
    if (g_extended_memory_enabled && g_extended_mgr != NULL)
    {
        // Check if allocation might need DRAM
        NvU64 vram_size = g_extended_mgr->getVramSize();
        NvU64 current_vram_usage = pMemoryManager->Ram.fbUsableMemSize -
                                   pMemoryManager->Ram.fbFreeMemSize;

        if (current_vram_usage + size > vram_size)
        {
            // This allocation will likely use DRAM
            ExtendedMemoryType preferred_type = MEMORY_TYPE_DRAM;

            NV_PRINTF(LEVEL_INFO,
                      "Allocation of %llu MB will use extended memory (current VRAM usage: %llu MB)\n",
                      size / (1024 * 1024), current_vram_usage / (1024 * 1024));

            return g_extended_mgr->allocateMemory(size, ppMemory, preferred_type);
        }
    }

    // Fall back to original implementation
    if (orig_memmgrAllocMemory != NULL)
    {
        return orig_memmgrAllocMemory(pGpu, pMemoryManager, size, ppMemory, flags);
    }

    return NV_ERR_NOT_SUPPORTED;
}

/*!
 * @brief Hook for memory transfer operations
 *
 * This function intercepts memory copy operations and redirects
 * DRAM accesses to DMA or CXL as configured.
 *
 * @param[in] pGpu   GPU object pointer
 * @param[in] pDst   Destination pointer
 * @param[in] pSrc   Source pointer
 * @param[in] size   Size to copy
 * @param[in] flags  Copy flags
 *
 * @returns NV_STATUS
 */
NV_STATUS
extmemMemoryCopy
(
    OBJGPU *pGpu,
    void *pDst,
    const void *pSrc,
    NvU64 size,
    NvU32 flags
)
{
    if (g_extended_memory_enabled && g_extended_mgr != NULL)
    {
        return g_extended_mgr->redirectMemoryAccess(pDst, pSrc, size);
    }

    // Fall back to standard memcpy
    portMemCopy(pDst, size, pSrc, size);
    return NV_OK;
}

/*!
 * @brief Install hooks into the memory manager
 *
 * This function saves the original function pointers and replaces
 * them with our extended memory versions.
 *
 * @param[in] pMemoryManager Memory manager object
 *
 * @returns NV_STATUS
 */
NV_STATUS
extmemInstallHooks
(
    MemoryManager *pMemoryManager
)
{
    // Save original function pointers
    // Note: These would need to be actual function pointers from the MemoryManager
    // structure. The exact names depend on the actual driver implementation.

    NV_PRINTF(LEVEL_INFO, "Installing Extended Memory Manager hooks\n");

    // The actual hooking would be done here by modifying function pointers
    // in the MemoryManager structure or using other hooking mechanisms

    return NV_OK;
}

/*!
 * @brief Remove hooks from the memory manager
 *
 * This function restores the original function pointers.
 *
 * @param[in] pMemoryManager Memory manager object
 */
void
extmemRemoveHooks
(
    MemoryManager *pMemoryManager
)
{
    NV_PRINTF(LEVEL_INFO, "Removing Extended Memory Manager hooks\n");

    // Restore original function pointers
}

/*!
 * @brief Handle memory request for extended memory regions
 *
 * @param[in] pGpu     GPU object pointer
 * @param[in] address  Memory address
 * @param[in] size     Size of request
 * @param[in] flags    Request flags
 *
 * @returns NV_STATUS
 */
NV_STATUS
extmemHandleMemoryRequest
(
    OBJGPU *pGpu,
    NvU64 address,
    NvU64 size,
    NvU32 flags
)
{
    if (g_extended_memory_enabled && g_extended_mgr != NULL)
    {
        return g_extended_mgr->handleMemoryRequest(address, size, flags);
    }

    return NV_OK;
}

/*!
 * @brief Get extended memory statistics
 *
 * @param[out] pStats Structure to fill with statistics
 *
 * @returns NV_STATUS
 */
NV_STATUS
extmemGetStatistics
(
    ExtendedMemoryStats *pStats
)
{
    if (!pStats)
        return NV_ERR_INVALID_ARGUMENT;

    if (g_extended_memory_enabled && g_extended_mgr != NULL)
    {
        g_extended_mgr->getStatistics(&pStats->dmaTransfers,
                                      &pStats->cxlRequests,
                                      &pStats->bytesTransferred);

        ExtendedMemoryInfo memInfo = g_extended_mgr->getMemoryInfo();
        pStats->vramSize = memInfo.vram_size;
        pStats->dramSize = memInfo.dram_size;
        pStats->cxlSize = memInfo.cxl_size;
        pStats->totalSize = memInfo.total_size;

        return NV_OK;
    }

    portMemSet(pStats, 0, sizeof(*pStats));
    return NV_ERR_NOT_READY;
}

/*!
 * @brief Configure CXL memory node
 *
 * @param[in] nodeId      CXL node ID
 * @param[in] baseAddress Base address for CXL memory
 * @param[in] size        Size of CXL memory region
 *
 * @returns NV_STATUS
 */
NV_STATUS
extmemConfigureCxlNode
(
    NvU32 nodeId,
    NvU64 baseAddress,
    NvU64 size
)
{
    if (g_extended_memory_enabled && g_extended_mgr != NULL)
    {
        return g_extended_mgr->configureCxlNode(nodeId, baseAddress, size);
    }

    return NV_ERR_NOT_READY;
}

/*!
 * @brief Set redirect mode for extended memory
 *
 * @param[in] mode Redirect mode (DMA or CXL)
 *
 * @returns NV_STATUS
 */
NV_STATUS
extmemSetRedirectMode
(
    const char *mode
)
{
    if (g_extended_memory_enabled && g_extended_mgr != NULL)
    {
        RedirectMode redirectMode;

        if (portStringCompare(mode, "cxl", 3) == 0)
        {
            redirectMode = REDIRECT_MODE_CXL_REQUEST;
        }
        else if (portStringCompare(mode, "dma", 3) == 0)
        {
            redirectMode = REDIRECT_MODE_CUDAMEMCPY_DMA;
        }
        else
        {
            return NV_ERR_INVALID_ARGUMENT;
        }

        return g_extended_mgr->setRedirectMode(redirectMode);
    }

    return NV_ERR_NOT_READY;
}

// Module parameter exports (for Linux kernel module)
#ifdef __linux__
#include <linux/module.h>

module_param(extended_dram_size_mb, ullong, 0644);
MODULE_PARM_DESC(extended_dram_size_mb, "Size of extended DRAM in MB (default: 32768)");

module_param(extended_redirect_mode, charp, 0644);
MODULE_PARM_DESC(extended_redirect_mode, "Redirect mode: 'dma' or 'cxl' (default: 'dma')");

EXPORT_SYMBOL(extmemInitialize);
EXPORT_SYMBOL(extmemShutdown);
EXPORT_SYMBOL(extmemGetUsableMemSize);
EXPORT_SYMBOL(extmemAllocateMemory);
EXPORT_SYMBOL(extmemMemoryCopy);
EXPORT_SYMBOL(extmemHandleMemoryRequest);
EXPORT_SYMBOL(extmemGetStatistics);
#endif