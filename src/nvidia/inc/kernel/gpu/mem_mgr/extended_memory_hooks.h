/*******************************************************************************
    Extended Memory Manager - Hook Definitions
*******************************************************************************/

#ifndef _EXTENDED_MEMORY_HOOKS_H_
#define _EXTENDED_MEMORY_HOOKS_H_

#include <nvtypes.h>
#include <nvstatus.h>

// Forward declarations
typedef struct OBJGPU OBJGPU;
typedef struct MemoryManager MemoryManager;

// Statistics structure
typedef struct {
    NvU64 vramSize;
    NvU64 dramSize;
    NvU64 cxlSize;
    NvU64 totalSize;
    NvU64 dmaTransfers;
    NvU64 cxlRequests;
    NvU64 bytesTransferred;
} ExtendedMemoryStats;

// Initialization and shutdown
NV_STATUS extmemInitialize(OBJGPU *pGpu, MemoryManager *pMemoryManager);
void extmemShutdown(OBJGPU *pGpu, MemoryManager *pMemoryManager);

// Hook functions
NV_STATUS extmemGetUsableMemSize(OBJGPU *pGpu, MemoryManager *pMemoryManager, NvU64 *pSize);
NV_STATUS extmemAllocateMemory(OBJGPU *pGpu, MemoryManager *pMemoryManager,
                               NvU64 size, void **ppMemory, NvU32 flags);
NV_STATUS extmemMemoryCopy(OBJGPU *pGpu, void *pDst, const void *pSrc,
                          NvU64 size, NvU32 flags);
NV_STATUS extmemHandleMemoryRequest(OBJGPU *pGpu, NvU64 address, NvU64 size, NvU32 flags);

// Hook management
NV_STATUS extmemInstallHooks(MemoryManager *pMemoryManager);
void extmemRemoveHooks(MemoryManager *pMemoryManager);

// Configuration and statistics
NV_STATUS extmemGetStatistics(ExtendedMemoryStats *pStats);
NV_STATUS extmemConfigureCxlNode(NvU32 nodeId, NvU64 baseAddress, NvU64 size);
NV_STATUS extmemSetRedirectMode(const char *mode);

// Utility macros for integration
#ifdef ENABLE_EXTENDED_MEMORY
    #define EXTMEM_HOOK_GET_SIZE(pGpu, pMem, pSize) \
        extmemGetUsableMemSize(pGpu, pMem, pSize)
    #define EXTMEM_HOOK_ALLOC(pGpu, pMem, size, ppMem, flags) \
        extmemAllocateMemory(pGpu, pMem, size, ppMem, flags)
    #define EXTMEM_HOOK_COPY(pGpu, dst, src, size, flags) \
        extmemMemoryCopy(pGpu, dst, src, size, flags)
#else
    #define EXTMEM_HOOK_GET_SIZE(pGpu, pMem, pSize) \
        memmgrGetUsableMemSize_HAL(pGpu, pMem, pSize)
    #define EXTMEM_HOOK_ALLOC(pGpu, pMem, size, ppMem, flags) \
        memmgrAllocMemory_HAL(pGpu, pMem, size, ppMem, flags)
    #define EXTMEM_HOOK_COPY(pGpu, dst, src, size, flags) \
        portMemCopy(dst, size, src, size)
#endif

#endif // _EXTENDED_MEMORY_HOOKS_H_