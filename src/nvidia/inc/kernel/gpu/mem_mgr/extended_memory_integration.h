/*
 * Extended Memory Manager Integration Wrapper
 */

#ifndef _EXTENDED_MEMORY_INTEGRATION_H_
#define _EXTENDED_MEMORY_INTEGRATION_H_

#ifdef ENABLE_EXTENDED_MEMORY

#include "extended_memory_build_config.h"
#include "kernel/gpu/extended_memory_manager.h"
#include "kernel/gpu/mem_mgr/extended_memory_hooks.h"

// Inline wrapper functions for easy integration
static inline NV_STATUS extmem_init_wrapper(OBJGPU *pGpu, MemoryManager *pMem) {
    #ifdef ENABLE_EXTENDED_MEMORY
        return extmemInitialize(pGpu, pMem);
    #else
        return NV_OK;
    #endif
}

static inline void extmem_shutdown_wrapper(OBJGPU *pGpu, MemoryManager *pMem) {
    #ifdef ENABLE_EXTENDED_MEMORY
        extmemShutdown(pGpu, pMem);
    #endif
}

static inline NV_STATUS extmem_get_size_wrapper(OBJGPU *pGpu, MemoryManager *pMem, NvU64 *pSize) {
    #ifdef ENABLE_EXTENDED_MEMORY
        return extmemGetUsableMemSize(pGpu, pMem, pSize);
    #else
        *pSize = pMem->Ram.fbUsableMemSize;
        return NV_OK;
    #endif
}

#else // !ENABLE_EXTENDED_MEMORY

// Empty stubs when Extended Memory is disabled
#define extmem_init_wrapper(pGpu, pMem) NV_OK
#define extmem_shutdown_wrapper(pGpu, pMem) ((void)0)
#define extmem_get_size_wrapper(pGpu, pMem, pSize) ({ *(pSize) = (pMem)->Ram.fbUsableMemSize; NV_OK; })

#endif // ENABLE_EXTENDED_MEMORY

#endif // _EXTENDED_MEMORY_INTEGRATION_H_
