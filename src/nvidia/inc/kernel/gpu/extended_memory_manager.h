/*******************************************************************************
    Extended Memory Manager for NVIDIA GPU

    This class provides functionality to:
    1. Fake GPU memory size as VRAM + DRAM
    2. Redirect DRAM requests to either cudamemcpy DMA or CXL memory requests
*******************************************************************************/

#ifndef _EXTENDED_MEMORY_MANAGER_H_
#define _EXTENDED_MEMORY_MANAGER_H_

#include <nvtypes.h>
#include <nvstatus.h>
#include <nvos.h>

typedef enum {
    MEMORY_TYPE_VRAM = 0,
    MEMORY_TYPE_DRAM,
    MEMORY_TYPE_CXL
} ExtendedMemoryType;

typedef enum {
    REDIRECT_MODE_CUDAMEMCPY_DMA = 0,
    REDIRECT_MODE_CXL_REQUEST
} RedirectMode;

typedef struct {
    NvU64 vram_size;
    NvU64 dram_size;
    NvU64 cxl_size;
    NvU64 total_size;
} ExtendedMemoryInfo;

typedef struct {
    NvU64 physical_address;
    NvU64 virtual_address;
    NvU64 size;
    ExtendedMemoryType type;
    NvBool is_allocated;
} MemoryBlock;

typedef struct {
    void *source_ptr;
    void *dest_ptr;
    NvU64 size;
    RedirectMode mode;
    NvU32 flags;
} DmaRequest;

typedef struct {
    NvU64 address;
    NvU64 size;
    NvU32 node_id;
    NvU32 flags;
} CxlRequest;

class ExtendedMemoryManager {
private:
    ExtendedMemoryInfo memory_info;
    RedirectMode redirect_mode;
    NvU64 vram_base_address;
    NvU64 dram_base_address;
    NvU64 cxl_base_address;

    // Memory tracking
    MemoryBlock *memory_blocks;
    NvU32 num_blocks;
    NvU32 max_blocks;

    // Statistics
    NvU64 total_dma_transfers;
    NvU64 total_cxl_requests;
    NvU64 bytes_transferred;

    // Helper functions
    NV_STATUS initializeMemoryBlocks();
    NV_STATUS allocateBlock(NvU64 size, ExtendedMemoryType type, MemoryBlock **block);
    NV_STATUS freeBlock(MemoryBlock *block);
    ExtendedMemoryType determineMemoryType(NvU64 address);

    // DMA operations
    NV_STATUS executeDmaTransfer(DmaRequest *request);
    NV_STATUS queueDmaTransfer(DmaRequest *request);

    // CXL operations
    NV_STATUS executeCxlRequest(CxlRequest *request);
    NV_STATUS mapCxlMemory(NvU64 address, NvU64 size);

public:
    ExtendedMemoryManager();
    ~ExtendedMemoryManager();

    // Initialization
    NV_STATUS initialize(NvU64 vram_size, NvU64 dram_size, RedirectMode mode);
    NV_STATUS shutdown();

    // Memory size management
    NvU64 getTotalMemorySize() const { return memory_info.total_size; }
    NvU64 getVramSize() const { return memory_info.vram_size; }
    NvU64 getDramSize() const { return memory_info.dram_size; }
    NvU64 getCxlSize() const { return memory_info.cxl_size; }
    ExtendedMemoryInfo getMemoryInfo() const { return memory_info; }

    // Fake memory size reporting
    NV_STATUS reportFakedMemorySize(NvU64 *total_size, NvU64 *available_size);

    // Memory allocation
    NV_STATUS allocateMemory(NvU64 size, void **ptr, ExtendedMemoryType preferred_type);
    NV_STATUS freeMemory(void *ptr);

    // Memory transfer/redirection
    NV_STATUS redirectMemoryAccess(void *dst, const void *src, NvU64 size);
    NV_STATUS handleMemoryRequest(NvU64 address, NvU64 size, NvU32 flags);

    // Mode switching
    NV_STATUS setRedirectMode(RedirectMode mode);
    RedirectMode getRedirectMode() const { return redirect_mode; }

    // Statistics
    void getStatistics(NvU64 *dma_transfers, NvU64 *cxl_requests, NvU64 *bytes);
    void resetStatistics();

    // Memory mapping
    NV_STATUS mapMemory(NvU64 physical_address, NvU64 size, void **virtual_address);
    NV_STATUS unmapMemory(void *virtual_address);

    // CXL specific operations
    NV_STATUS configureCxlNode(NvU32 node_id, NvU64 base_address, NvU64 size);
    NV_STATUS getCxlNodeInfo(NvU32 node_id, NvU64 *base_address, NvU64 *size);

    // Debug utilities
    void dumpMemoryLayout();
    void validateMemoryIntegrity();
};

// Global instance getter
ExtendedMemoryManager* getExtendedMemoryManager();

// Integration hooks for existing code
NV_STATUS hook_gpu_memory_size_query(NvU64 *size);
NV_STATUS hook_memory_allocation(NvU64 size, void **ptr, NvU32 flags);
NV_STATUS hook_memory_transfer(void *dst, const void *src, NvU64 size, NvU32 flags);

#endif // _EXTENDED_MEMORY_MANAGER_H_