/*******************************************************************************
    Extended Memory Manager - ProcFS Interface

    Provides /proc/driver/nvidia/extended_memory/* interfaces for monitoring
*******************************************************************************/

#include "nv-linux.h"
#include "nv-procfs.h"
#include "os-interface.h"
#include "kernel/gpu/mem_mgr/extended_memory_hooks.h"

#ifdef CONFIG_PROC_FS

static struct proc_dir_entry *extended_memory_dir = NULL;

// Function to format memory size in human-readable format
static void format_memory_size(char *buf, size_t len, NvU64 bytes)
{
    if (bytes >= (1ULL << 40)) {
        snprintf(buf, len, "%llu.%02llu TB",
                 bytes >> 40,
                 ((bytes >> 30) & 0x3FF) * 100 / 1024);
    } else if (bytes >= (1ULL << 30)) {
        snprintf(buf, len, "%llu.%02llu GB",
                 bytes >> 30,
                 ((bytes >> 20) & 0x3FF) * 100 / 1024);
    } else if (bytes >= (1ULL << 20)) {
        snprintf(buf, len, "%llu.%02llu MB",
                 bytes >> 20,
                 ((bytes >> 10) & 0x3FF) * 100 / 1024);
    } else if (bytes >= (1ULL << 10)) {
        snprintf(buf, len, "%llu.%02llu KB",
                 bytes >> 10,
                 (bytes & 0x3FF) * 100 / 1024);
    } else {
        snprintf(buf, len, "%llu B", bytes);
    }
}

// /proc/driver/nvidia/extended_memory/info
static int
nv_procfs_read_extended_memory_info(
    struct seq_file *m,
    void *v
)
{
    ExtendedMemoryStats stats;
    NV_STATUS status;
    char size_buf[32];

    status = extmemGetStatistics(&stats);
    if (status != NV_OK)
    {
        seq_printf(m, "Extended Memory Manager: Not initialized\n");
        return 0;
    }

    seq_printf(m, "Extended Memory Manager Information\n");
    seq_printf(m, "===================================\n\n");

    seq_printf(m, "Memory Configuration:\n");

    format_memory_size(size_buf, sizeof(size_buf), stats.vramSize);
    seq_printf(m, "  VRAM Size:        %s\n", size_buf);

    format_memory_size(size_buf, sizeof(size_buf), stats.dramSize);
    seq_printf(m, "  DRAM Size:        %s\n", size_buf);

    if (stats.cxlSize > 0)
    {
        format_memory_size(size_buf, sizeof(size_buf), stats.cxlSize);
        seq_printf(m, "  CXL Size:         %s\n", size_buf);
    }

    format_memory_size(size_buf, sizeof(size_buf), stats.totalSize);
    seq_printf(m, "  Total Size:       %s\n", size_buf);

    seq_printf(m, "\nTransfer Statistics:\n");
    seq_printf(m, "  DMA Transfers:    %llu\n", stats.dmaTransfers);
    seq_printf(m, "  CXL Requests:     %llu\n", stats.cxlRequests);

    format_memory_size(size_buf, sizeof(size_buf), stats.bytesTransferred);
    seq_printf(m, "  Bytes Transferred: %s\n", size_buf);

    if (stats.dmaTransfers > 0)
    {
        NvU64 avg_transfer = stats.bytesTransferred / stats.dmaTransfers;
        format_memory_size(size_buf, sizeof(size_buf), avg_transfer);
        seq_printf(m, "  Avg Transfer Size: %s\n", size_buf);
    }

    return 0;
}

NV_DEFINE_SINGLE_PROCFS_FILE(extended_memory_info);

// /proc/driver/nvidia/extended_memory/status
static int
nv_procfs_read_extended_memory_status(
    struct seq_file *m,
    void *v
)
{
    ExtendedMemoryStats stats;
    NV_STATUS status;

    status = extmemGetStatistics(&stats);

    seq_printf(m, "Status: %s\n", (status == NV_OK) ? "ACTIVE" : "INACTIVE");

    if (status == NV_OK)
    {
        NvU64 vram_used = 0;  // Would need to get from actual allocator
        NvU64 dram_used = 0;  // Would need to get from actual allocator

        seq_printf(m, "VRAM: %llu MB / %llu MB (%.1f%% used)\n",
                   vram_used / (1024 * 1024),
                   stats.vramSize / (1024 * 1024),
                   stats.vramSize > 0 ? (100.0 * vram_used / stats.vramSize) : 0);

        seq_printf(m, "DRAM: %llu MB / %llu MB (%.1f%% used)\n",
                   dram_used / (1024 * 1024),
                   stats.dramSize / (1024 * 1024),
                   stats.dramSize > 0 ? (100.0 * dram_used / stats.dramSize) : 0);
    }

    return 0;
}

NV_DEFINE_SINGLE_PROCFS_FILE(extended_memory_status);

// /proc/driver/nvidia/extended_memory/mode
static int
nv_procfs_read_extended_memory_mode(
    struct seq_file *m,
    void *v
)
{
    // The mode would need to be retrieved from the Extended Memory Manager
    // For now, we'll show a placeholder
    seq_printf(m, "Redirect Mode: DMA\n");
    seq_printf(m, "Available Modes: DMA, CXL\n");
    return 0;
}

static ssize_t
nv_procfs_write_extended_memory_mode(
    struct file *file,
    const char __user *buffer,
    size_t count,
    loff_t *ppos
)
{
    char mode[16];
    NV_STATUS status;

    if (count >= sizeof(mode))
        return -EINVAL;

    if (copy_from_user(mode, buffer, count))
        return -EFAULT;

    mode[count] = '\0';

    // Remove trailing newline if present
    if (count > 0 && mode[count - 1] == '\n')
        mode[count - 1] = '\0';

    status = extmemSetRedirectMode(mode);
    if (status != NV_OK)
    {
        printk(KERN_ERR "nvidia: Failed to set extended memory mode to '%s'\n", mode);
        return -EINVAL;
    }

    printk(KERN_INFO "nvidia: Extended memory mode set to '%s'\n", mode);
    return count;
}

static int
nv_procfs_open_extended_memory_mode(
    struct inode *inode,
    struct file *file
)
{
    return single_open(file, nv_procfs_read_extended_memory_mode, NULL);
}

static const struct proc_ops nv_procfs_extended_memory_mode_fops = {
    .proc_open    = nv_procfs_open_extended_memory_mode,
    .proc_read    = seq_read,
    .proc_write   = nv_procfs_write_extended_memory_mode,
    .proc_lseek   = seq_lseek,
    .proc_release = single_release,
};

// /proc/driver/nvidia/extended_memory/stats
static int
nv_procfs_read_extended_memory_stats(
    struct seq_file *m,
    void *v
)
{
    ExtendedMemoryStats stats;
    NV_STATUS status;

    status = extmemGetStatistics(&stats);
    if (status != NV_OK)
    {
        seq_printf(m, "No statistics available\n");
        return 0;
    }

    seq_printf(m, "Transfer Statistics\n");
    seq_printf(m, "==================\n\n");

    seq_printf(m, "DMA Transfers:\n");
    seq_printf(m, "  Count:           %llu\n", stats.dmaTransfers);
    if (stats.dmaTransfers > 0)
    {
        NvU64 avg_size = stats.bytesTransferred / stats.dmaTransfers;
        seq_printf(m, "  Average Size:    %llu KB\n", avg_size / 1024);
        seq_printf(m, "  Total Volume:    %llu MB\n",
                   stats.bytesTransferred / (1024 * 1024));
    }

    seq_printf(m, "\nCXL Requests:\n");
    seq_printf(m, "  Count:           %llu\n", stats.cxlRequests);

    seq_printf(m, "\nOverall:\n");
    seq_printf(m, "  Total Transfers: %llu\n",
               stats.dmaTransfers + stats.cxlRequests);
    seq_printf(m, "  Total Bytes:     %llu MB\n",
               stats.bytesTransferred / (1024 * 1024));

    return 0;
}

NV_DEFINE_SINGLE_PROCFS_FILE(extended_memory_stats);

// Initialize Extended Memory procfs interface
int nv_register_extended_memory_procfs(struct proc_dir_entry *nvidia_dir)
{
    struct proc_dir_entry *entry;

    if (!nvidia_dir)
        return -EINVAL;

    // Create /proc/driver/nvidia/extended_memory directory
    extended_memory_dir = proc_mkdir("extended_memory", nvidia_dir);
    if (!extended_memory_dir)
    {
        printk(KERN_ERR "nvidia: Failed to create extended_memory procfs directory\n");
        return -ENOMEM;
    }

    // Create info file
    entry = proc_create("info", 0444, extended_memory_dir,
                       &nv_procfs_extended_memory_info_fops);
    if (!entry)
        goto cleanup;

    // Create status file
    entry = proc_create("status", 0444, extended_memory_dir,
                       &nv_procfs_extended_memory_status_fops);
    if (!entry)
        goto cleanup;

    // Create mode file (read/write)
    entry = proc_create("mode", 0644, extended_memory_dir,
                       &nv_procfs_extended_memory_mode_fops);
    if (!entry)
        goto cleanup;

    // Create stats file
    entry = proc_create("stats", 0444, extended_memory_dir,
                       &nv_procfs_extended_memory_stats_fops);
    if (!entry)
        goto cleanup;

    printk(KERN_INFO "nvidia: Extended Memory procfs interface registered\n");
    return 0;

cleanup:
    if (extended_memory_dir)
    {
        remove_proc_subtree("extended_memory", nvidia_dir);
        extended_memory_dir = NULL;
    }
    printk(KERN_ERR "nvidia: Failed to create extended memory procfs entries\n");
    return -ENOMEM;
}

// Cleanup Extended Memory procfs interface
void nv_unregister_extended_memory_procfs(struct proc_dir_entry *nvidia_dir)
{
    if (extended_memory_dir && nvidia_dir)
    {
        remove_proc_subtree("extended_memory", nvidia_dir);
        extended_memory_dir = NULL;
        printk(KERN_INFO "nvidia: Extended Memory procfs interface unregistered\n");
    }
}

#else // !CONFIG_PROC_FS

int nv_register_extended_memory_procfs(struct proc_dir_entry *nvidia_dir)
{
    return 0;
}

void nv_unregister_extended_memory_procfs(struct proc_dir_entry *nvidia_dir)
{
}

#endif // CONFIG_PROC_FS