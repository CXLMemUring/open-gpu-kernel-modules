#include <linux/module.h>
#include <linux/export-internal.h>
#include <linux/compiler.h>

MODULE_INFO(name, KBUILD_MODNAME);

__visible struct module __this_module
__section(".gnu.linkonce.this_module") = {
	.name = KBUILD_MODNAME,
	.init = init_module,
#ifdef CONFIG_MODULE_UNLOAD
	.exit = cleanup_module,
#endif
	.arch = MODULE_ARCH_INIT,
};



static const struct modversion_info ____versions[]
__used __section("__versions") = {
	{ 0x1418bda3, "unregister_kretprobe" },
	{ 0xe1e1f979, "_raw_spin_lock_irqsave" },
	{ 0x811f5b02, "__free_pages" },
	{ 0xcb8b6ec6, "kfree" },
	{ 0x81a1a811, "_raw_spin_unlock_irqrestore" },
	{ 0xd710adbf, "__kmalloc_noprof" },
	{ 0xbd03ed67, "random_kmalloc_seed" },
	{ 0x4ac4312d, "kmalloc_caches" },
	{ 0x8d1d7639, "__kmalloc_cache_noprof" },
	{ 0xaf787675, "alloc_pages_noprof" },
	{ 0xbd03ed67, "vmemmap_base" },
	{ 0xd272d446, "__fentry__" },
	{ 0xd272d446, "__x86_return_thunk" },
	{ 0xe8213e80, "_printk" },
	{ 0x7c898386, "register_kretprobe" },
	{ 0x70eca2ca, "module_layout" },
};

static const u32 ____version_ext_crcs[]
__used __section("__version_ext_crcs") = {
	0x1418bda3,
	0xe1e1f979,
	0x811f5b02,
	0xcb8b6ec6,
	0x81a1a811,
	0xd710adbf,
	0xbd03ed67,
	0x4ac4312d,
	0x8d1d7639,
	0xaf787675,
	0xbd03ed67,
	0xd272d446,
	0xd272d446,
	0xe8213e80,
	0x7c898386,
	0x70eca2ca,
};
static const char ____version_ext_names[]
__used __section("__version_ext_names") =
	"unregister_kretprobe\0"
	"_raw_spin_lock_irqsave\0"
	"__free_pages\0"
	"kfree\0"
	"_raw_spin_unlock_irqrestore\0"
	"__kmalloc_noprof\0"
	"random_kmalloc_seed\0"
	"kmalloc_caches\0"
	"__kmalloc_cache_noprof\0"
	"alloc_pages_noprof\0"
	"vmemmap_base\0"
	"__fentry__\0"
	"__x86_return_thunk\0"
	"_printk\0"
	"register_kretprobe\0"
	"module_layout\0"
;

MODULE_INFO(depends, "");


MODULE_INFO(srcversion, "D1A65AEC16A5B1943BD7E0B");
