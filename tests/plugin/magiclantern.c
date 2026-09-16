/*
 * Copyright (C) 2022 Magic Lantern Team
 *
 * License: GNU GPL, version 2.
 *   See the COPYING file in the top-level directory.
 */
#include <inttypes.h>
#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdio.h>
#include <glib.h>

#include <qemu-plugin.h>

QEMU_PLUGIN_EXPORT int qemu_plugin_version = QEMU_PLUGIN_VERSION;

static uint32_t DebugMsg_addr = 0;

/* QEMU40PEV — instruction-level 5D4 OLC probe */
static uint64_t q40pev_seq = 0;
static unsigned q40pev_shoot = 0;
static unsigned q40pev_tv = 0;
static unsigned q40pev_av = 0;

static void q40pev_insn_exec(unsigned int cpu_index, void *udata)
{
    uint32_t pc = (uint32_t)(uintptr_t)udata;
    uint32_t lo = pc & 0x00FFFFFFU;
    const char *region;
    unsigned *counter;

    if (lo >= 0x006E7000U && lo < 0x006E8200U) {
        region = "SHOOTOLC";
        counter = &q40pev_shoot;
    } else if (lo >= 0x0067A000U && lo < 0x0067B100U) {
        region = "TV";
        counter = &q40pev_tv;
    } else if (lo >= 0x00674800U && lo < 0x00675300U) {
        region = "AV";
        counter = &q40pev_av;
    } else {
        return;
    }

    unsigned n = __atomic_add_fetch(counter, 1, __ATOMIC_RELAXED);
    if (n > 300)
        return;

    uint64_t seq = __atomic_add_fetch(&q40pev_seq, 1, __ATOMIC_RELAXED);

    fprintf(stderr,
        "[QEMU40PEV-INSN] SEQ=%" PRIu64
        " CPU=%u REGION=%s PC=%08X N=%u\n",
        seq, cpu_index, region, pc, n);
}
void DebugMsg_log(unsigned int cpu_index);
static void vcpu_insn_exec_before(unsigned int cpu_index, void *udata)
{
    DebugMsg_log(cpu_index);
}

static void vcpu_tb_trans(qemu_plugin_id_t id, struct qemu_plugin_tb *tb)
{
    size_t n = qemu_plugin_tb_n_insns(tb);
    size_t i;

    static uint64_t prev_vaddr = 0;
    for (i = 0; i < n; i++) {
        struct qemu_plugin_insn *insn = qemu_plugin_tb_get_insn(tb, i);
        uint64_t vaddr = qemu_plugin_insn_vaddr(insn);

        uint32_t q40lo = (uint32_t)vaddr & 0x00FFFFFFU;
        if ((q40lo >= 0x006E7000U && q40lo < 0x006E8200U) ||
            (q40lo >= 0x0067A000U && q40lo < 0x0067B100U) ||
            (q40lo >= 0x00674800U && q40lo < 0x00675300U))
        {
            qemu_plugin_register_vcpu_insn_exec_cb(
                insn, q40pev_insn_exec,
                QEMU_PLUGIN_CB_NO_REGS,
                (void *)(uintptr_t)(uint32_t)vaddr);
        }

        if (vaddr == DebugMsg_addr
            && prev_vaddr != vaddr 
            && vaddr)
        {
            qemu_plugin_register_vcpu_insn_exec_cb(
                insn, vcpu_insn_exec_before, QEMU_PLUGIN_CB_NO_REGS, NULL);
        }
        prev_vaddr = vaddr;
    }
}

QEMU_PLUGIN_EXPORT int qemu_plugin_install(qemu_plugin_id_t id,
                                           const qemu_info_t *info,
                                           int argc, char **argv)
{
    // how to supply arguments to the plugin:
    // -plugin libmagiclantern.so,arg="beepboop=0",arg="hello=yes"
    // would give you argc == 2, argv[0] == 'beepboop=0', argv[1] == 'hello=yes'
    for(int i = 0; i < argc; i++)
    {
        char *opt = argv[i];
        if (g_str_has_prefix(opt, "debugmsg_addr="))
        {
            DebugMsg_addr = g_ascii_strtoull(opt + 14, NULL, 16);
        }
        else
        {
            fprintf(stderr, "plugin option parsing failed: %s\n", opt);
        }
    }
    qemu_plugin_register_vcpu_tb_trans_cb(id, vcpu_tb_trans);
    return 0;
}
