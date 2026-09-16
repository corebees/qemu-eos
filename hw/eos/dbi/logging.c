#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

#include "qemu/osdep.h"
#include "qemu/log.h"
#include "disas/disas.h"
#include "exec/exec-all.h"
#include "exec/log.h"
#include "qapi/error.h"
#include "cpu.h"
#include "elf.h"
#include "hw/boards.h"
#include "hw/loader.h"

#include "../eos.h"
#include "../model_list.h"
#include "logging.h"
#include "memcheck.h"
#include "backtrace.h"

/* QEMU40PAD_BC_R20GY */
static int qemu40_gy_event21_wait = 0;



#define CALLSTACK_RIGHT_ALIGN 80

static uint32_t DebugMsg_addr = 0;

static const char *eos_lookup_symbol(uint32_t pc)
{
    if (pc < 0x100)
    {
        /* very low address? don't bother */
        return "";
    }

    /* known function(s)? */
    if ((pc & ~1) == (DebugMsg_addr & ~1))
    {
        return "DebugMsg";
    }

    /* looks like most (all?) symbols are loaded with Thumb bit cleared */
    const char *name = lookup_symbol(pc & ~1);

    if (!(name && name[0]))
    {
        /* not found? try to look it up with Thumb bit set */
        name = lookup_symbol(pc | 1);
    }

    return name;
}

/* whether the addresses from this memory region should be analyzed (by any logging tools) */
static inline int should_log_memory_region(MemoryRegion *mr, int is_write)
{
    int is_read = !is_write;

    if (mr->ram && qemu_loglevel_mask(EOS_LOG_RAM)) {
        if ((is_read  && qemu_loglevel_mask(EOS_LOG_RAM_R)) ||
            (is_write && qemu_loglevel_mask(EOS_LOG_RAM_W))) {
            return 1;
        }
    }

    if (mr->rom_device && qemu_loglevel_mask(EOS_LOG_ROM)) {
        if ((is_read  && qemu_loglevel_mask(EOS_LOG_ROM_R)) ||
            (is_write && qemu_loglevel_mask(EOS_LOG_ROM_W))) {
            return 1;
        }
    }

    if (mr->name == NULL)
    {
        /* unmapped? */
        assert(!mr->ram);
        assert(!mr->rom_device);
        return 1;
    }

    return 0;
}

/* whether the addresses from this memory region should be printed in logs */
/* same as above, but with the EOS_PR[int] modifier */
/* fixme: duplicate code */
static inline int should_log_memory_region_verbosely(MemoryRegion *mr, int is_write)
{
    int is_read = !is_write;

    if (mr->ram && qemu_loglevel_mask(EOS_PR(EOS_LOG_RAM))) {
        if ((is_read  && qemu_loglevel_mask(EOS_PR(EOS_LOG_RAM_R))) ||
            (is_write && qemu_loglevel_mask(EOS_PR(EOS_LOG_RAM_W)))) {
            return 1;
        }
    }

    if (mr->rom_device && qemu_loglevel_mask(EOS_PR(EOS_LOG_ROM))) {
        if ((is_read  && qemu_loglevel_mask(EOS_PR(EOS_LOG_ROM_R))) ||
            (is_write && qemu_loglevel_mask(EOS_PR(EOS_LOG_ROM_W)))) {
            return 1;
        }
    }

    if (mr->name == NULL)
    {
        /* unmapped? */
        assert(!mr->ram);
        assert(!mr->rom_device);
        return 1;
    }

    return 0;
}

static void eos_log_selftest(hwaddr addr, uint64_t value, uint32_t size, int flags)
{
    int is_write = flags & 1;
    int no_check = flags & NOCHK_LOG;

    /* check reads - they must match the memory contents */
    if (!no_check && !is_write)
    {
        uint64_t check;
        uint64_t mask = (1ull << (size*8)) - 1;
        assert(size <= 4);
        cpu_physical_memory_read(addr, &check, size);
        if ((check & mask) != (value & mask))
        {
            fprintf(stderr, "FIXME: %x: %x vs %x (R%d)\n", (int)addr, (int)value, (int)check, size);
        }
    }

    if (is_write)
    {
        /* rebuild a second copy of the RAM */
        static uint32_t *buf = NULL; if (!buf) buf = calloc(1, eos_state->model->ram_size);
        static uint32_t *ram = NULL; if (!ram) ram = calloc(1, eos_state->model->ram_size);

        /* ckeck both copies every now and then to make sure they are identical (slow) */
        static int k = 0; k++;
        if ((k % 0x100000 == 0) && (!no_check))
        {
            cpu_physical_memory_read(0, ram, eos_state->model->ram_size);
            for (int i = 0; i < eos_state->model->ram_size/4; i++)
            {
                if (buf[i] != ram[i])
                {
                    fprintf(stderr, "FIXME: %x: %x vs %x (W%d)\n", i*4, (int)buf[i], (int)ram[i], size);
                    buf[i] = ram[i];
                }
            }
        }
        
        uint32_t address = addr;
        if (address >= 0x40001000)
        {
            address &= ~0x40000000;
        }
        if (address < 0x40000000)
        {
            switch (size)
            {
                case 1:
                    ((uint8_t *)buf)[address] = value;
                    break;
                case 2:
                    ((uint16_t *)buf)[address/2] = value;
                    break;
                case 4:
                    ((uint32_t *)buf)[address/4] = value;
                    break;
                default:
                    assert(0);
            }
        }
    }
}

static void eos_callstack_log_mem(hwaddr _addr, uint64_t _value, uint32_t size, int flags);
static void eos_romcpy_log_mem(MemoryRegion *mr, hwaddr _addr, uint64_t _value, uint32_t size, int flags);

void eos_log_mem(hwaddr addr, uint64_t value, uint32_t size, int flags)
{
    const char *msg = "";
    intptr_t msg_arg1 = 0;
    intptr_t msg_arg2 = 0;
    int is_write = flags & 1;
    int mode = is_write ? MODE_WRITE : MODE_READ;

    /* find out what kind of memory is this */
    /* fixme: can be slow */
    hwaddr l = 4;
    hwaddr addr1;
    MemoryRegion *mr = address_space_translate(&address_space_memory, addr, &addr1, &l, is_write,
                                               MEMTXATTRS_UNSPECIFIED);

    if (!should_log_memory_region(mr, is_write))
    {
        return;
    }

    if (qemu_loglevel_mask(EOS_LOG_RAM_DBG))
    {
        /* perform a self-test to make sure the loggers capture
         * all memory write events correctly (not sure how to check reads)
         */
        eos_log_selftest(addr, value, size, flags);
    }

    if (qemu_loglevel_mask(EOS_LOG_CALLSTACK))
    {
        eos_callstack_log_mem(addr, value, size, flags);
    }

    if (qemu_loglevel_mask(EOS_LOG_CALLS))
    {
        /* calls implies callstack; nothing to do here */
        /* will just print the function calls as they happen */
    }

    if (qemu_loglevel_mask(EOS_LOG_ROMCPY))
    {
        eos_romcpy_log_mem(mr, addr, value, size, flags);
    }

    if (qemu_loglevel_mask(EOS_LOG_RAM_MEMCHK))
    {
        /* in memcheck.c */
        eos_memcheck_log_mem(addr, value, size, flags);
    }

    if (!should_log_memory_region_verbosely(mr, is_write))
    {
        /* only print the items specifically asked by the user */
        return;
    }

    /* we are going log memory accesses in the same way as I/O */
    /* even if -d io was not specified */
    mode |= FORCE_LOG;

    switch (size)
    {
        case 1:
            msg = "8-bit";
            value &= 0xFF;
            break;
        case 2:
            msg = "16-bit";
            value &= 0xFFFFF;
            break;
        case 4:
            value &= 0xFFFFFFFF;
            break;
        default:
            assert(0);
    }

    if (is_write)
    {
        /* log the old value as well */
        msg_arg2 = (intptr_t) msg;
        msg_arg1 = 0;
        msg = "was 0x%X; %s";
        cpu_physical_memory_read(addr, &msg_arg1, size);
    }

    /* all our memory region names start with eos. */
    assert(!mr->name || strncmp(mr->name, "eos.", 4) == 0);
    const char *name = (mr->name) ? mr->name + 4 : KLRED"UNMAPPED"KRESET;
    io_log(name, addr, mode, value, value, msg, msg_arg1, msg_arg2);
}



/* ----------------------------------------------------------------------------- */


static char idc_path[100];
static FILE *idc = NULL;

/* QEMU is usually closed with CTRL-C, so call this when finished */
static void close_idc(void)
{
    fprintf(idc, "}\n");
    fclose(idc); idc = 0;
    fprintf(stderr, "%s saved.\n", idc_path);
}

static void eos_idc_log_call(CPUState *cpu, CPUARMState *env,
    TranslationBlock *tb, uint32_t prev_pc, uint32_t prev_lr, uint32_t prev_size)
{
    static int stderr_dup = 0;

    if (!idc)
    {
        snprintf(idc_path, sizeof(idc_path), "%s/calls.idc", eos_state->model->name);
        fprintf(stderr, "Exporting called functions to %s.\n", idc_path);
        idc = fopen(idc_path, "w");
        assert(idc);

        atexit(close_idc);

        fprintf(idc, "/* List of functions called during execution. */\n");
        fprintf(idc, "/* Generated from QEMU. */\n\n");
        fprintf(idc, "#include <idc.idc>\n\n");
        fprintf(idc, "static main() {\n");

        stderr_dup = dup(fileno(stderr));
    }

    /* bit array for every possible PC & ~3 */
    static uint32_t saved_pcs[(1u << 30) / 32] = {0};

    uint32_t pc = env->regs[15];
    uint32_t lr = env->regs[14];
    uint32_t sp = env->regs[13];

    /* log each called function to IDC, only once */
    int pca = pc >> 2;
    if (!(saved_pcs[pca/32] & (1u << (pca%32))))
    {
        saved_pcs[pca/32] |= (1u << pca%32);
        
        /* log_target_disas writes to stderr; redirect it to our output file */
        /* todo: any other threads that might output to stderr? */
        assert(stderr_dup);
        fflush(stderr); fflush(idc);
        dup2(fileno(idc), fileno(stderr));
        fprintf(stderr, "  /* from "); log_target_disas(cpu, prev_pc, prev_size);
        fprintf(stderr, "   *   -> "); log_target_disas(cpu, tb->pc, tb->size);
        char *task_name = eos_get_current_task_name();
        fprintf(stderr, "   * %s%sPC:%x->%x LR:%x->%x SP:%x */\n",
            task_name ? task_name : "", task_name ? " " : "",
            prev_pc, pc, prev_lr, lr, sp
        );
        fprintf(stderr, "  SetReg(0x%X, \"T\", %d);\n", pc, env->thumb);
        fprintf(stderr, "  MakeCode(0x%X);\n", pc);
        fprintf(stderr, "  MakeFunction(0x%X, BADADDR);\n", pc);
        fprintf(stderr, "\n");
        dup2(stderr_dup, fileno(stderr));
    }
}

/* call stack reconstruction */
/* fixme: adapt panda's callstack_instr rather than reinventing the wheel */

/* todo: move it in EOSState? */
static uint32_t interrupt_level = 0;

struct call_stack_entry
{
    union
    {
        struct
        {
            uint32_t R0;  uint32_t R1; uint32_t R2;  uint32_t R3;
            uint32_t R4;  uint32_t R5; uint32_t R6;  uint32_t R7;
            uint32_t R8;  uint32_t R9; uint32_t R10; uint32_t R11;
            uint32_t R12; uint32_t sp; uint32_t lr;  uint32_t pc;
        };
        uint32_t regs[16];
    };
    uint32_t last_pc;
    uint32_t num_args;
    uint32_t is_tail_call;      /* boolean: whether it's a tail function call */
    uint32_t interrupt_id;      /* 0 = regular code, nonzero = interrupt */
    uint32_t direct_jumps[4];   /* DIGIC 6 code uses many of those */
};

static struct call_stack_entry call_stacks[256][256];
static int call_stack_num[256] = {0};

/* special stack IDs */
#define ID_INVALID   (COUNT(call_stack_num)-1)   /* no DryOS task started yet, or no info available */
#define ID_INTERRUPT (COUNT(call_stack_num)-2)   /* some interrupt handler (i.e. not a regular DryOS task) */

static uint8_t get_stackid(void)
{
    if (interrupt_level)
    {
        return ID_INTERRUPT;
    }

    uint8_t new_task_id = eos_get_current_task_id();

    /* ID_INTERRUPT is special; hopefully DryOS never returns this task ID */
    assert(new_task_id != ID_INTERRUPT);

    /* eos_get_current_task_id() might return 0xFF = invalid/unknown; that's OK */
    if (new_task_id == 0xFF) {
        assert(new_task_id == ID_INVALID);
    }

    return new_task_id & 0xFF;
}

static inline void call_stack_push(uint8_t id, uint32_t *regs,
    uint32_t pc, uint32_t last_pc, uint32_t is_tail_call, uint32_t interrupt_id)
{
    assert(call_stack_num[id] < COUNT(call_stacks[0]));

    struct call_stack_entry *entry = &call_stacks[id][call_stack_num[id]];
    memcpy(entry->regs, regs, sizeof(entry->regs));
    entry->num_args = 4;        /* fixme */
    entry->pc = pc;             /* override pc (actually, use the one that includes the Thumb flag) */
    entry->last_pc = last_pc;   /* on Thumb, LR is not enough to find this because of variable instruction size */
    entry->is_tail_call = is_tail_call;
    entry->interrupt_id = interrupt_id;
    memset(entry->direct_jumps, 0, sizeof(entry->direct_jumps));
    call_stack_num[id]++;
}

#if 0
static uint32_t call_stack_pop(uint8_t id)
{
    assert(call_stack_num[id] > 0);
    return call_stacks[id][--call_stack_num[id]].lr;
}
#endif

static uint32_t callstack_frame_size(uint8_t id, unsigned level)
{
    if (level == 0)
    {
        /* unknown */
        return 0;
    }

    uint32_t sp = call_stacks[id][level].sp;
    uint32_t next_sp = call_stacks[id][level-1].sp;
    if (sp <= next_sp && next_sp - sp < 0x10000)
    {
        /* stack decreased => easy */
        return next_sp - sp;
    }

    /* stack increased => unknown */
    return 0;
}

uint32_t eos_callstack_get_caller_param(int call_depth, enum param_type param_type)
{
    uint8_t id = get_stackid();

    if (param_type == CALL_DEPTH)
    {
        return call_stack_num[id];
    }

    int level = call_stack_num[id] - call_depth - 1;
    assert(level >= 0);

    switch (param_type)
    {
        case CALLER_STACKFRAME_SIZE:
            return callstack_frame_size(id, level);

        case CALLER_PC:
            return call_stacks[id][level].pc;

        case CALL_LOCATION:
            return call_stacks[id][level].last_pc;

        case CALLER_LR:
            return call_stacks[id][level].lr;

        case CALLER_SP:
            return call_stacks[id][level].sp;

        case CALLER_NUM_ARGS:
            return call_stacks[id][level].num_args;

        default:
            break;
    }

    /* default: positive value = function argument index */
    int arg_index = param_type;

    if (arg_index < 4)
    {
        /* first 4 args are in registers */
        return call_stacks[id][level].regs[arg_index];
    }
    else
    {
        /* all others are on the stack */
        /* assume they are in the first caller's stack frame */
        uint32_t frame_size = callstack_frame_size(id, level);
        assert((arg_index - 4) < frame_size / 4);
        uint32_t arg_addr = call_stacks[id][level].sp + (arg_index - 4) * 4;
        uint32_t arg = 0;
        cpu_physical_memory_read(arg_addr, &arg, 4);
        return arg;
    }
}

int eos_indent(int initial_len, int target_indent)
{
    char buf[256];
    int len = target_indent - initial_len;
    if (len < 0)
    {
        fprintf(stderr, "\n");
        len = target_indent;
    }
    assert(len < sizeof(buf));
    memset(buf, ' ', len);
    buf[len] = 0;
    fprintf(stderr, "%s", buf);
    return len;
}

static int call_stack_indent(uint8_t id, int initial_len, int max_initial_len)
{
    int len = initial_len;
    len += eos_indent(initial_len, max_initial_len + call_stack_num[id]);
    return len;
}

int eos_callstack_indent(void)
{
    if (qemu_loglevel_mask(EOS_LOG_CALLS)) {
        return call_stack_indent(get_stackid(), 0, 0);
    } else {
        return 0;
    }
}

int eos_callstack_get_indent(void)
{
    if (qemu_loglevel_mask(EOS_LOG_CALLS)) {
        return call_stack_num[get_stackid()];
    } else {
        return 0;
    }
}

int eos_callstack_print(const char *prefix, const char *sep, const char *suffix)
{
    uint8_t id = get_stackid();

    if (!call_stack_num[id])
    {
        /* empty? */
        return 0;
    }

    int len = fprintf(stderr, "%s", prefix);
    uint32_t pc = CURRENT_CPU->env.regs[15];
    uint32_t sp = CURRENT_CPU->env.regs[13];

    uint32_t stack_top, stack_bot;
    if (eos_get_current_task_stack(&stack_top, &stack_bot))
    {
        len += fprintf(stderr, "[%x-%x] ", stack_top, stack_bot);
    }

    len += fprintf(stderr, "(%x:%x)%s", pc, sp, sep);
    for (int k = call_stack_num[id]-1; k >= 0; k--)
    {
        uint32_t lr = call_stacks[id][k].lr;
        uint32_t sp = call_stacks[id][k].sp;
        uint32_t ii = call_stacks[id][k].interrupt_id;
        len += fprintf(stderr, "%s%x:%x%s", ii ? "i:" : "", lr, sp, sep);
    }
    len += fprintf(stderr, "%s", suffix);
    return len;
}

static int print_args(uint32_t *regs);

void eos_callstack_print_verbose(void)
{
    uint8_t id = get_stackid();

    if (!qemu_loglevel_mask(EOS_LOG_CALLSTACK)) {
        /* no callstack instrumentation enabled
         * try to figure it out from the stack */
        eos_backtrace_rebuild(0, 0);
        return;
    }

    if (!call_stack_num[id])
    {
        /* empty? */
        return;
    }

    uint32_t pc = CURRENT_CPU->env.regs[15];
    uint32_t lr = CURRENT_CPU->env.regs[14];
    uint32_t sp = CURRENT_CPU->env.regs[13];

    uint32_t stack_top, stack_bot;
    if (eos_get_current_task_stack(&stack_top, &stack_bot))
    {
        int len = fprintf(stderr, "Current stack: [%x-%x] sp=%x", stack_top, stack_bot, sp);
        len += eos_indent(len, CALLSTACK_RIGHT_ALIGN);
        len += eos_print_location(pc, lr, " at ", "\n");
    }

    for (int k = 0; k < call_stack_num[id]; k++)
    {
        struct call_stack_entry *entry = &call_stacks[id][k];
        uint32_t pc = entry->pc;
        uint32_t sp = entry->sp;
        uint32_t ret = entry->last_pc;

        int len = eos_indent(0, k);
        
        if (entry->interrupt_id)
        {
            len += fprintf(stderr, "interrupt %02Xh", entry->interrupt_id);
            len += eos_indent(len, CALLSTACK_RIGHT_ALIGN);
            eos_print_location(ret, sp, " at ", "\n");
            uint32_t pc0 = pc & ~1;
            uint32_t vbar = CURRENT_CPU->env.cp15.vbar_s;
            assert(pc0 == vbar + 0x18);
        }
        else
        {
            /* print direct jumps, if any */
            /* use any of their names for the entire group */
            const char *name = eos_lookup_symbol(pc);
            for (int i = COUNT(entry->direct_jumps)-1; i >= 0; i--) {
                if (entry->direct_jumps[i]) {
                    const char *jump_name = eos_lookup_symbol(entry->direct_jumps[i]);
                    if (jump_name && jump_name[0]) {
                        name = jump_name;
                    }
                    len += fprintf(stderr, "0x%X -> ", entry->direct_jumps[i]);
                }
            }
            len += fprintf(stderr, "0x%X", pc);

            if (name && name[0]) {
                len += fprintf(stderr, " %s", name);
            }
            len += print_args(entry->regs);
            len += eos_indent(len, CALLSTACK_RIGHT_ALIGN);
            eos_print_location(ret, sp, " at ", " (pc:sp)\n");
        }
    }
}

int eos_print_location(uint32_t pc, uint32_t lr, const char *prefix, const char *suffix)
{
    char name_suffix[512];

    const char *name = eos_lookup_symbol(pc);
    if (name && name[0]) {
        snprintf(name_suffix, sizeof(name_suffix), " (%s)%s", name, suffix);
        suffix = name_suffix;
    }

    if (interrupt_level) {
        return fprintf(stderr, "%s[INT-%02X:%x:%x]%s", prefix, eos_state->irq_id, pc, lr, suffix);
    } else {
        char *task_name = eos_get_current_task_name();
        if (task_name) {
            return fprintf(stderr, "%s[%s:%x:%x]%s", prefix, task_name, pc, lr, suffix);
        } else {
            return fprintf(stderr, "%s[%x:%x]%s", prefix, pc, lr, suffix);
        }
    }
}

int eos_print_location_gdb(void)
{
    int len = 0;
    uint32_t ret = CURRENT_CPU->env.regs[14] - 4;

    if (qemu_loglevel_mask(EOS_LOG_CALLSTACK)) {
        uint8_t id = get_stackid();
        int level = call_stack_num[id] - 1;
        uint32_t stack_lr = level >= 0 ? call_stacks[id][level].lr : 0;
        ret = stack_lr - 4;
    }

    /* on multicore machines, print CPU index for each message */
    if (CPU_NEXT(first_cpu)) {
        len += fprintf(stderr, "[CPU%d] ", current_cpu->cpu_index);
    }

    if (interrupt_level) {
        len += fprintf(stderr, "[%s     INT-%02Xh:%08x %s] ", KCYN, eos_state->irq_id, ret, KRESET) - strlen(KCYN KRESET);
    } else {
        const char * task_name = eos_get_current_task_name();
        if (!task_name) task_name = "";
        len += fprintf(stderr, "[%s%12s:%08x %s] ", KCYN, task_name, ret, KRESET) - strlen(KCYN KRESET);
    }

    return len;
}

static int print_call_location(uint32_t pc, uint32_t lr)
{
    return eos_print_location(pc, lr, " at ", "\n");
}

/* check whether a guest memory address range can be safely dereferenced */
static int check_address_range(uint32_t ptr, uint32_t len)
{
    hwaddr l = len;
    hwaddr addr1;
    MemoryRegion * mr = address_space_translate(&address_space_memory, ptr, &addr1, &l, 0,
                                                MEMTXATTRS_UNSPECIFIED);

    if (!mr)
    {
        return 0;
    }

    if (l != len)
    {
        return 0;
    }

    return mr->ram || mr->rom_device;
}

/* from dm-spy-experiments */
static int is_sane_ptr(uint32_t ptr, uint32_t len)
{
    if (ptr < 0x1000)
    {
        return 0;
    }

    if ((ptr & 0xF0000000) != ((ptr + len) & 0xF0000000))
    {
        return 0;
    }

    switch (ptr & 0xF0000000)
    {
        case 0x00000000:
        case 0x10000000:
        case 0x40000000:
        case 0x50000000:
        case 0xE0000000:
        case 0xF0000000:
            /* looks fine at first sight; now perform a thorough check */
            return check_address_range(ptr, len);
    }

    return 0;
}

static const char *looks_like_string(uint32_t addr)
{
    if (!is_sane_ptr(addr, 64))
    {
        return 0;
    }

    static char buf[64];
    const int min_len = 4;
    const int max_len = sizeof(buf);
    cpu_physical_memory_read(addr, buf, sizeof(buf));
    buf[sizeof(buf)-1] = 0;

    for (char *p = buf; p < buf + max_len; p++)
    {
        unsigned char c = *p;
        if (c == 0 && p > buf + min_len)
        {
            if (p + 1 == buf + max_len)
            {
                *(p-1) = *(p-2) = *(p-3) = '.';
            }
            return buf;
        }
        if ((c < 32 || c > 127) && c != 7 && c != 10 && c != 13)
        {
            return 0;
        }
    }
    return 0;
}

static const char *string_escape(const char *str)
{
    static char buf[128];
    char *out = buf;
    for (const char *c = str; *c && out + 2 < buf + sizeof(buf); c++)
    {
        switch ((unsigned char)(*c))
        {
            case 10:
                *out = '\\'; out++;
                *out = 'n'; out++;
                break;
            case 13:
                *out = '\\'; out++;
                *out = 'r'; out++;
                break;
            case 7:
                *out = '\\'; out++;
                *out = 'a'; out++;
                break;
            case 32 ... 127:
                *out = *c; out++;
                break;
            default:
                *out = '?'; out++;
        }
    }
    *out = 0;
    return buf;
}

static int print_arg(uint32_t arg)
{
    int len = fprintf(stderr, "%x", arg);

    const char *name = eos_lookup_symbol(arg);
    if (name && name[0])
    {
        return len + fprintf(stderr, " %s", name);
    }

    const char *str = 0;
    if ((str = looks_like_string(arg)))
    {
        return len + fprintf(stderr, " \"%s\"", string_escape(str));
    }

    if (is_sane_ptr(arg, 4))
    {
        uint32_t mem_arg;
        cpu_physical_memory_read(arg, &mem_arg, sizeof(mem_arg));
        if ((str = looks_like_string(mem_arg)))
        {
            return len + fprintf(stderr, " &\"%s\"", string_escape(str));
        }
    }

    return len;
}

static int print_args(uint32_t *regs)
{
    /* fixme: guess the number of arguments */
    int len = 0;
    len += fprintf(stderr, "(");
    len += print_arg(regs[0]);
    len += fprintf(stderr, ", ");
    len += print_arg(regs[1]);
    len += fprintf(stderr, ", ");
    len += print_arg(regs[2]);
    len += fprintf(stderr, ", ");
    len += print_arg(regs[3]);
    len += fprintf(stderr, ")");
    return len;
}

static void eos_callstack_log_mem(hwaddr _addr, uint64_t _value, uint32_t size, int flags)
{
    uint32_t addr = _addr;
    uint32_t value = _value;
    int is_write = flags & 1;
    int is_read = !is_write;
    uint32_t sp = CURRENT_CPU->env.regs[13];

    if (is_read && 
        addr > sp &&
        addr < sp + 0x100)
    {
        uint8_t id = get_stackid();
        int call_depth = call_stack_num[id];
        if (call_depth)
        {
            uint32_t caller1_sp = eos_callstack_get_caller_param(0, CALLER_SP);

            if (addr >= caller1_sp)
            {
                /* read access in 1st caller stack frame or beyond? */
                uint32_t caller1_frame_size = eos_callstack_get_caller_param(0, CALLER_STACKFRAME_SIZE);
                uint32_t caller2_sp = caller1_sp + caller1_frame_size;

                if (addr < caller2_sp)
                {
                    /* reading more than 4 arguments from stack? */

                    int level = call_stack_num[id] - 1;
                    int num_args = call_stacks[id][level].num_args;
                    for (int i = 0; i < num_args; i++)
                    {
                        uint32_t arg = eos_callstack_get_caller_param(0, i);
                        if (arg >= sp && arg <= addr)
                        {
                            /* found a pointer to this address
                             * probably a local variable */
                            return;
                        }
                    }

                    int arg_num = 5 + (addr - caller1_sp) / 4;
                    if (arg_num > 9)
                    {
                        return;
                    }

                    call_stacks[id][level].num_args = MAX(arg_num, call_stacks[id][level].num_args);

                    if (qemu_loglevel_mask(EOS_LOG_CALLS)) {
                        uint32_t pc = CURRENT_CPU->env.regs[15];
                        uint32_t lr = CURRENT_CPU->env.regs[14];
                        int len = eos_callstack_indent();
                        len += fprintf(stderr, "arg%d = ", arg_num);
                        len += print_arg(value);
                        len += eos_indent(len, CALLSTACK_RIGHT_ALIGN);
                        print_call_location(pc, lr);
                        if (arg_num > 10)
                        {
                            eos_callstack_indent();
                            eos_callstack_print("cstack:", " ", "\n");
                            assert(0);
                        }
                    }
                }
            }
        }
    }

    if (is_write && qemu_loglevel_mask(EOS_LOG_CALLS))
    {
        uint8_t id = get_stackid();
        int call_depth = call_stack_num[id];
        if (call_depth)
        {
            int level = call_stack_num[id] - 1;
            int num_args = call_stacks[id][level].num_args;
            for (int i = 0; i < num_args; i++)
            {
                uint32_t arg = eos_callstack_get_caller_param(0, i);
                if (addr == arg)
                {
                    uint32_t pc = CURRENT_CPU->env.regs[15];
                    uint32_t lr = CURRENT_CPU->env.regs[14];
                    int len = eos_callstack_indent();
                    len += fprintf(stderr, "*%x = %x", addr, value);
                    len += eos_indent(len, CALLSTACK_RIGHT_ALIGN - 4);
                    len += fprintf(stderr, "arg%d", i + 1);
                    len += eos_indent(len, CALLSTACK_RIGHT_ALIGN);
                    print_call_location(pc, lr);
                }
            }
        }
    }
}

static int check_abi_register_usage(CPUARMState *env, int id, int k, uint32_t prev_pc, int output)
{
    int warnings = 0;

    /* check whether the scratch registers were preserved as specified in the ABI */
    for (int i = 4; i <= 11; i++)
    {
        if (env->regs[i] != call_stacks[id][k].regs[i])
        {
            warnings++;

            if (output)
            {
                int len = eos_callstack_indent();
                len += fprintf(stderr, KCYN"Warning: R%d not restored"KRESET" (0x%x -> 0x%x)", i, call_stacks[id][k].regs[i], env->regs[i]);
                len -= strlen(KCYN KRESET);
                len += eos_indent(len, CALLSTACK_RIGHT_ALIGN);
                uint32_t stack_lr = call_stacks[id][k].lr;
                print_call_location(prev_pc, stack_lr);
            }
        }
    }

    uint32_t sp = env->regs[13];
    if (sp != call_stacks[id][k].sp)
    {
        warnings++;

        if (output)
        {
            /* fixme: this is OK when ML patches the startup process, but not OK otherwise */
            int len = eos_callstack_indent();
            len += fprintf(stderr, KCYN"Warning: SP not restored"KRESET" (0x%x -> 0x%x)", call_stacks[id][k].sp, sp);
            len -= strlen(KCYN KRESET);
            len += eos_indent(len, CALLSTACK_RIGHT_ALIGN);
            uint32_t stack_lr = call_stacks[id][k].lr;
            print_call_location(prev_pc, stack_lr);
        }
    }

    return warnings;
}

/* store the exec log state for each task
 * (to avoid disruption from interrupts) */
struct call_stack_exec_state
{
    uint32_t pc;
    uint32_t lr;
    uint32_t sp;
    uint32_t size;
};

static struct call_stack_exec_state cs_exec_states[COUNT(call_stacks)];

static void eos_callstack_log_exec(CPUState *cpu, TranslationBlock *tb)
{
    ARMCPU *arm_cpu = ARM_CPU(cpu);
    CPUARMState *env = &arm_cpu->env;

    /* use local state for speed */
    static uint32_t prev_pc = 0xFFFFFFFF;
    static uint32_t prev_lr = 0;
    static uint32_t prev_sp = 0;
    static uint32_t prev_size = 0;

    /* pc, lr, sp */
    uint32_t pc = env->regs[15] | env->thumb;
    uint32_t lr = env->regs[14];
    uint32_t sp = env->regs[13];

    /* with the Thumb bit cleared */
    uint32_t pc0 = pc & ~1;
    uint32_t lr0 = lr & ~1;
    uint32_t prev_pc0 = prev_pc & ~1;

    uint32_t vbar = env->cp15.vbar_s;
    assert(vbar == 0 || eos_state->model->digic_version == 7
           || eos_state->model->digic_version == 8
           || eos_state->model->digic_version == 10);


    /* tb->pc always has the Thumb bit cleared */
    assert(pc0 == tb->pc);

    /* for some reason, this may called multiple times on the same PC */
    if (prev_pc0 == pc0 && prev_sp == sp && prev_lr == lr) return;

    /* our uninitialized stubs are 0 - don't log this address */
    if (!pc0) return;

    if (0)
    {
        fprintf(stderr, "   * PC:%x->%x LR:%x->%x SP:%x->%x */\n",
            prev_pc, pc, prev_lr, lr, prev_sp, sp
        );
    }

    /* only check cases where PC is "jumping" */
    if (pc == prev_pc + prev_size)
    {
        goto end;
    }

    if (pc0 == vbar + 0x18)
    {
        /* handle interrupt jumps first */

        if (interrupt_level == 0)
        {
            /* interrupted a regular DryOS task
             * save the previous state (we'll need to restore it when returning from interrupt) */
            uint8_t id = get_stackid();
            assert(id != ID_INTERRUPT);
            //fprintf(stderr, "Saving state [%x]: pc %x, lr %x, sp %x, size %x\n", id, prev_pc, prev_lr, prev_sp, prev_size);
            cs_exec_states[id] = (struct call_stack_exec_state) {
                .pc = prev_pc,
                .lr = prev_lr,
                .sp = prev_sp,
                .size = prev_size
            };
        }

        interrupt_level++;
        uint8_t id = get_stackid();
        assert(id == ID_INTERRUPT);
        if (qemu_loglevel_mask(EOS_LOG_CALLS)) {
            int len = call_stack_indent(id, 0, 0);
            len += fprintf(stderr, KCYN"interrupt %02Xh"KRESET, eos_state->irq_id);
            len -= strlen(KCYN KRESET);
            len += eos_indent(len, CALLSTACK_RIGHT_ALIGN);
            print_call_location(prev_pc, prev_lr);
        }
        if (interrupt_level == 1) assert(call_stack_num[id] == 0);
        assert(eos_state->irq_id);
        call_stack_push(id, env->regs, pc, prev_pc, 0, eos_state->irq_id);
        goto end;
    }

    if (prev_pc0 == vbar + 0x18)
    {
        /* jump from the interrupt vector - ignore */
        goto end;
    }

/* when returning from interrupt */
recheck:

    /* when returning from a function call,
     * it may decrement the call stack by 1 or more levels
     * see e.g. tail calls (B func) - in this case, one BX LR
     * does two returns (or maybe more, if tail calls are nested)
     * 
     * idea from panda callstack_instr: just look up each PC in the call stack
     * for speed: only check this for PC not advancing by 1 instruction
     * that's not enough, as about 30% of calls are "jumps" (!)
     * other heuristic: a return must either set PC=LR (BX LR) or change SP
     */

    if (pc == lr || sp != prev_sp)
    {
        uint8_t id = get_stackid();
        int interrupts_found = 0;

        for (int k = call_stack_num[id]-1; k >= 0; k--)
        {
            if (call_stacks[id][k].interrupt_id)
            {
                /* handled later */
                interrupts_found++;
                continue;
            }

            if (pc == call_stacks[id][k].lr)
            {
                /* pop tail calls, if any */
                while (k > 0 && call_stacks[id][k].is_tail_call) {
                    k--;
                    assert(pc == call_stacks[id][k].lr);
                }

                call_stack_num[id] = k;

                if (qemu_loglevel_mask(EOS_LOG_CALLS)) {
                    int len = call_stack_indent(id, 0, 0);
                    len += fprintf(stderr, "return %x to 0x%X", env->regs[0], pc | env->thumb);
                    len += eos_indent(len, CALLSTACK_RIGHT_ALIGN);

                    /* print LR from the call stack, so it will always show the caller */
                    int level = call_stack_num[id] - 1;
                    uint32_t stack_lr = level >= 0 ? call_stacks[id][level].lr : 0;
                    print_call_location(prev_pc, stack_lr);
                }

                if (interrupts_found) {
                    call_stack_indent(id, 0, 0);
                    fprintf(stderr, KBLU"FIXME: missed reti"KRESET"\n");
                    interrupt_level -= interrupts_found;
                }

                check_abi_register_usage(env, id, k, prev_pc, 1);

                /* to check whether this heuristic affects the results */
                /* (normally it should be optimized out...) */
                if (0 && !(pc == lr || sp != prev_sp))
                {
                    assert(0);
                }

                /* todo: callback here? */

                goto end;
            }
        }
    }

    /* when a function call is made:
     * - LR contains the return address (but that doesn't mean it's always modified, e.g. calls in a loop)
     * - PC jumps (it does not execute the next instruction after the call)
     * - SP is unchanged (it may be decremented inside the function, but not when executing the call)
     * - note: the first two also happen when handling an interrupt, so we check this case earlier
     */
    if (lr0 == prev_pc0 + prev_size)
    {
    function_call:
        assert(sp == prev_sp);

        /* assume anything that doesn't set LR to next instruction is a tail call */
        int tail_call = (lr0 != prev_pc0 + prev_size);

        uint8_t id = get_stackid();

        if (qemu_loglevel_mask(EOS_LOG_CALLS)) {
            const char * name = eos_lookup_symbol(pc);
            int len = call_stack_indent(id, 0, 0);
            len += fprintf(stderr, "%scall 0x%X", tail_call ? "tail " : "", pc | env->thumb);
            if (name && name[0]) {
                len += fprintf(stderr, " %s", name);
            }
            len += print_args(env->regs);
            len += eos_indent(len, CALLSTACK_RIGHT_ALIGN);

            /* print LR from the call stack, so it will always show the caller */
            int level = call_stack_num[id] - 1;
            uint32_t stack_lr = level >= 0 ? call_stacks[id][level].lr : 0;
            print_call_location(prev_pc, stack_lr);
        }

        if (qemu_loglevel_mask(EOS_LOG_IDC)) {
            /* save to IDC if requested */
            eos_idc_log_call(cpu, env, tb, prev_pc, prev_lr, prev_size);
        }

        call_stack_push(id, env->regs, pc, prev_pc, tail_call, 0);

#ifdef BKT_CROSSCHECK_CALLSTACK
        if (!interrupt_level) {
            /* testing mode */
            eos_backtrace_rebuild(0, 0);
        }
#endif

        /* todo: callback here? */

        goto end;
    }

    /* check all other PC jumps */
    /* skip first instruction (we need valid prev_pc) */
    if (prev_pc != 0xFFFFFFFF)
    {
        uint32_t insn;
        cpu_physical_memory_read(prev_pc0, &insn, sizeof(insn));

        if (prev_pc & 1)
        {
            /* previous instruction was Thumb */
            /* http://read.pudn.com/downloads159/doc/709030/Thumb-2SupplementReferenceManual.pdf */
            switch (prev_size)
            {
                case 4:
                {
                    /* 32-bit Thumb instruction */
                    /* see Thumb-2SupplementReferenceManual p.52 for encoding */
                    if (insn == 0xc000e9bd)
                    {
                        /* RFEIA SP!
                         * called both when exiting from interrupt and outside interrupts */
                        goto maybe_task_switch;
                    }
                    else if ((insn & 0xD000F800) == 0x8000F000)
                    {
                        /* conditional branch (p.71) - ignore */
                        goto end;
                    }
                    else if ((insn & 0xD000F800) == 0x9000F000)
                    {
                        /* unconditional branch (p.71) */
                        goto jump_instr;
                    }
                    else if ((insn & 0xFFF0FFFF) == 0xF000E8DF)
                    {
                        /* TBB [PC, Rn] (p.473) */
                        goto end;
                    }
                    break;
                }

                case 2:
                {
                    /* 16-bit Thumb instruction */
                    /* see Thumb-2SupplementReferenceManual p.43 for encoding */
                    insn &= 0xFFFF;

                    if (insn == 0x4760)
                    {
                        /* BX IP */
                        /* frequently used in interrupt handler */
                        /* workaround for the direct jump test */
                        uint8_t id = get_stackid();
                        int level = call_stack_num[id] - 1;
                        uint32_t stack_pc = (level >= 0) ? call_stacks[id][level].pc : 0;
                        if (prev_pc - 8 == stack_pc)
                        {
                            prev_pc -= 8;
                        }
                        goto jump_instr;
                    }

                    if (insn == 0x4718)
                    {
                        /* BX R3 */
                        /* used for indirect tail calls in a few places */
                        goto jump_instr;
                    }

                    if ((insn & 0xF800) == 0xE000)
                    {
                        /* unconditional branch */
                        goto jump_instr;
                    }

                    if ((insn & 0xF000) == 0xD000)
                    {
                        /* conditional branch - ignore */
                        goto end;
                    }

                    if (((insn & 0xFD00) == 0xB100) ||
                        ((insn & 0xFD00) == 0xB900))
                    {
                        /* CBZ/CBNZ - ignore */
                        goto end;
                    }

                    break;
                }

                default:
                {
                    assert(0);
                }
            }
        }
        else /* ARM (32-bit instructions) */
        {
            if ((insn & 0xFF000000) == 0xEA000000 ||    /* B dest */
                (insn & 0xFFFFFFF0) == 0xE12FFF10)      /* BX Rn */
            {
                /* unconditional branch */
                goto jump_instr;
            }

            if ((insn & 0x0F000000) == 0x0A000000)
            {
                /* conditional branch - ignore */
                /* fixme: a few of those are actually valid tail calls */
                goto end;
            }

            if ((insn & 0xFF7FF000) == 0xe51ff000)
            {
                /* LDR PC, [PC, #off] */
                /* long jump */
                goto jump_instr;
            }

            if (insn == 0xe8fddfff || insn == 0xe8d4ffff)
            {
                /* DryOS:   LDMFD SP!, {R0-R12,LR,PC}^
                 * VxWorks: LDMIA R4, {R0-PC}^
                 * They can be called from interrupts or from regular code. */
            maybe_task_switch:
                if (interrupt_level == 0) {
                    /* DryOS task switch outside interrupts? save the previous state
                     * we'll need to restore it when returning from interrupt back to this task
                     * fixme: duplicate code */
                    uint8_t id = get_stackid();
                    assert(id != ID_INTERRUPT);
                    //fprintf(stderr, "Saving state [%x]: pc %x, lr %x, sp %x, size %x\n", id, prev_pc, prev_lr, prev_sp, prev_size);
                    cs_exec_states[id] = (struct call_stack_exec_state) {
                        .pc = prev_pc,
                        .lr = prev_lr,
                        .sp = prev_sp,
                        .size = prev_size
                    };
                    goto end;
                } else {
                    /* return from interrupt to a DryOS task */
                    goto reti;
                }
            }

            if (insn == 0xe8fd901f || insn == 0xe8fd800f)
            {
                /* DryOS:   LDMFD SP!, {R0-R4,R12,PC}^
                 * VxWorks: LDMFD SP!, {R0-R3,PC}^  */

            reti:
                /* this must be return from interrupt */
                /* note: internal returns inside an interrupt were handled as normal returns */
                assert(interrupt_level > 0);
                uint8_t id = get_stackid();
                assert(id == ID_INTERRUPT);

                int interrupt_entries = 0;
                for (int k = call_stack_num[id]-1; k >= 0; k--)
                {
                    interrupt_entries += (call_stacks[id][k].interrupt_id ? 1 : 0);
                }
                assert(interrupt_level == interrupt_entries);

                /* interrupts may be nested */
                uint32_t old_pc = 0;
                for (int k = call_stack_num[id]-1; k >= 0; k--)
                {
                    if (call_stacks[id][k].interrupt_id)
                    {
                        interrupt_level--;
                        call_stack_num[id] = k;
                        uint32_t stack_ppc = call_stacks[id][k].last_pc;
                        if (pc == stack_ppc || pc == stack_ppc + 4)
                        {
                            old_pc = stack_ppc;
                            break;
                        }
                    }
                }

                if (!old_pc)
                {
                    /* context switch? */
                    old_pc = call_stacks[id][0].last_pc;
                    assert(call_stack_num[id] == 0);
                    assert(interrupt_level == 0);
                }

                if (qemu_loglevel_mask(EOS_LOG_CALLS)) {
                    int len = call_stack_indent(id, 0, 0);
                    len += fprintf(stderr, KCYN"return from interrupt"KRESET" to %x", pc);
                    if (pc != old_pc && pc != old_pc + 4) len += fprintf(stderr, " (old=%x)", old_pc);
                    len -= strlen(KCYN KRESET);
                    len += eos_indent(len, CALLSTACK_RIGHT_ALIGN);
                    print_call_location(prev_pc, prev_lr);
                }

                if (call_stack_num[id] == 0)
                {
                    /* return to a DryOS task
                     * what if the interrupt interrupted one task right in the "middle"
                     * of a function call or return?
                     * note: we detect these by looking at prev_pc -> pc etc (using state variables).
                     * imagine this:
                     *   1234: BL 5678
                     *   <interrupt triggered here>
                     *   1238: next instruction
                     *   5678: STMFD ...
                     * we detect the call by checking whether PC jumped
                     * (here, from prev_pc = 1234 to somewhere else - the destination
                     *  would be the called function) and LR was set to next instruction
                     * (here, prev_pc + 4 = 1238).
                     * When the interrupt breaks this logic, we need to re-create
                     * the "normal" conditions (as if the interrupt wasn't there)
                     * and do the usual call/return checks. 
                     */
                    assert(old_pc == call_stacks[id][0].last_pc);

                    /* get the new stack ID (a regular DryOS stack) 
                     * and restore our state from there */
                    uint8_t id = get_stackid();
                    assert(id != ID_INTERRUPT);
                    prev_pc   = cs_exec_states[id].pc; prev_pc0 = prev_pc & ~1;
                    prev_lr   = cs_exec_states[id].lr;
                    prev_sp   = cs_exec_states[id].sp;
                    prev_size = cs_exec_states[id].size;
                    //fprintf(stderr, "Restoring state [%x]: pc %x->%x lr %x->%x sp %x->%x size %x->%x\n", id, prev_pc, pc, prev_lr, lr, prev_sp, sp, prev_size, tb->size);

                    if (pc != prev_pc && pc != prev_pc + 4)
                    {
                        /* PC jump when returning from interrupt?
                         * may be a call or a return - check it */
                        goto recheck;
                    }
                }
                goto end;
            }
        }

        /* jump instruction - could it be a tail function call? */
        if (0)
        {
        jump_instr:;
            uint8_t id = get_stackid();
            int level = call_stack_num[id] - 1;
            if (level >= 0)
            {
                struct call_stack_entry *entry = &call_stacks[id][level];
                uint32_t stack_pc = entry->pc;

                if (prev_pc == stack_pc)
                {
                    /* many DIGIC 6 functions have wrappers that simply jump to another function */
                    /* don't be too verbose on these, but also make sure it's really just a simple jump */
                    if (qemu_loglevel_mask(EOS_LOG_CALLS)) {
                        int len = call_stack_indent(id, 0, 0);
                        len += fprintf(stderr, "-> 0x%X", pc | env->thumb);
                        const char * name = eos_lookup_symbol(pc);
                        if (name && name[0]) {
                            len += fprintf(stderr, " %s", name);
                        }
                        len += eos_indent(len, CALLSTACK_RIGHT_ALIGN);

                        /* print LR from the call stack, so it will always show the caller */
                        uint32_t stack_lr = entry->lr;
                        print_call_location(prev_pc, stack_lr);
                    }
                    for (int i = 0; i < 14; i++) {
                        if (i == 12) continue;
                        if (env->regs[i] != entry->regs[i]) {
                            fprintf(stderr, "R%d changed\n", i);
                            assert(0);
                        }
                    }

                    /* update PC of the last call on the stack, to allow chaining more direct jumps */
                    /* (consider it is the same function call) */
                    assert(level >= 0);
                    assert(entry->direct_jumps[3] == 0);
                    entry->direct_jumps[3] = entry->direct_jumps[2];
                    entry->direct_jumps[2] = entry->direct_jumps[1];
                    entry->direct_jumps[1] = entry->direct_jumps[0];
                    entry->direct_jumps[0] = entry->pc;
                    entry->pc = pc;
                    goto end;
                }
                else /* not a direct jump to some function */
                {
                    if (check_abi_register_usage(env, id, level, prev_pc, 0) > 0)
                    {
                        /* this must be a jump inside a function
                         * do not report it */
                         goto end;
                    }

                    /* jumps from the current function? */
                    if (prev_pc > stack_pc &&
                        prev_pc < stack_pc + 0x1000)
                    {
                        /* jumps out of the current function? */
                        if (pc < stack_pc ||        /* jump "behind" the current function? */
                            pc > prev_pc + 0x100)   /* large jump forward? */
                        {
                            /* assume tail call
                             * fixme: in IDC, these must be defined before their caller,
                             * as IDA frequently gets them wrong */
                            if (!qemu_loglevel_mask(EOS_LOG_NO_TAIL_CALLS)) {
                                goto function_call;
                            }
                            /* with -d notail, report as jump */
                        }
                        else
                        {
                            /* most likely a jump inside a small function (not caught by ABI check) */
                            /* fixme: there are a few actual tail calls not caught by this */
                            if (0) {
                                fprintf(stderr, "short jump?");
                                print_call_location(prev_pc, prev_lr);
                            }
                            goto end;
                        }
                    }
                    else
                    {
                        /* jump not from the current function?
                         * note: most cases appear to be valid tail calls,
                         * but not identified properly because of
                         * a missed function call right before this */
                        if (!qemu_loglevel_mask(EOS_LOG_NO_TAIL_CALLS)) {
                            /* note: many warnings with -d notail */
                            /* there's also a false warning at first jump */
                            if (!(id == ID_INVALID && call_stack_num[id] == 0))
                            {
                                int len = call_stack_indent(id, 0, 0);
                                len += fprintf(stderr, KCYN"Warning: missed function call?"KRESET);
                                len -= strlen(KCYN KRESET);
                                len += eos_indent(len, CALLSTACK_RIGHT_ALIGN);
                                print_call_location(prev_pc, prev_lr);
                            }

                            /* heuristic: assume large jumps are tail calls */
                            if (abs((int)pc - (int)prev_pc) > 0x100)
                            {
                                goto function_call;
                                /* with -d notail, report as jump */
                            }
                        }
                    }
                }
            }
            /* anything that falls through the cracks is handled below */
        }

        /* unknown jump case, to be diagnosed manually */
        if (qemu_loglevel_mask(EOS_LOG_CALLS)) {
            static uint32_t prev_jump = 0;
            if (pc != prev_jump)
            {
                prev_jump = pc;
                uint8_t id = get_stackid();
                int len = call_stack_indent(id, 0, 0);
                len += fprintf(stderr, KCYN"jump to 0x%X"KRESET" lr=%x", pc | env->thumb, lr);
                len -= strlen(KCYN KRESET);
                len += eos_indent(len, CALLSTACK_RIGHT_ALIGN);
                print_call_location(prev_pc, prev_lr);
                call_stack_indent(id, 0, 0);
                /* hm, target_disas used to look at flags for ARM or Thumb... */
                int t0 = env->thumb; env->thumb = prev_pc & 1;
                assert(prev_size);
                target_disas(stderr, CPU(env_archcpu(env)), prev_pc0, prev_size);
                env->thumb = t0;
            }
        }
    }

end:
    prev_pc = pc;
    prev_lr = lr;
    prev_sp = sp;
    prev_size = tb->size;
}

static void print_task_switch(uint32_t pc, uint32_t prev_pc, uint32_t prev_lr)
{
    int len = eos_callstack_indent();
    len += fprintf(stderr,
        KCYN"Task switch"KRESET" to %s:%x %s",
        eos_get_current_task_name(), pc, eos_lookup_symbol(pc)
    );
    len -= strlen(KCYN KRESET);
    len += eos_indent(len, CALLSTACK_RIGHT_ALIGN);
    print_call_location(prev_pc, prev_lr);
}

static void eos_tasks_log_exec(CPUState *cpu, TranslationBlock *tb)
{
    ARMCPU *arm_cpu = ARM_CPU(cpu);
    CPUARMState *env = &arm_cpu->env;
    
    static uint32_t prev_pc = 0xFFFFFFFF;
    static uint32_t prev_lr = 0;
    uint32_t pc = env->regs[15] | env->thumb;
    uint32_t lr = env->regs[14];

    /* for task switch, only check large PC jumps */
    if (abs((int)pc - (int)prev_pc) > 16 &&
        eos_state->model->current_task_addr)
    {
        /* fixme: this method catches all task switches,
         * but requires reading current_task_ptr from guest memory at every PC jump */
        uint32_t current_task_ptr;
        static uint32_t previous_task_ptr;
        cpu_physical_memory_read(eos_state->model->current_task_addr, &current_task_ptr, 4);
        if (current_task_ptr != previous_task_ptr)
        {
            previous_task_ptr = current_task_ptr;
            print_task_switch(pc, prev_pc, prev_lr);
        }
    }

    prev_pc = pc;
    prev_lr = lr;
}

#ifdef __SIZEOF_INT128__

static uint32_t block_start;        /* destination address */
static uint32_t block_size;
static uint32_t block_offset;       /* start + offset = source address */
static uint32_t block_pc;           /* address of code that copies this block */
static uint32_t last_read_addr;
static uint32_t last_read_size;
static __uint128_t last_read_value;
static uint32_t last_write_addr;
static uint32_t last_write_size;
static __uint128_t last_write_value;

static char dd_path[100];
static FILE *dd = 0;

static void close_dd(void)
{
    fclose(dd); dd = 0;
    fprintf(stderr, "%s saved.\n", dd_path);
}

static void romcpy_log_block(void)
{
    uint32_t block_rom_start = block_start + block_offset;

    fprintf(stderr, "[ROMCPY] 0x%-8X -> 0x%-8X size 0x%-8X at 0x%-8X\n",
        block_rom_start, block_start, block_size, block_pc
    );

    hwaddr l = block_size;
    hwaddr block_rom_start_rel;
    MemoryRegion *mr = address_space_translate(&address_space_memory, block_rom_start, &block_rom_start_rel, &l, 0,
                                               MEMTXATTRS_UNSPECIFIED);
    assert(l == block_size);

    if (strcmp(mr->name, "eos.rom0") == 0 ||
        strcmp(mr->name, "eos.rom1") == 0)
    {
        if (!dd)
        {
            snprintf(dd_path, sizeof(dd_path), "%s/romcpy.sh", eos_state->model->name);
            fprintf(stderr, "Logging ROM-copied blocks to %s.\n", dd_path);
            dd = fopen(dd_path, "w");
            assert(dd);
            atexit(close_dd);
        }

        /* fixme: dd executes a bit slow with bs=1 */
        fprintf(dd, "dd if=ROM%c.BIN of=%s.0x%X.bin bs=1 skip=$((0x%X)) count=$((0x%X))\n",
            mr->name[7],
            eos_state->model->name, block_start, (int)block_rom_start_rel, block_size
        );
    }
}

static void romcpy_log_n_reset_block(void)
{
    if (block_size >= 64)
    {
        /* block large enough to report? */
        romcpy_log_block();
    }

    /* reset block */
    block_start = 0;
    block_size = 0;
    block_offset = 0;
    block_pc = 0;
}

static void romcpy_new_block(uint32_t write_addr, uint32_t read_addr, uint32_t size, uint32_t pc)
{
    block_start  = write_addr;
    block_size   = size;
    block_offset = read_addr - write_addr;
    block_pc = pc;
}

static void eos_romcpy_log_mem(MemoryRegion *mr, hwaddr _addr, uint64_t _value, uint32_t size, int flags)
{
    if (flags & NOCHK_LOG)
    {
        /* this is from our DMA; we don't want these to be logged :) */
        return;
    }

    uint32_t addr = _addr;
    uint32_t value = _value;
    int is_write = flags & 1;
    int is_read = !is_write;
    static int prev_read = 0;
    int was_read = prev_read;
    prev_read = is_read;

    if (is_read)
    {
        if (mr->rom_device)
        {
            if (was_read && addr == last_read_addr + last_read_size)
            {
                last_read_value |= ((__uint128_t)value << (last_read_size * 8));
                last_read_size += size;
                qemu_log_mask(EOS_LOG_VERBOSE, "%d-bit read from %x (accumulated)\n", last_read_size * 8, last_read_addr);
            }
            else
            {
                last_read_addr = addr;
                last_read_value = value;
                last_read_size = size;
                qemu_log_mask(EOS_LOG_VERBOSE, "%d-bit read from %x\n", last_read_size * 8, last_read_addr);
            }
        }
    }
    else /* write */
    {
        if (mr->ram)
        {
            if (size < last_read_size && addr == last_write_addr + last_write_size)
            {
                last_write_value |= ((__uint128_t)value << (last_write_size * 8));
                last_write_size += size;
                qemu_log_mask(EOS_LOG_VERBOSE, "%d-bit write to %x (accumulated)\n", last_write_size * 8, last_write_addr);
            }
            else
            {
                last_write_addr = addr;
                last_write_value = value;
                last_write_size = size;
                qemu_log_mask(EOS_LOG_VERBOSE, "%d-bit write to %x\n", last_write_size * 8, last_write_addr);
            }

            if (last_write_size == last_read_size)
            {
                /* reset accumulation */
                uint32_t item_size = last_write_size;
                last_write_size = last_read_size = 0;
                qemu_log_mask(EOS_LOG_VERBOSE, "%d-bit R/W\n", item_size * 8);

                if (last_write_value == last_read_value)
                {
                    uint32_t offset = last_read_addr - last_write_addr;
                    qemu_log_mask(EOS_LOG_VERBOSE, "%d-bit copy from %x to %x (offset %x)\n", item_size * 8, last_read_addr, last_write_addr, offset);
                    qemu_log_mask(EOS_LOG_VERBOSE, "current block: %x-%x (offset %x)\n", block_start, block_start + block_size, block_offset);

                    if (offset == block_offset)
                    {
                        if (last_write_addr == block_start + block_size)
                        {
                            /* growing current block to right */
                            block_size += item_size;
                            qemu_log_mask(EOS_LOG_VERBOSE, "grow block to right: %x-%x\n", block_start, block_start + block_size);
                            return;
                        }
                        if (last_write_addr == block_start - item_size)
                        {
                            /* growing current block to left */
                            block_start -= item_size;
                            block_size += item_size;
                            qemu_log_mask(EOS_LOG_VERBOSE, "grow block to left: %x-%x\n", block_start, block_start + block_size);
                            return;
                        }
                    }

                    /* not growing current block; assume a new one might have been started */
                    qemu_log_mask(EOS_LOG_VERBOSE, "new block (previous %x-%x)\n", block_start, block_start + block_size);
                    uint32_t pc = CURRENT_CPU->env.regs[15];
                    romcpy_log_n_reset_block();
                    romcpy_new_block(last_write_addr, last_read_addr, item_size, pc);
                }
            }
        }
        else /* some other value written to memory */
        {
            qemu_log_mask(EOS_LOG_VERBOSE, "reset block (previous %x-%x)\n", block_start, block_size);
            romcpy_log_n_reset_block();
        }
    }
}

#else /* no int128_t available */

static void eos_romcpy_log_mem(MemoryRegion *mr, hwaddr _addr, uint64_t _value, uint32_t size, int flags)
{
    fprintf(stderr, "FIXME: ROMCPY not supported on this platform.\n");
}
#endif

static uint64_t saved_loglevel = 0;

static void tb_exec_cb(CPUState *cpu, TranslationBlock *tb)
{
    /*
     * QEMU40PEN-ROM-ALIAS
     *
     * Determine the actual execution alias used by Canon GUI code.
     * Match only low 24 address bits so FCxxxxxx / FExxxxxx aliases
     * are both observed. Passive logging only.
     */
    {
        static unsigned pen_n=0;

        uint32_t pen_pc=(uint32_t)tb->pc;
        uint32_t pen_end=pen_pc+(uint32_t)tb->size;

        uint32_t lo_pc=pen_pc & 0x00FFFFFFU;
        uint32_t lo_end=lo_pc+(uint32_t)tb->size;

        int shootolc =
            lo_pc < 0x006E8200U &&
            lo_end > 0x006E7000U;

        int tv =
            lo_pc < 0x0067B100U &&
            lo_end > 0x0067A000U;

        int av =
            lo_pc < 0x00675300U &&
            lo_end > 0x00674800U;

        if ((shootolc || tv || av) && pen_n < 512)
        {
            CPUArchState *pen_env=cpu->env_ptr;

            fprintf(stderr,
                "[QEMU40PEN-ALIAS] "
                "N=%u CPU=%d PC=%08X END=%08X "
                "LOW=%06X THUMB=%u LR=%08X "
                "SHOOTOLC=%d TV=%d AV=%d\n",
                ++pen_n,
                cpu->cpu_index,
                pen_pc,
                pen_end,
                lo_pc,
                (unsigned)pen_env->thumb,
                (uint32_t)pen_env->regs[14],
                shootolc,tv,av);
        }
    }

    /*
     * QEMU40PEM-OLC-CPU-OWNERSHIP
     *
     * Passive CPU ownership probe, intentionally before the CPU0-only
     * diagnostics below. No guest state modification.
     */
    {
        static unsigned pem_n = 0;

        uint32_t pem_pc  = (uint32_t)tb->pc;
        uint32_t pem_end = pem_pc + (uint32_t)tb->size;

        int shootolc =
            pem_pc < 0xFE6E8200U &&
            pem_end > 0xFE6E7000U;

        int tv =
            pem_pc < 0xFE67B100U &&
            pem_end > 0xFE67A000U;

        int av =
            pem_pc < 0xFE675300U &&
            pem_end > 0xFE674800U;

        if ((shootolc || tv || av) && pem_n < 512)
        {
            CPUArchState *pem_env = cpu->env_ptr;

            fprintf(stderr,
                "[QEMU40PEM-CPU] N=%u CPU=%d "
                "TB=%08X-%08X THUMB=%u LR=%08X "
                "SHOOTOLC=%d TV=%d AV=%d\n",
                ++pem_n,
                cpu->cpu_index,
                pem_pc,
                pem_end,
                (unsigned)pem_env->thumb,
                (uint32_t)pem_env->regs[14],
                shootolc, tv, av);
        }
    }

    /* QEMU40PAD-BC-R20EA-DISPCTRL-DELIVERY */
    if (cpu->cpu_index == 0)
    {
        CPUArchState *env=cpu->env_ptr;

        static unsigned seq=0;
        static unsigned first_localset=0;
        static unsigned rearm=0;
        static unsigned post21_pending=0;
        static uint32_t post21_ctrl=0;
        static unsigned post21_lowtrace=0;
        static unsigned r20eg_dumped=0;
        static unsigned lowcode_dumped=0;

        uint32_t pc=(uint32_t)tb->pc;
        uint32_t end=pc+(uint32_t)tb->size;

#define R20EA_HIT(x) ((x)>=pc && (x)<end)
#define R20EA_LOG(fmt,...) fprintf(stderr, \
    "[QEMU40PAD-BC-R20EA] SEQ=%u " fmt "\n", \
    ++seq, ##__VA_ARGS__)


        /*
         * QEMU40PEI-TVAV-GETTER
         *
         * Passive 5D4 Tv/Av OLC getter probe.
         * Logging only. No guest memory/register/state modification.
         */
        {
            static unsigned pei_tv_helper = 0;
            static unsigned pei_tv_exit   = 0;
            static unsigned pei_tv_caller = 0;
            static unsigned pei_av_helper = 0;
            static unsigned pei_av_exit   = 0;

            uint32_t pei_sp = (uint32_t)env->regs[13];

            /*
             * Tv FE67ADE8:
             *   FE67AE02 BL helper
             *   FE67AE06 helper return
             */
            if (R20EA_HIT(0xFE67AE06U) &&
                pei_tv_helper < 32)
            {
                uint32_t outptr = (uint32_t)env->regs[7];
                uint32_t out = 0;
                uint32_t aux = 0;
                uint32_t key0 = 0;
                uint32_t key1 = 0;

                cpu_physical_memory_read(
                    pei_sp + 4U, &aux, 4);
                cpu_physical_memory_read(
                    pei_sp + 8U, &key0, 4);
                cpu_physical_memory_read(
                    pei_sp + 12U, &key1, 4);

                if (outptr)
                    cpu_physical_memory_read(
                        outptr, &out, 4);

                fprintf(stderr,
                    "[QEMU40PEI-TV-HELPER] "
                    "N=%u TB=%08X-%08X "
                    "R0=%08X OUTPTR=%08X OUT=%08X "
                    "AUX=%08X KEY0=%08X KEY1=%08X\n",
                    ++pei_tv_helper,
                    pc, end,
                    (uint32_t)env->regs[0],
                    outptr, out,
                    aux, key0, key1);
            }

            /*
             * Tv getter final decision.
             * r6 = return/status
             * r7 = output pointer
             * r4 = table index reached/matched
             */
            if (R20EA_HIT(0xFE67AE44U) &&
                pei_tv_exit < 32)
            {
                uint32_t outptr = (uint32_t)env->regs[7];
                uint32_t out = 0;

                if (outptr)
                    cpu_physical_memory_read(
                        outptr, &out, 4);

                fprintf(stderr,
                    "[QEMU40PEI-TV-EXIT] "
                    "N=%u TB=%08X-%08X "
                    "STATUS=%08X OUTPTR=%08X OUT=%08X "
                    "IDX=%u R8=%08X\n",
                    ++pei_tv_exit,
                    pc, end,
                    (uint32_t)env->regs[6],
                    outptr, out,
                    (unsigned)env->regs[4],
                    (uint32_t)env->regs[8]);
            }

            /*
             * Tv direct caller return:
             * FE67ABF8 BL FE67ADE8
             * FE67ABFC resumes with output at caller SP+28.
             */
            if (R20EA_HIT(0xFE67ABFCU) &&
                pei_tv_caller < 32)
            {
                uint32_t out = 0;

                cpu_physical_memory_read(
                    pei_sp + 28U, &out, 4);

                fprintf(stderr,
                    "[QEMU40PEI-TV-CALLER] "
                    "N=%u TB=%08X-%08X "
                    "RET=%08X OUT=%08X\n",
                    ++pei_tv_caller,
                    pc, end,
                    (uint32_t)env->regs[0],
                    out);
            }

            /*
             * Av FE675152:
             * FE67516C BL helper
             * FE675170 helper return
             */
            if (R20EA_HIT(0xFE675170U) &&
                pei_av_helper < 32)
            {
                uint32_t outptr = (uint32_t)env->regs[7];
                uint32_t out = 0;
                uint32_t aux = 0;
                uint32_t key0 = 0;
                uint32_t key1 = 0;

                cpu_physical_memory_read(
                    pei_sp + 4U, &aux, 4);
                cpu_physical_memory_read(
                    pei_sp + 8U, &key0, 4);
                cpu_physical_memory_read(
                    pei_sp + 12U, &key1, 4);

                if (outptr)
                    cpu_physical_memory_read(
                        outptr, &out, 4);

                fprintf(stderr,
                    "[QEMU40PEI-AV-HELPER] "
                    "N=%u TB=%08X-%08X "
                    "R0=%08X OUTPTR=%08X OUT=%08X "
                    "AUX=%08X KEY0=%08X KEY1=%08X\n",
                    ++pei_av_helper,
                    pc, end,
                    (uint32_t)env->regs[0],
                    outptr, out,
                    aux, key0, key1);
            }

            /*
             * Av getter final decision.
             */
            if (R20EA_HIT(0xFE6751AEU) &&
                pei_av_exit < 32)
            {
                uint32_t outptr = (uint32_t)env->regs[7];
                uint32_t out = 0;

                if (outptr)
                    cpu_physical_memory_read(
                        outptr, &out, 4);

                fprintf(stderr,
                    "[QEMU40PEI-AV-EXIT] "
                    "N=%u TB=%08X-%08X "
                    "STATUS=%08X OUTPTR=%08X OUT=%08X "
                    "IDX=%u R8=%08X\n",
                    ++pei_av_exit,
                    pc, end,
                    (uint32_t)env->regs[6],
                    outptr, out,
                    (unsigned)env->regs[4],
                    (uint32_t)env->regs[8]);
            }
        }


        /*
         * QEMU40PEJ-OLC-RANGE
         *
         * Passive execution census around the 5D4 shooting OLC
         * Tv / Av code regions. Logging only.
         */
        {
            static unsigned pej_tv_n=0;
            static unsigned pej_av_n=0;

            if (pc >= 0xFE67A000U &&
                pc <  0xFE67B100U &&
                pej_tv_n < 256)
            {
                fprintf(stderr,
                    "[QEMU40PEJ-TV-RANGE] "
                    "N=%u TB=%08X-%08X "
                    "LR=%08X R0=%08X R1=%08X "
                    "R2=%08X R3=%08X\n",
                    ++pej_tv_n,
                    pc,end,
                    (uint32_t)env->regs[14],
                    (uint32_t)env->regs[0],
                    (uint32_t)env->regs[1],
                    (uint32_t)env->regs[2],
                    (uint32_t)env->regs[3]);
            }

            if (pc >= 0xFE674800U &&
                pc <  0xFE675300U &&
                pej_av_n < 256)
            {
                fprintf(stderr,
                    "[QEMU40PEJ-AV-RANGE] "
                    "N=%u TB=%08X-%08X "
                    "LR=%08X R0=%08X R1=%08X "
                    "R2=%08X R3=%08X\n",
                    ++pej_av_n,
                    pc,end,
                    (uint32_t)env->regs[14],
                    (uint32_t)env->regs[0],
                    (uint32_t)env->regs[1],
                    (uint32_t)env->regs[2],
                    (uint32_t)env->regs[3]);
            }
        }


        /*
         * QEMU40PEL-SHOOTOLC-EVENT
         *
         * Passive 5D4 Shoot OLC lifecycle/event probe.
         * Logging only; no guest state modification.
         */
        {
            static unsigned n_start=0;
            static unsigned n_handler=0;
            static unsigned n_dispatch=0;
            static unsigned n_init_a=0;
            static unsigned n_init_b=0;
            static unsigned n_bulk=0;
            static unsigned n_tvinit=0;
            static unsigned n_avinit=0;

            if (R20EA_HIT(0xFE6E7A66U) && n_start < 16)
            {
                fprintf(stderr,
                    "[QEMU40PEL-START] N=%u "
                    "R0=%08X R1=%08X R2=%08X R3=%08X LR=%08X\n",
                    ++n_start,
                    (uint32_t)env->regs[0],
                    (uint32_t)env->regs[1],
                    (uint32_t)env->regs[2],
                    (uint32_t)env->regs[3],
                    (uint32_t)env->regs[14]);
            }

            /*
             * Function entry before the 8-register push.
             * Fifth argument is therefore at original SP+0.
             */
            if (R20EA_HIT(0xFE6E71CCU) && n_handler < 128)
            {
                uint32_t arg4=0;
                cpu_physical_memory_read(
                    (uint32_t)env->regs[13], &arg4, 4);

                fprintf(stderr,
                    "[QEMU40PEL-HANDLER] N=%u "
                    "R0=%08X R1=%08X EVENT_R2=%08X "
                    "R3=%08X ARG4=%08X LR=%08X\n",
                    ++n_handler,
                    (uint32_t)env->regs[0],
                    (uint32_t)env->regs[1],
                    (uint32_t)env->regs[2],
                    (uint32_t)env->regs[3],
                    arg4,
                    (uint32_t)env->regs[14]);
            }

            if (R20EA_HIT(0xFE6E72F8U) && n_dispatch < 128)
            {
                fprintf(stderr,
                    "[QEMU40PEL-DISPATCH] N=%u "
                    "EVENT_R4=%08X ARG_R5=%08X "
                    "R8=%08X R9=%08X\n",
                    ++n_dispatch,
                    (uint32_t)env->regs[4],
                    (uint32_t)env->regs[5],
                    (uint32_t)env->regs[8],
                    (uint32_t)env->regs[9]);
            }

            if (R20EA_HIT(0xFE6E70CAU) && n_init_a < 16)
            {
                fprintf(stderr,
                    "[QEMU40PEL-INIT-A] N=%u\n",
                    ++n_init_a);
            }

            if (R20EA_HIT(0xFE6E706CU) && n_init_b < 16)
            {
                fprintf(stderr,
                    "[QEMU40PEL-INIT-B] N=%u\n",
                    ++n_init_b);
            }

            if ((R20EA_HIT(0xFE6E7864U) ||
                 R20EA_HIT(0xFE6E7866U)) &&
                n_bulk < 32)
            {
                fprintf(stderr,
                    "[QEMU40PEL-BULK-UPDATE] N=%u PC=%08X\n",
                    ++n_bulk, pc);
            }

            if (R20EA_HIT(0xFE67ABCAU) && n_tvinit < 16)
            {
                fprintf(stderr,
                    "[QEMU40PEL-TV-INIT] N=%u\n",
                    ++n_tvinit);
            }

            if (R20EA_HIT(0xFE674EA6U) && n_avinit < 16)
            {
                fprintf(stderr,
                    "[QEMU40PEL-AV-INIT] N=%u\n",
                    ++n_avinit);
            }
        }

        /* QEMU40PBD — passive fRefreshDisplay writer probes.
         * No guest writes. Normal debugmsg execution only.
         */
        {
            static unsigned n_set1=0;
            static unsigned n_setarg=0;
            static unsigned n_clear=0;
            uint32_t f=0;

            if (R20EA_HIT(0xFE44DC70U) && n_set1 < 16)
            {
                cpu_physical_memory_read(0xFE0C,&f,4);
                fprintf(stderr,
                    "[QEMU40PBD] WRITER=SET1 N=%u TB=%08X-%08X R6=%08X ADDR=%08X FBEFORE=%08X\n",
                    ++n_set1,pc,end,
                    (uint32_t)env->regs[6],
                    (uint32_t)env->regs[6]+0x28U,f);
            }

            if (R20EA_HIT(0xFE44DB66U) && n_setarg < 16)
            {
                cpu_physical_memory_read(0xFE0C,&f,4);
                fprintf(stderr,
                    "[QEMU40PBD] WRITER=SETARG N=%u TB=%08X-%08X R0=%08X FBEFORE=%08X\n",
                    ++n_setarg,pc,end,
                    (uint32_t)env->regs[0],f);
            }

            if (R20EA_HIT(0xFE44D5C2U) && n_clear < 16)
            {
                cpu_physical_memory_read(0xFE0C,&f,4);
                fprintf(stderr,
                    "[QEMU40PBD] WRITER=CLEAR N=%u TB=%08X-%08X R4=%08X R8=%08X ADDR=%08X FBEFORE=%08X\n",
                    ++n_clear,pc,end,
                    (uint32_t)env->regs[4],
                    (uint32_t)env->regs[8],
                    (uint32_t)env->regs[4]+0x28U,f);
            }
        }

        /*
         * Exact R20DM-R2 validated one-shot rearm.
         * Do not alter this trigger while testing delivery.
         */
        if (0 && !rearm && first_localset && R20EA_HIT(0xFE44D3E2U))
        {
            uint32_t one=1,old=0;

            cpu_physical_memory_read(0xFE0C,&old,4);
            cpu_physical_memory_write(0xFE0C,&one,4);

            rearm=1;
            R20EA_LOG("ACTION=FREFRESH_REARM OLD=%08X",old);
        }

        /* QEMU40PAD-BC-R20EB-LOWRET */
        /* Producer side plus DispDCtrl/state snapshot. */
        if (rearm &&
            R20EA_HIT(0xFE1386B0U) &&
            (uint32_t)env->regs[2]==21U)
        {
            uint32_t disp=(uint32_t)env->regs[0];
            uint32_t ctrl=0,so=0,state=0;
            uint32_t c[4]={0};

            cpu_physical_memory_read(disp+4,&ctrl,4);
            cpu_physical_memory_read(disp+8,&so,4);

            if (so)
                cpu_physical_memory_read(so+0x1C,&state,4);

            if (ctrl)
                cpu_physical_memory_read(ctrl,c,sizeof(c));

            post21_ctrl=ctrl;
            post21_pending=1;
            post21_lowtrace=0;

            {
                static int r20el_dumped=0;
                if (!r20el_dumped)
                {
                    uint8_t b[16];
                    uint32_t a;
                    unsigned i;
                    r20el_dumped=1;

                    for (a=0x80000800; a<0x80000900; a+=16)
                    {
                        cpu_physical_memory_read(a,b,sizeof(b));
                        fprintf(stderr,"[R20EL] CODE=%08X",a);
                        for(i=0;i<16;i++) fprintf(stderr," %02X",b[i]);
                        fprintf(stderr,"\n");
                    }
                }
            }

            {
                static int r20ej_dumped=0;
                if (!r20ej_dumped)
                {
                    uint8_t b[16];
                    uint32_t a;
                    unsigned i;
                    r20ej_dumped=1;

                    for (a=0x80003A80; a<0x80003B80; a+=16)
                    {
                        cpu_physical_memory_read(a,b,sizeof(b));
                        fprintf(stderr,"[R20EJ] CODE=%08X",a);
                        for(i=0;i<16;i++) fprintf(stderr," %02X",b[i]);
                        fprintf(stderr,"\n");
                    }
                }
            }

            {
                static int r20ei_dumped=0;
                if (!r20ei_dumped)
                {
                    uint8_t b[16];
                    uint32_t a;
                    unsigned i;
                    r20ei_dumped=1;

                    for (a=0x800022C0; a<0x800023C0; a+=16)
                    {
                        cpu_physical_memory_read(a,b,sizeof(b));
                        fprintf(stderr,"[R20EI] CODE=%08X",a);
                        for(i=0;i<16;i++) fprintf(stderr," %02X",b[i]);
                        fprintf(stderr,"\n");
                    }
                }
            }

            /* QEMU40PAD-BC-R20EG-1734 CODE DUMP */
            if (!r20eg_dumped)
            {
                uint8_t b[16];
                uint32_t a;
                unsigned i;

                r20eg_dumped=1;

                for (a=0x000016C0; a<0x000017C0; a+=16)
                {
                    cpu_physical_memory_read(a,b,sizeof(b));

                    fprintf(stderr,
                        "[QEMU40PAD-BC-R20EG] CODE=%08X",a);

                    for (i=0;i<sizeof(b);i++)
                        fprintf(stderr," %02X",b[i]);

                    fprintf(stderr,"\n");
                }
            }

            /* QEMU40PAD-BC-R20ED-CODE-DUMP */
            if (!lowcode_dumped)
            {
                uint8_t b[16];
                uint32_t a;
                unsigned i;

                lowcode_dumped=1;

                for (a=0x00001D80; a<0x00001E80; a+=16)
                {
                    cpu_physical_memory_read(a,b,sizeof(b));

                    fprintf(stderr,
                        "[QEMU40PAD-BC-R20EE] CODE=%08X",a);

                    for (i=0;i<sizeof(b);i++)
                        fprintf(stderr," %02X",b[i]);

                    fprintf(stderr,"\n");
                }

                for (a=0x00002200; a<0x00002280; a+=16)
                {
                    cpu_physical_memory_read(a,b,sizeof(b));

                    fprintf(stderr,
                        "[QEMU40PAD-BC-R20ED] CODE=%08X",a);

                    for (i=0;i<sizeof(b);i++)
                        fprintf(stderr," %02X",b[i]);

                    fprintf(stderr,"\\n");
                }

                for (a=0x00002350; a<0x000023B0; a+=16)
                {
                    cpu_physical_memory_read(a,b,sizeof(b));

                    fprintf(stderr,
                        "[QEMU40PAD-BC-R20ED] CODE=%08X",a);

                    for (i=0;i<sizeof(b);i++)
                        fprintf(stderr," %02X",b[i]);

                    fprintf(stderr,"\\n");
                }
            }

            R20EA_LOG(
                "TARGET=POST21 R0=%08X R1=%08X R2=%08X "
                "R3=%08X LR=%08X CTRL=%08X SO=%08X STATE=%u "
                "C0=%08X C1=%08X C2=%08X C3=%08X",
                disp,
                (uint32_t)env->regs[1],
                (uint32_t)env->regs[2],
                (uint32_t)env->regs[3],
                (uint32_t)env->regs[14],
                ctrl,so,state,c[0],c[1],c[2],c[3]);
        }

        /* QEMU40PAD-BC-R20EG-1734 */
        if (rearm && post21_pending &&
            pc < 0x000017C0U &&
            end > 0x000016C0U)
        {
            R20EA_LOG(
                "TARGET=WAKE1734 PC=%08X SIZE=%u "
                "LR=%08X R0=%08X R1=%08X R2=%08X R3=%08X "
                "R4=%08X R5=%08X R6=%08X R7=%08X SP=%08X",
                pc,
                (unsigned)tb->size,
                (uint32_t)env->regs[14],
                (uint32_t)env->regs[0],
                (uint32_t)env->regs[1],
                (uint32_t)env->regs[2],
                (uint32_t)env->regs[3],
                (uint32_t)env->regs[4],
                (uint32_t)env->regs[5],
                (uint32_t)env->regs[6],
                (uint32_t)env->regs[7],
                (uint32_t)env->regs[13]);
        }

        /* QEMU40PAD-BC-R20EH-TCM-WAKE */
        if (0 && rearm && post21_pending &&
            pc < 0x800023C0U &&
            end > 0x800022C0U)
        {
            R20EA_LOG(
                "TARGET=TCMWAKE PC=%08X SIZE=%u "
                "LR=%08X R0=%08X R1=%08X R2=%08X R3=%08X "
                "R4=%08X R5=%08X R6=%08X R7=%08X SP=%08X",
                pc,(unsigned)tb->size,
                (uint32_t)env->regs[14],
                (uint32_t)env->regs[0],
                (uint32_t)env->regs[1],
                (uint32_t)env->regs[2],
                (uint32_t)env->regs[3],
                (uint32_t)env->regs[4],
                (uint32_t)env->regs[5],
                (uint32_t)env->regs[6],
                (uint32_t)env->regs[7],
                (uint32_t)env->regs[13]);
        }

        /* QEMU40PAD-BC-R20EK-80003ACC */
        if (0 && rearm && post21_pending)
        {
            if ((pc >= 0x80003A80U && pc < 0x80003B80U) ||
                pc == 0x80002378U || pc == 0x8000237CU)
            {
                R20EA_LOG(
                    "TARGET=WAKE3ACC PC=%08X SIZE=%u LR=%08X "
                    "R0=%08X R1=%08X R2=%08X R3=%08X "
                    "R4=%08X R5=%08X R6=%08X R7=%08X SP=%08X",
                    pc,(unsigned)tb->size,
                    (uint32_t)env->regs[14],
                    (uint32_t)env->regs[0],
                    (uint32_t)env->regs[1],
                    (uint32_t)env->regs[2],
                    (uint32_t)env->regs[3],
                    (uint32_t)env->regs[4],
                    (uint32_t)env->regs[5],
                    (uint32_t)env->regs[6],
                    (uint32_t)env->regs[7],
                    (uint32_t)env->regs[13]);
            }
        }

        /* QEMU40PAD-BC-R20EL-0880 */
        if (0 && rearm && post21_pending &&
            (pc == 0x80003B12U ||
             pc == 0x80000880U ||
             pc == 0x80003B16U))
        {
            R20EA_LOG(
                "TARGET=WAKE0880 PC=%08X SIZE=%u LR=%08X "
                "R0=%08X R1=%08X R2=%08X R3=%08X "
                "R4=%08X R5=%08X R6=%08X R7=%08X SP=%08X",
                pc,(unsigned)tb->size,
                (uint32_t)env->regs[14],
                (uint32_t)env->regs[0],
                (uint32_t)env->regs[1],
                (uint32_t)env->regs[2],
                (uint32_t)env->regs[3],
                (uint32_t)env->regs[4],
                (uint32_t)env->regs[5],
                (uint32_t)env->regs[6],
                (uint32_t)env->regs[7],
                (uint32_t)env->regs[13]);
        }

        /* QEMU40PAD-BC-R20EM-SPARSE */
        if (0 && rearm && post21_pending &&
            (pc == 0x80002336U ||
             pc == 0x80002350U ||
             pc == 0x80002378U ||
             pc == 0x80003ACCU ||
             pc == 0x80003B12U))
        {
            R20EA_LOG(
                "TARGET=WAKECHAIN PC=%08X LR=%08X "
                "R0=%08X R1=%08X R2=%08X R3=%08X SP=%08X",
                pc,
                (uint32_t)env->regs[14],
                (uint32_t)env->regs[0],
                (uint32_t)env->regs[1],
                (uint32_t)env->regs[2],
                (uint32_t)env->regs[3],
                (uint32_t)env->regs[13]);
        }

        /* QEMU40PAD-BC-R20EN-3ACC-BRANCH */
        if (0 && rearm && post21_pending &&
            (pc == 0x80003ACCU ||
             pc == 0x80003AD8U ||
             pc == 0x80003AE0U ||
             pc == 0x80003AF0U ||
             pc == 0x80003AFEU ||
             pc == 0x80003B08U ||
             pc == 0x80003B12U))
        {
            R20EA_LOG(
                "TARGET=BRANCH3ACC PC=%08X LR=%08X "
                "R0=%08X R1=%08X R2=%08X R3=%08X "
                "R4=%08X R5=%08X R6=%08X R7=%08X SP=%08X",
                pc,
                (uint32_t)env->regs[14],
                (uint32_t)env->regs[0],
                (uint32_t)env->regs[1],
                (uint32_t)env->regs[2],
                (uint32_t)env->regs[3],
                (uint32_t)env->regs[4],
                (uint32_t)env->regs[5],
                (uint32_t)env->regs[6],
                (uint32_t)env->regs[7],
                (uint32_t)env->regs[13]);
        }

        /* QEMU40PAD-BC-R20EO-WATCH */
        if (0)
        {
            static int r20eo_init=0;
            static uint16_t r20eo_old=0;
            uint16_t v=0;

            cpu_physical_memory_read(0x002E6C00U,&v,sizeof(v));

            if (!r20eo_init)
            {
                r20eo_old=v;
                r20eo_init=1;
            }
            else if (v != r20eo_old)
            {
                R20EA_LOG(
                    "TARGET=STATE2E6C00 PC=%08X LR=%08X "
                    "OLD=%04X NEW=%04X "
                    "R0=%08X R1=%08X R2=%08X R3=%08X SP=%08X",
                    pc,
                    (uint32_t)env->regs[14],
                    (unsigned)r20eo_old,
                    (unsigned)v,
                    (uint32_t)env->regs[0],
                    (uint32_t)env->regs[1],
                    (uint32_t)env->regs[2],
                    (uint32_t)env->regs[3],
                    (uint32_t)env->regs[13]);

                r20eo_old=v;
            }
        }

        /* QEMU40PAD-BC-R20EP-DEFERRED */
        if (0 && rearm && post21_pending &&
            (pc == 0x80003AD6U ||
             pc == 0x80003ADEU ||
             pc == 0x80003B18U ||
             pc == 0x80003B1CU ||
             pc == 0x80003B20U ||
             pc == 0x80003B2AU ||
             pc == 0x80003A80U ||
             pc == 0x80003B2EU))
        {
            uint16_t active=0, limit=0, queued=0;
            uint32_t base=(uint32_t)env->regs[4];

            if (base)
            {
                cpu_physical_memory_read(base+0x0C,&active,2);
                cpu_physical_memory_read(base+0x10,&limit,2);
                cpu_physical_memory_read(base+0x12,&queued,2);
            }

            R20EA_LOG(
                "TARGET=DEFERWAKE PC=%08X LR=%08X "
                "BASE=%08X ACTIVE=%04X LIMIT=%04X QUEUED=%04X "
                "R0=%08X R1=%08X R2=%08X R3=%08X SP=%08X",
                pc,
                (uint32_t)env->regs[14],
                base,
                (unsigned)active,
                (unsigned)limit,
                (unsigned)queued,
                (uint32_t)env->regs[0],
                (uint32_t)env->regs[1],
                (uint32_t)env->regs[2],
                (uint32_t)env->regs[3],
                (uint32_t)env->regs[13]);
        }

        /* QEMU40PAD-BC-R20FG-ACTIVE */
        if (0)
        {
            static unsigned prod_n=0;
            static unsigned disp_n=0;

            uint32_t pcl = pc & 0x7FFFFFFFU;

            /*
             * Independent proof that this diagnostic block is alive.
             * R20FA established dispatcher target handle 0x02330062.
             */
            if (pc == 0x800022ECU &&
                (uint32_t)env->regs[0] == 0x02330062U &&
                disp_n < 32)
            {
                R20EA_LOG(
                    "TARGET=FG_DISPATCH N=%u "
                    "HANDLE=%08X R1=%08X R2=%08X R3=%08X "
                    "LR=%08X SP=%08X",
                    disp_n,
                    (uint32_t)env->regs[0],
                    (uint32_t)env->regs[1],
                    (uint32_t)env->regs[2],
                    (uint32_t)env->regs[3],
                    (uint32_t)env->regs[14],
                    (uint32_t)env->regs[13]);

                disp_n++;
            }

            /*
             * R20FD shows the dispatcher BL returns at 0x1D05.
             * Immediately before it:
             *   1CFC: lsrs r0,r4,#1
             * therefore test both low/high TCM aliases.
             */
            if ((pcl == 0x00001CFCU ||
                 pcl == 0x00001D00U) &&
                (((uint32_t)env->regs[4] >> 1) == 0x02330062U) &&
                prod_n < 32)
            {
                R20EA_LOG(
                    "TARGET=FG_PRODUCER N=%u "
                    "PC=%08X PCLOW=%08X "
                    "R4=%08X HANDLE=%08X "
                    "R5=%08X R6=%08X "
                    "R0=%08X R1=%08X R2=%08X R3=%08X "
                    "LR=%08X SP=%08X",
                    prod_n,
                    pc,
                    pcl,
                    (uint32_t)env->regs[4],
                    ((uint32_t)env->regs[4] >> 1),
                    (uint32_t)env->regs[5],
                    (uint32_t)env->regs[6],
                    (uint32_t)env->regs[0],
                    (uint32_t)env->regs[1],
                    (uint32_t)env->regs[2],
                    (uint32_t)env->regs[3],
                    (uint32_t)env->regs[14],
                    (uint32_t)env->regs[13]);

                prod_n++;
            }
        }

        /* QEMU40PAD-BC-R20FH-POSTCRIT */
        if (0)
        {
            static int critical=0;
            static unsigned prod_n=0;
            static unsigned disp_n=0;
            static unsigned any_prod_n=0;

            const uint32_t obj=0x002E6BF4U;
            const uint32_t target=0x02330062U;

            uint32_t pcl=pc & 0x7FFFFFFFU;

            if (!critical &&
                pc == 0x80003B2EU &&
                (uint32_t)env->regs[4] == obj)
            {
                uint16_t a=0,q=0,w=0,r=0;

                cpu_physical_memory_read(obj+0x0C,&a,2);
                cpu_physical_memory_read(obj+0x12,&q,2);
                cpu_physical_memory_read(obj+0x18,&w,2);
                cpu_physical_memory_read(obj+0x1A,&r,2);

                if (a == 0 && q == 1 && w == 4 && r == 3)
                {
                    critical=1;

                    R20EA_LOG(
                        "TARGET=FH_CRITICAL "
                        "ACTIVE=%04X QUEUED=%04X "
                        "W18=%04X R1A=%04X",
                        (unsigned)a,
                        (unsigned)q,
                        (unsigned)w,
                        (unsigned)r);
                }
            }

            /*
             * Observe every producer invocation after the critical
             * state. At 1D00 R0 already contains R4 >> 1.
             */
            if (critical &&
                pcl == 0x00001D00U &&
                any_prod_n < 32)
            {
                uint32_t h=((uint32_t)env->regs[4] >> 1);

                R20EA_LOG(
                    "TARGET=FH_ANY_PRODUCER N=%u "
                    "RAW=%08X HANDLE=%08X TARGET=%d "
                    "R5=%08X R6=%08X "
                    "R0=%08X R1=%08X LR=%08X SP=%08X",
                    any_prod_n,
                    (uint32_t)env->regs[4],
                    h,
                    h == target,
                    (uint32_t)env->regs[5],
                    (uint32_t)env->regs[6],
                    (uint32_t)env->regs[0],
                    (uint32_t)env->regs[1],
                    (uint32_t)env->regs[14],
                    (uint32_t)env->regs[13]);

                any_prod_n++;

                if (h == target)
                    prod_n++;
            }

            if (critical &&
                pc == 0x800022ECU &&
                disp_n < 32)
            {
                R20EA_LOG(
                    "TARGET=FH_DISPATCH N=%u "
                    "HANDLE=%08X TARGET=%d "
                    "R1=%08X LR=%08X SP=%08X",
                    disp_n,
                    (uint32_t)env->regs[0],
                    (uint32_t)env->regs[0] == target,
                    (uint32_t)env->regs[1],
                    (uint32_t)env->regs[14],
                    (uint32_t)env->regs[13]);

                disp_n++;
            }
        }

        /* QEMU40PAD-BC-R20FI-CONTEXT */
        if (0)
        {
            static int captured=0;
            static int critical=0;
            static uint32_t ctx=0;

            uint32_t pcl=pc & 0x7FFFFFFFU;
            const uint32_t obj=0x002E6BF4U;

#define FI_DUMP_MEM(label,base) do {                         \
                uint8_t b_[16];                              \
                uint32_t a_;                                 \
                unsigned i_;                                 \
                for (a_=(base)-0x50; a_<(base)+0x90; a_+=16)\
                {                                            \
                    cpu_physical_memory_read(a_,b_,16);       \
                    fprintf(stderr,"[R20FI] %s %08X",label,a_);\
                    for(i_=0;i_<16;i_++)                      \
                        fprintf(stderr," %02X",b_[i_]);       \
                    fprintf(stderr,"\n");                     \
                }                                            \
            } while(0)

            /*
             * First confirmed DispDCtrl producer.
             */
            if (!captured &&
                pcl == 0x00001D00U &&
                ((uint32_t)env->regs[4] >> 1) == 0x02330062U)
            {
                uint8_t b[16];
                uint32_t a;
                unsigned i;

                captured=1;
                ctx=(uint32_t)env->regs[5];

                R20EA_LOG(
                    "TARGET=FI_PRE "
                    "CTX=%08X RAW=%08X HANDLE=%08X "
                    "R6=%08X SP=%08X",
                    ctx,
                    (uint32_t)env->regs[4],
                    ((uint32_t)env->regs[4] >> 1),
                    (uint32_t)env->regs[6],
                    (uint32_t)env->regs[13]);

                FI_DUMP_MEM("PRE",ctx);

                /*
                 * Earlier part of the producer/selection function.
                 */
                for(a=0x00001B80U;a<0x00001CC0U;a+=16)
                {
                    cpu_physical_memory_read(a,b,16);
                    fprintf(stderr,"[R20FI] CODE %08X",a);

                    for(i=0;i<16;i++)
                        fprintf(stderr," %02X",b[i]);

                    fprintf(stderr,"\n");
                }
            }

            /*
             * Exact known-bad queue state.
             */
            if (captured &&
                !critical &&
                pc == 0x80003B2EU &&
                (uint32_t)env->regs[4] == obj)
            {
                uint16_t active=0,q=0,w=0,r=0;

                cpu_physical_memory_read(obj+0x0C,&active,2);
                cpu_physical_memory_read(obj+0x12,&q,2);
                cpu_physical_memory_read(obj+0x18,&w,2);
                cpu_physical_memory_read(obj+0x1A,&r,2);

                if (active==0 && q==1 && w==4 && r==3)
                {
                    critical=1;

                    R20EA_LOG(
                        "TARGET=FI_CRITICAL "
                        "CTX=%08X ACTIVE=%04X QUEUED=%04X "
                        "W18=%04X R1A=%04X",
                        ctx,
                        active,q,w,r);

                    FI_DUMP_MEM("POST",ctx);
                }
            }

#undef FI_DUMP_MEM
        }

        /* QEMU40PAD-BC-R20FJ-CALLER */
        if (0)
        {
            static int critical=0;
            static int target_pre_seen=0;
            static unsigned post_n=0;

            const uint32_t obj=0x002E6BF4U;
            const uint32_t target_raw=0x046600C4U;
            const uint32_t target_ctx=0x00350750U;

            uint32_t pcl=pc & 0x7FFFFFFFU;

            /*
             * Entry of function at 0x1CA0:
             * R0 = raw encoded handle
             * R1 = context
             * R2 = auxiliary argument
             * LR = ORIGINAL CALLER
             */
            if (pcl == 0x00001CA0U &&
                !target_pre_seen &&
                (uint32_t)env->regs[0] == target_raw &&
                (uint32_t)env->regs[1] == target_ctx)
            {
                target_pre_seen=1;

                R20EA_LOG(
                    "TARGET=FJ_TARGET_ENTRY "
                    "R0=%08X R1=%08X R2=%08X R3=%08X "
                    "LR=%08X SP=%08X",
                    (uint32_t)env->regs[0],
                    (uint32_t)env->regs[1],
                    (uint32_t)env->regs[2],
                    (uint32_t)env->regs[3],
                    (uint32_t)env->regs[14],
                    (uint32_t)env->regs[13]);
            }

            if (!critical &&
                pc == 0x80003B2EU &&
                (uint32_t)env->regs[4] == obj)
            {
                uint16_t a=0,q=0,w=0,r=0;

                cpu_physical_memory_read(obj+0x0C,&a,2);
                cpu_physical_memory_read(obj+0x12,&q,2);
                cpu_physical_memory_read(obj+0x18,&w,2);
                cpu_physical_memory_read(obj+0x1A,&r,2);

                if (a==0 && q==1 && w==4 && r==3)
                {
                    critical=1;

                    R20EA_LOG(
                        "TARGET=FJ_CRITICAL "
                        "ACTIVE=%04X QUEUED=%04X "
                        "W18=%04X R1A=%04X",
                        a,q,w,r);
                }
            }

            /*
             * Record all later calls to 0x1CA0.
             * This tells us which callers/contexts remain runnable.
             */
            if (critical &&
                pcl == 0x00001CA0U &&
                post_n < 32)
            {
                R20EA_LOG(
                    "TARGET=FJ_POST_ENTRY N=%u "
                    "R0=%08X HANDLE=%08X "
                    "R1=%08X R2=%08X R3=%08X "
                    "ISTARGET=%d LR=%08X SP=%08X",
                    post_n,
                    (uint32_t)env->regs[0],
                    ((uint32_t)env->regs[0] >> 1),
                    (uint32_t)env->regs[1],
                    (uint32_t)env->regs[2],
                    (uint32_t)env->regs[3],
                    ((uint32_t)env->regs[0] == target_raw &&
                     (uint32_t)env->regs[1] == target_ctx),
                    (uint32_t)env->regs[14],
                    (uint32_t)env->regs[13]);

                post_n++;
            }
        }

        /* QEMU40PAD-BC-R20FK-CALLSITE */
        if (0)
        {
            static int dumped=0;
            static int critical=0;
            static unsigned post_n=0;

            const uint32_t obj=0x002E6BF4U;
            const uint32_t target_raw=0x046600C4U;
            const uint32_t target_ctx=0x00350750U;

            uint32_t pcl=pc & 0x7FFFFFFFU;

            /*
             * LR=0x2213 at 0x1CA0 means the 32-bit Thumb BL
             * begins at 0x220E and returns to 0x2212|1.
             */
            if (!dumped && pcl == 0x0000220EU)
            {
                uint8_t b[16];
                uint32_t a;
                unsigned i;

                dumped=1;

                R20EA_LOG(
                    "TARGET=FK_CALLSITE_PRE "
                    "R0=%08X R1=%08X R2=%08X R3=%08X "
                    "R4=%08X R5=%08X R6=%08X R7=%08X "
                    "LR=%08X SP=%08X",
                    (uint32_t)env->regs[0],
                    (uint32_t)env->regs[1],
                    (uint32_t)env->regs[2],
                    (uint32_t)env->regs[3],
                    (uint32_t)env->regs[4],
                    (uint32_t)env->regs[5],
                    (uint32_t)env->regs[6],
                    (uint32_t)env->regs[7],
                    (uint32_t)env->regs[14],
                    (uint32_t)env->regs[13]);

                for (a=0x00002180U; a<0x00002250U; a+=16)
                {
                    cpu_physical_memory_read(a,b,16);

                    fprintf(stderr,"[R20FK] CODE=%08X",a);

                    for(i=0;i<16;i++)
                        fprintf(stderr," %02X",b[i]);

                    fprintf(stderr,"\n");
                }
            }

            if (!critical &&
                pc == 0x80003B2EU &&
                (uint32_t)env->regs[4] == obj)
            {
                uint16_t active=0,q=0,w=0,r=0;

                cpu_physical_memory_read(obj+0x0C,&active,2);
                cpu_physical_memory_read(obj+0x12,&q,2);
                cpu_physical_memory_read(obj+0x18,&w,2);
                cpu_physical_memory_read(obj+0x1A,&r,2);

                if (active==0 && q==1 && w==4 && r==3)
                {
                    critical=1;

                    R20EA_LOG(
                        "TARGET=FK_CRITICAL "
                        "ACTIVE=%04X QUEUED=%04X "
                        "W18=%04X R1A=%04X",
                        active,q,w,r);
                }
            }

            /*
             * Observe this exact call site after the critical state.
             * R0/R1 are the arguments about to be passed to 0x1CA0.
             */
            if (critical &&
                pcl == 0x0000220EU &&
                post_n < 32)
            {
                R20EA_LOG(
                    "TARGET=FK_POST_CALL N=%u "
                    "R0=%08X HANDLE=%08X "
                    "R1=%08X R2=%08X R3=%08X "
                    "ISTARGET=%d LR=%08X SP=%08X",
                    post_n,
                    (uint32_t)env->regs[0],
                    ((uint32_t)env->regs[0] >> 1),
                    (uint32_t)env->regs[1],
                    (uint32_t)env->regs[2],
                    (uint32_t)env->regs[3],
                    ((uint32_t)env->regs[0] == target_raw &&
                     (uint32_t)env->regs[1] == target_ctx),
                    (uint32_t)env->regs[14],
                    (uint32_t)env->regs[13]);

                post_n++;
            }
        }

        /* QEMU40PAD-BC-R20FL-WRAPPER */
        if (0)
        {
            static int critical=0;
            static int target_seen=0;
            static uint32_t target_obj=0;
            static unsigned post_n=0;
            static int dump_done=0;

            const uint32_t qobj=0x002E6BF4U;
            const uint32_t target_raw=0x046600C4U;

            uint32_t pcl=pc & 0x7FFFFFFFU;

            /*
             * Wrapper entry 0x21E8.
             * It later executes:
             *   ldr r0,[r0,#0x10]
             *   mov r1,sp
             *   bl  0x1CA0
             *
             * So R0 here is the object that owns the encoded handle.
             */
            if (pcl == 0x000021E8U)
            {
                uint32_t obj=(uint32_t)env->regs[0];
                uint32_t raw=0;

                if (obj)
                    cpu_physical_memory_read(obj+0x10,&raw,4);

                if (!target_seen && raw == target_raw)
                {
                    target_seen=1;
                    target_obj=obj;

                    R20EA_LOG(
                        "TARGET=FL_TARGET_WRAPPER "
                        "OBJ=%08X FIELD10=%08X "
                        "R1=%08X R2=%08X R3=%08X "
                        "LR=%08X SP=%08X",
                        obj,raw,
                        (uint32_t)env->regs[1],
                        (uint32_t)env->regs[2],
                        (uint32_t)env->regs[3],
                        (uint32_t)env->regs[14],
                        (uint32_t)env->regs[13]);
                }
            }

            if (!dump_done &&
                pcl == 0x000021E8U)
            {
                uint8_t b[16];
                uint32_t obj=(uint32_t)env->regs[0];
                uint32_t raw=0;
                uint32_t a;
                unsigned i;

                if (obj)
                    cpu_physical_memory_read(obj+0x10,&raw,4);

                if (raw == target_raw)
                {
                    dump_done=1;

                    for (a=0x00002230U; a<0x00002300U; a+=16)
                    {
                        cpu_physical_memory_read(a,b,16);

                        fprintf(stderr,"[R20FL] CODE=%08X",a);

                        for(i=0;i<16;i++)
                            fprintf(stderr," %02X",b[i]);

                        fprintf(stderr,"\n");
                    }
                }
            }

            if (!critical &&
                pc == 0x80003B2EU &&
                (uint32_t)env->regs[4] == qobj)
            {
                uint16_t active=0,q=0,w=0,r=0;

                cpu_physical_memory_read(qobj+0x0C,&active,2);
                cpu_physical_memory_read(qobj+0x12,&q,2);
                cpu_physical_memory_read(qobj+0x18,&w,2);
                cpu_physical_memory_read(qobj+0x1A,&r,2);

                if (active==0 && q==1 && w==4 && r==3)
                {
                    critical=1;

                    R20EA_LOG(
                        "TARGET=FL_CRITICAL "
                        "TARGETOBJ=%08X ACTIVE=%04X "
                        "QUEUED=%04X W18=%04X R1A=%04X",
                        target_obj,active,q,w,r);
                }
            }

            /*
             * Which objects continue to enter the wrapper after the stall?
             */
            if (critical &&
                pcl == 0x000021E8U &&
                post_n < 32)
            {
                uint32_t obj=(uint32_t)env->regs[0];
                uint32_t raw=0;

                if (obj)
                    cpu_physical_memory_read(obj+0x10,&raw,4);

                R20EA_LOG(
                    "TARGET=FL_POST_WRAPPER N=%u "
                    "OBJ=%08X FIELD10=%08X "
                    "ISTARGET=%d LR=%08X SP=%08X",
                    post_n,
                    obj,
                    raw,
                    (obj == target_obj && raw == target_raw),
                    (uint32_t)env->regs[14],
                    (uint32_t)env->regs[13]);

                post_n++;
            }
        }

        /* QEMU40PAD-BC-R20FM-CALLER */
        if (0)
        {
            static int critical=0;
            static int pre=0;
            static unsigned post=0;

            const uint32_t qobj=0x002E6BF4U;
            const uint32_t target=0x00AB7B58U;
            uint32_t pcl=pc & 0x7FFFFFFFU;

            /* Entry of function 0x223A: R0 is the object. */
            if (!pre &&
                pcl == 0x0000223AU &&
                (uint32_t)env->regs[0] == target)
            {
                uint32_t f8=0,f10=0,f14=0;

                cpu_physical_memory_read(target+0x08,&f8,4);
                cpu_physical_memory_read(target+0x10,&f10,4);
                cpu_physical_memory_read(target+0x14,&f14,4);

                pre=1;

                R20EA_LOG(
                    "TARGET=FM_TARGET_ENTRY "
                    "OBJ=%08X F8=%08X F10=%08X F14=%08X "
                    "R1=%08X R2=%08X R3=%08X "
                    "LR=%08X SP=%08X",
                    target,f8,f10,f14,
                    (uint32_t)env->regs[1],
                    (uint32_t)env->regs[2],
                    (uint32_t)env->regs[3],
                    (uint32_t)env->regs[14],
                    (uint32_t)env->regs[13]);
            }

            if (!critical &&
                pc == 0x80003B2EU &&
                (uint32_t)env->regs[4] == qobj)
            {
                uint16_t a=0,q=0,w=0,r=0;

                cpu_physical_memory_read(qobj+0x0C,&a,2);
                cpu_physical_memory_read(qobj+0x12,&q,2);
                cpu_physical_memory_read(qobj+0x18,&w,2);
                cpu_physical_memory_read(qobj+0x1A,&r,2);

                if (a==0 && q==1 && w==4 && r==3)
                {
                    uint32_t f8=0,f10=0,f14=0;

                    cpu_physical_memory_read(target+0x08,&f8,4);
                    cpu_physical_memory_read(target+0x10,&f10,4);
                    cpu_physical_memory_read(target+0x14,&f14,4);

                    critical=1;

                    R20EA_LOG(
                        "TARGET=FM_CRITICAL "
                        "F8=%08X F10=%08X F14=%08X "
                        "ACTIVE=%04X QUEUED=%04X W18=%04X R1A=%04X",
                        f8,f10,f14,a,q,w,r);
                }
            }

            /* All calls to 0x223A after the critical state. */
            if (critical &&
                pcl == 0x0000223AU &&
                post < 32)
            {
                uint32_t o=(uint32_t)env->regs[0];

                R20EA_LOG(
                    "TARGET=FM_POST_ENTRY N=%u "
                    "OBJ=%08X ISTARGET=%d "
                    "LR=%08X SP=%08X",
                    post,o,o==target,
                    (uint32_t)env->regs[14],
                    (uint32_t)env->regs[13]);

                post++;
            }
        }

        /* QEMU40PAD-BC-R20FN-SAVED-LR */
        if (0)
        {
            static int done=0;

            const uint32_t target_obj=0x00AB7B58U;
            const uint32_t target_raw=0x046600C4U;

            uint32_t pcl=pc & 0x7FFFFFFFU;

            /*
             * Reliable wrapper entry.
             * Caller function:
             *   223A push {r4,r5,lr}
             *   223C sub sp,#0x1c
             *
             * Therefore original saved LR is at current SP+0x24.
             */
            if (!done &&
                pcl == 0x000021E8U &&
                (uint32_t)env->regs[0] == target_obj)
            {
                uint32_t sp=(uint32_t)env->regs[13];
                uint32_t saved_lr=0;
                uint32_t raw=0;

                cpu_physical_memory_read(sp+0x24,&saved_lr,4);
                cpu_physical_memory_read(target_obj+0x10,&raw,4);

                if (raw == target_raw)
                {
                    uint8_t b[16];
                    uint32_t base;
                    uint32_t a;
                    unsigned i;

                    done=1;

                    R20EA_LOG(
                        "TARGET=FN_TARGET "
                        "OBJ=%08X RAW=%08X "
                        "WRAPPER_LR=%08X "
                        "SAVED_LR=%08X "
                        "SP=%08X SAVED_AT=%08X",
                        target_obj,
                        raw,
                        (uint32_t)env->regs[14],
                        saved_lr,
                        sp,
                        sp+0x24);

                    /*
                     * Thumb LR bit0 is set. Dump around real return
                     * address with bit0 removed.
                     */
                    base=(saved_lr & ~1U);

                    if (base >= 0x80)
                    {
                        base=(base-0x80U) & ~0xFU;

                        for(a=base;a<base+0x120U;a+=16)
                        {
                            cpu_physical_memory_read(a,b,16);

                            fprintf(stderr,
                                    "[R20FN] CALLER_CODE=%08X",a);

                            for(i=0;i<16;i++)
                                fprintf(stderr," %02X",b[i]);

                            fprintf(stderr,"\n");
                        }
                    }
                }
            }
        }

        /* QEMU40PAD-BC-R20FO-DYNAMIC */
        if (0)
        {
            static int done=0;
            const uint32_t target_raw=0x046600C4U;

            uint32_t pcl=pc & 0x7FFFFFFFU;

            if (!done && pcl == 0x000021E8U)
            {
                uint32_t obj=(uint32_t)env->regs[0];
                uint32_t raw=0;

                if (obj)
                    cpu_physical_memory_read(obj+0x10,&raw,4);

                if (raw == target_raw)
                {
                    uint32_t sp=(uint32_t)env->regs[13];
                    uint32_t saved_lr=0;
                    uint32_t base;
                    uint8_t b[16];
                    uint32_t a;
                    unsigned i;

                    done=1;

                    /*
                     * Caller frame at 0x223A:
                     * push {r4,r5,lr}  -> 12 bytes
                     * sub  sp,#0x1c   -> 28 bytes
                     * total = 0x28 bytes.
                     *
                     * Saved LR is at caller frame offset +0x24
                     * from the SP visible inside 0x21E8.
                     */
                    cpu_physical_memory_read(sp+0x24,&saved_lr,4);

                    R20EA_LOG(
                        "TARGET=FO_TARGET "
                        "OBJ=%08X RAW=%08X "
                        "WRAPPER_LR=%08X "
                        "SAVED_LR=%08X "
                        "SP=%08X SAVED_AT=%08X",
                        obj,
                        raw,
                        (uint32_t)env->regs[14],
                        saved_lr,
                        sp,
                        sp+0x24);

                    base=(saved_lr & ~1U);

                    if (base >= 0x100U)
                    {
                        base=(base-0x80U) & ~0xFU;

                        for(a=base;a<base+0x120U;a+=16)
                        {
                            cpu_physical_memory_read(a,b,16);

                            fprintf(stderr,
                                    "[R20FO] CALLER_CODE=%08X",a);

                            for(i=0;i<16;i++)
                                fprintf(stderr," %02X",b[i]);

                            fprintf(stderr,"\n");
                        }
                    }
                }
            }
        }

        /* QEMU40PAD-BC-R20FP-SCHED */
        if (0)
        {
            static int target_seen=0;
            static int critical=0;
            static uint32_t target_rec=0;
            static uint32_t target_cb=0;
            static uint32_t target_arg=0;
            static uint32_t sched_global=0;
            static unsigned post_n=0;

            const uint32_t qobj=0x002E6BF4U;
            const uint32_t target_raw=0x046600C4U;

            /*
             * 0x80001730:
             *   ldrd r1,r0,[r4,#0x0c]
             * 0x80001734:
             *   blx r1
             *
             * Therefore at 0x1734:
             *   R4 = scheduler record
             *   R1 = callback
             *   R0 = callback argument/object
             *   R5 = address of scheduler/current global
             */
            if (pc == 0x80001734U)
            {
                uint32_t arg=(uint32_t)env->regs[0];
                uint32_t raw=0;

                if (arg)
                    cpu_physical_memory_read(arg+0x10,&raw,4);

                if (!target_seen && raw == target_raw)
                {
                    uint32_t cur=0;

                    target_seen=1;
                    target_rec=(uint32_t)env->regs[4];
                    target_cb=(uint32_t)env->regs[1];
                    target_arg=arg;
                    sched_global=(uint32_t)env->regs[5];

                    if (sched_global)
                        cpu_physical_memory_read(sched_global,&cur,4);

                    R20EA_LOG(
                        "TARGET=FP_TARGET_PRE "
                        "REC=%08X CB=%08X ARG=%08X RAW=%08X "
                        "GLOBAL=%08X GLOBALVAL=%08X "
                        "LR=%08X SP=%08X",
                        target_rec,
                        target_cb,
                        target_arg,
                        raw,
                        sched_global,
                        cur,
                        (uint32_t)env->regs[14],
                        (uint32_t)env->regs[13]);

                    {
                        uint8_t b[16];
                        uint32_t a;
                        unsigned i;

                        for(a=target_rec;
                            a<target_rec+0x40;
                            a+=16)
                        {
                            cpu_physical_memory_read(a,b,16);

                            fprintf(stderr,
                                    "[R20FP] PRE_REC=%08X",a);

                            for(i=0;i<16;i++)
                                fprintf(stderr," %02X",b[i]);

                            fprintf(stderr,"\n");
                        }
                    }
                }
            }

            if (target_seen &&
                !critical &&
                pc == 0x80003B2EU &&
                (uint32_t)env->regs[4] == qobj)
            {
                uint16_t active=0,q=0,w=0,r=0;

                cpu_physical_memory_read(qobj+0x0C,&active,2);
                cpu_physical_memory_read(qobj+0x12,&q,2);
                cpu_physical_memory_read(qobj+0x18,&w,2);
                cpu_physical_memory_read(qobj+0x1A,&r,2);

                if (active==0 && q==1 && w==4 && r==3)
                {
                    uint32_t cur=0;
                    uint32_t cb=0;
                    uint32_t arg=0;

                    critical=1;

                    cpu_physical_memory_read(target_rec+0x0C,&cb,4);
                    cpu_physical_memory_read(target_rec+0x10,&arg,4);

                    if (sched_global)
                        cpu_physical_memory_read(sched_global,&cur,4);

                    R20EA_LOG(
                        "TARGET=FP_CRITICAL "
                        "REC=%08X CB=%08X ARG=%08X "
                        "GLOBAL=%08X GLOBALVAL=%08X "
                        "ACTIVE=%04X QUEUED=%04X W18=%04X R1A=%04X",
                        target_rec,
                        cb,
                        arg,
                        sched_global,
                        cur,
                        active,q,w,r);

                    {
                        uint8_t b[16];
                        uint32_t a;
                        unsigned i;

                        for(a=target_rec;
                            a<target_rec+0x40;
                            a+=16)
                        {
                            cpu_physical_memory_read(a,b,16);

                            fprintf(stderr,
                                    "[R20FP] POST_REC=%08X",a);

                            for(i=0;i<16;i++)
                                fprintf(stderr," %02X",b[i]);

                            fprintf(stderr,"\n");
                        }
                    }
                }
            }

            /*
             * Which scheduler records continue to execute after stall?
             */
            if (critical &&
                pc == 0x80001734U &&
                post_n < 32)
            {
                uint32_t rec=(uint32_t)env->regs[4];
                uint32_t cb=(uint32_t)env->regs[1];
                uint32_t arg=(uint32_t)env->regs[0];

                R20EA_LOG(
                    "TARGET=FP_POST_CALL N=%u "
                    "REC=%08X CB=%08X ARG=%08X "
                    "ISTARGET=%d GLOBAL=%08X SP=%08X",
                    post_n,
                    rec,cb,arg,
                    rec==target_rec,
                    (uint32_t)env->regs[5],
                    (uint32_t)env->regs[13]);

                post_n++;
            }
        }

        /* QEMU40PAD-BC-R20FQ-WRITERS */
        if (0)
        {
            static int armed=0;
            static uint32_t rec=0;

            static uint32_t old_global=0;
            static uint32_t old14=0;
            static uint32_t old18=0;
            static uint32_t old28=0;
            static uint32_t old2c=0;
            static uint32_t old34=0;
            static uint32_t old38=0;

            static unsigned changes=0;

            const uint32_t global_addr=0x000045A4U;
            const uint32_t target_raw=0x046600C4U;

            /*
             * Discover target scheduler record dynamically from the
             * already-proven callback dispatch.
             */
            if (!armed && pc == 0x80001734U)
            {
                uint32_t arg=(uint32_t)env->regs[0];
                uint32_t raw=0;

                if (arg)
                    cpu_physical_memory_read(arg+0x10,&raw,4);

                if (raw == target_raw)
                {
                    rec=(uint32_t)env->regs[4];

                    cpu_physical_memory_read(global_addr,&old_global,4);
                    cpu_physical_memory_read(rec+0x14,&old14,4);
                    cpu_physical_memory_read(rec+0x18,&old18,4);
                    cpu_physical_memory_read(rec+0x28,&old28,4);
                    cpu_physical_memory_read(rec+0x2C,&old2c,4);
                    cpu_physical_memory_read(rec+0x34,&old34,4);
                    cpu_physical_memory_read(rec+0x38,&old38,4);

                    armed=1;

                    R20EA_LOG(
                        "TARGET=FQ_ARM REC=%08X "
                        "GLOBAL=%08X "
                        "F14=%08X F18=%08X "
                        "F28=%08X F2C=%08X "
                        "F34=%08X F38=%08X",
                        rec,old_global,
                        old14,old18,
                        old28,old2c,
                        old34,old38);
                }
            }

            if (armed && changes < 64)
            {
                uint32_t vglobal=0;
                uint32_t v14=0,v18=0,v28=0,v2c=0,v34=0,v38=0;

                cpu_physical_memory_read(global_addr,&vglobal,4);
                cpu_physical_memory_read(rec+0x14,&v14,4);
                cpu_physical_memory_read(rec+0x18,&v18,4);
                cpu_physical_memory_read(rec+0x28,&v28,4);
                cpu_physical_memory_read(rec+0x2C,&v2c,4);
                cpu_physical_memory_read(rec+0x34,&v34,4);
                cpu_physical_memory_read(rec+0x38,&v38,4);

#define FQ_CHANGE(name,oldv,newv,addr) do {                   \
                    if ((oldv)!=(newv) && changes < 64)       \
                    {                                         \
                        R20EA_LOG(                             \
                            "TARGET=FQ_CHANGE N=%u "           \
                            "FIELD=%s ADDR=%08X "              \
                            "OLD=%08X NEW=%08X "               \
                            "PC=%08X LR=%08X SP=%08X",         \
                            changes,#name,(uint32_t)(addr),    \
                            (uint32_t)(oldv),(uint32_t)(newv), \
                            pc,                               \
                            (uint32_t)env->regs[14],           \
                            (uint32_t)env->regs[13]);          \
                        changes++;                            \
                        (oldv)=(newv);                        \
                    }                                         \
                } while(0)

                FQ_CHANGE(GLOBAL,old_global,vglobal,global_addr);
                FQ_CHANGE(F14,old14,v14,rec+0x14);
                FQ_CHANGE(F18,old18,v18,rec+0x18);
                FQ_CHANGE(F28,old28,v28,rec+0x28);
                FQ_CHANGE(F2C,old2c,v2c,rec+0x2C);
                FQ_CHANGE(F34,old34,v34,rec+0x34);
                FQ_CHANGE(F38,old38,v38,rec+0x38);

#undef FQ_CHANGE
            }
        }

        /* QEMU40PAD-BC-R20FR-RING */
        if (0)
        {
            typedef struct {
                uint32_t kind;
                uint32_t addr;
                uint32_t oldv;
                uint32_t newv;
                uint32_t pc;
                uint32_t lr;
                uint32_t sp;
            } R20FR_Event;

            static int armed=0;
            static int dumped=0;
            static uint32_t rec=0;

            static uint32_t old_global=0;
            static uint32_t old14=0;
            static uint32_t old18=0;
            static uint32_t old28=0;
            static uint32_t old2c=0;
            static uint32_t old34=0;
            static uint32_t old38=0;

            static R20FR_Event ring[48];
            static unsigned wr=0;
            static unsigned total=0;
            static unsigned target_global_hits=0;

            const uint32_t global_addr=0x000045A4U;
            const uint32_t target_raw=0x046600C4U;
            const uint32_t qobj=0x002E6BF4U;

#define FR_STORE(k,a,o,n) do {                               \
                R20FR_Event *e=&ring[wr];                    \
                e->kind=(k);                                 \
                e->addr=(a);                                 \
                e->oldv=(o);                                 \
                e->newv=(n);                                 \
                e->pc=pc;                                    \
                e->lr=(uint32_t)env->regs[14];               \
                e->sp=(uint32_t)env->regs[13];               \
                wr=(wr+1)%48;                                \
                total++;                                     \
            } while(0)

            /*
             * Dynamically discover the DispDCtrl scheduler record.
             */
            if (!armed && pc == 0x80001734U)
            {
                uint32_t arg=(uint32_t)env->regs[0];
                uint32_t raw=0;

                if (arg)
                    cpu_physical_memory_read(arg+0x10,&raw,4);

                if (raw == target_raw)
                {
                    rec=(uint32_t)env->regs[4];

                    cpu_physical_memory_read(global_addr,&old_global,4);
                    cpu_physical_memory_read(rec+0x14,&old14,4);
                    cpu_physical_memory_read(rec+0x18,&old18,4);
                    cpu_physical_memory_read(rec+0x28,&old28,4);
                    cpu_physical_memory_read(rec+0x2C,&old2c,4);
                    cpu_physical_memory_read(rec+0x34,&old34,4);
                    cpu_physical_memory_read(rec+0x38,&old38,4);

                    armed=1;

                    R20EA_LOG(
                        "TARGET=FR_ARM REC=%08X GLOBAL=%08X "
                        "F14=%08X F18=%08X F28=%08X "
                        "F2C=%08X F34=%08X F38=%08X",
                        rec,old_global,
                        old14,old18,old28,
                        old2c,old34,old38);
                }
            }

            if (armed && !dumped)
            {
                uint32_t vg=0;
                uint32_t v14=0,v18=0,v28=0,v2c=0,v34=0,v38=0;

                cpu_physical_memory_read(global_addr,&vg,4);
                cpu_physical_memory_read(rec+0x14,&v14,4);
                cpu_physical_memory_read(rec+0x18,&v18,4);
                cpu_physical_memory_read(rec+0x28,&v28,4);
                cpu_physical_memory_read(rec+0x2C,&v2c,4);
                cpu_physical_memory_read(rec+0x34,&v34,4);
                cpu_physical_memory_read(rec+0x38,&v38,4);

                if (vg != old_global)
                {
                    FR_STORE(1,global_addr,old_global,vg);

                    if (vg == rec)
                        target_global_hits++;

                    old_global=vg;
                }

                if (v14 != old14) {
                    FR_STORE(2,rec+0x14,old14,v14);
                    old14=v14;
                }

                if (v18 != old18) {
                    FR_STORE(3,rec+0x18,old18,v18);
                    old18=v18;
                }

                if (v28 != old28) {
                    FR_STORE(4,rec+0x28,old28,v28);
                    old28=v28;
                }

                if (v2c != old2c) {
                    FR_STORE(5,rec+0x2C,old2c,v2c);
                    old2c=v2c;
                }

                if (v34 != old34) {
                    FR_STORE(6,rec+0x34,old34,v34);
                    old34=v34;
                }

                if (v38 != old38) {
                    FR_STORE(7,rec+0x38,old38,v38);
                    old38=v38;
                }

                /*
                 * Exact known-bad state.
                 */
                if (pc == 0x80003B2EU &&
                    (uint32_t)env->regs[4] == qobj)
                {
                    uint16_t active=0,q=0,w=0,r=0;

                    cpu_physical_memory_read(qobj+0x0C,&active,2);
                    cpu_physical_memory_read(qobj+0x12,&q,2);
                    cpu_physical_memory_read(qobj+0x18,&w,2);
                    cpu_physical_memory_read(qobj+0x1A,&r,2);

                    if (active==0 && q==1 && w==4 && r==3)
                    {
                        unsigned count=(total < 48) ? total : 48;
                        unsigned start=(total < 48) ? 0 : wr;
                        unsigned j;

                        dumped=1;

                        R20EA_LOG(
                            "TARGET=FR_CRITICAL "
                            "REC=%08X GLOBAL=%08X "
                            "TOTAL=%u TARGET_HITS=%u "
                            "ACTIVE=%04X QUEUED=%04X "
                            "W18=%04X R1A=%04X",
                            rec,vg,total,target_global_hits,
                            active,q,w,r);

                        for(j=0;j<count;j++)
                        {
                            unsigned idx=(start+j)%48;
                            R20FR_Event *e=&ring[idx];

                            R20EA_LOG(
                                "TARGET=FR_HISTORY N=%u "
                                "KIND=%u ADDR=%08X "
                                "OLD=%08X NEW=%08X "
                                "PC=%08X LR=%08X SP=%08X",
                                j,
                                e->kind,
                                e->addr,
                                e->oldv,
                                e->newv,
                                e->pc,
                                e->lr,
                                e->sp);
                        }

                        R20EA_LOG(
                            "TARGET=FR_FINAL "
                            "GLOBAL=%08X "
                            "F14=%08X F18=%08X "
                            "F28=%08X F2C=%08X "
                            "F34=%08X F38=%08X",
                            vg,v14,v18,v28,v2c,v34,v38);
                    }
                }
            }

#undef FR_STORE
        }

        /* QEMU40PAD-BC-R20FS-DEFER */
        if (0)
        {
            static int armed=0;
            static uint32_t rec=0;

            static unsigned defer_n=0;
            static unsigned pending=0;
            static unsigned switches=0;
            static unsigned target_hits=0;

            static uint32_t last_global=0;
            static uint16_t last_w=0xffff;
            static uint16_t last_r=0xffff;

            const uint32_t qobj=0x002E6BF4U;
            const uint32_t global_addr=0x000045A4U;
            const uint32_t target_raw=0x046600C4U;

            /*
             * Discover DispDCtrl scheduler record dynamically.
             */
            if (pc == 0x80001734U)
            {
                uint32_t arg=(uint32_t)env->regs[0];
                uint32_t raw=0;

                if (arg)
                    cpu_physical_memory_read(arg+0x10,&raw,4);

                if (raw == target_raw)
                {
                    if (!armed)
                    {
                        armed=1;
                        rec=(uint32_t)env->regs[4];

                        cpu_physical_memory_read(
                            global_addr,&last_global,4);

                        R20EA_LOG(
                            "TARGET=FS_ARM "
                            "REC=%08X GLOBAL=%08X",
                            rec,last_global);
                    }

                    /*
                     * A previously deferred request has reached
                     * DispDCtrl again: successful wake/reschedule.
                     */
                    if (pending)
                    {
                        uint32_t g=0;
                        uint32_t f14=0,f18=0,f28=0,f2c=0,f34=0,f38=0;

                        cpu_physical_memory_read(global_addr,&g,4);
                        cpu_physical_memory_read(rec+0x14,&f14,4);
                        cpu_physical_memory_read(rec+0x18,&f18,4);
                        cpu_physical_memory_read(rec+0x28,&f28,4);
                        cpu_physical_memory_read(rec+0x2C,&f2c,4);
                        cpu_physical_memory_read(rec+0x34,&f34,4);
                        cpu_physical_memory_read(rec+0x38,&f38,4);

                        R20EA_LOG(
                            "TARGET=FS_RESUME N=%u "
                            "GLOBAL=%08X SWITCHES=%u TARGETHITS=%u "
                            "F14=%08X F18=%08X "
                            "F28=%08X F2C=%08X "
                            "F34=%08X F38=%08X",
                            pending,g,switches,target_hits,
                            f14,f18,f28,f2c,f34,f38);

                        pending=0;
                        switches=0;
                        target_hits=0;
                    }
                }
            }

            /*
             * Count scheduler movement while a deferred wake is pending.
             */
            if (armed && pending)
            {
                uint32_t g=0;

                cpu_physical_memory_read(global_addr,&g,4);

                if (g != last_global)
                {
                    switches++;

                    if (g == rec)
                        target_hits++;

                    last_global=g;
                }
            }

            /*
             * Fully installed deferred entry.
             */
            if (armed &&
                pc == 0x80003B2EU &&
                (uint32_t)env->regs[4] == qobj)
            {
                uint16_t active=0,q=0,w=0,r=0;

                cpu_physical_memory_read(qobj+0x0C,&active,2);
                cpu_physical_memory_read(qobj+0x12,&q,2);
                cpu_physical_memory_read(qobj+0x18,&w,2);
                cpu_physical_memory_read(qobj+0x1A,&r,2);

                /*
                 * De-duplicate repeated observation of the same
                 * queue state.
                 */
                if (active==0 &&
                    q!=0 &&
                    w!=r &&
                    (w!=last_w || r!=last_r))
                {
                    uint32_t g=0;
                    uint32_t f14=0,f18=0,f28=0,f2c=0,f34=0,f38=0;

                    defer_n++;
                    pending=defer_n;
                    switches=0;
                    target_hits=0;

                    last_w=w;
                    last_r=r;

                    cpu_physical_memory_read(global_addr,&g,4);
                    cpu_physical_memory_read(rec+0x14,&f14,4);
                    cpu_physical_memory_read(rec+0x18,&f18,4);
                    cpu_physical_memory_read(rec+0x28,&f28,4);
                    cpu_physical_memory_read(rec+0x2C,&f2c,4);
                    cpu_physical_memory_read(rec+0x34,&f34,4);
                    cpu_physical_memory_read(rec+0x38,&f38,4);

                    last_global=g;

                    R20EA_LOG(
                        "TARGET=FS_DEFER N=%u "
                        "ACTIVE=%04X QUEUED=%04X "
                        "W18=%04X R1A=%04X "
                        "GLOBAL=%08X "
                        "F14=%08X F18=%08X "
                        "F28=%08X F2C=%08X "
                        "F34=%08X F38=%08X",
                        defer_n,
                        active,q,w,r,g,
                        f14,f18,f28,f2c,f34,f38);
                }
            }
        }

        /* QEMU40PAD-BC-R20FT-DEQUEUE */
        if (0)
        {
            static int armed=0;
            static uint32_t rec=0;
            static uint16_t prev_r=0xffff;
            static unsigned defer_n=0;
            static unsigned drain_n=0;

            const uint32_t qobj=0x002E6BF4U;
            const uint32_t target_raw=0x046600C4U;
            const uint32_t global_addr=0x000045A4U;

            /*
             * Discover scheduler record dynamically.
             */
            if (!armed && pc == 0x80001734U)
            {
                uint32_t arg=(uint32_t)env->regs[0];
                uint32_t raw=0;

                if (arg)
                    cpu_physical_memory_read(arg+0x10,&raw,4);

                if (raw == target_raw)
                {
                    armed=1;
                    rec=(uint32_t)env->regs[4];

                    cpu_physical_memory_read(qobj+0x1A,&prev_r,2);

                    R20EA_LOG(
                        "TARGET=FT_ARM REC=%08X R1A=%04X",
                        rec,prev_r);
                }
            }

            /*
             * Every fully-installed deferred enqueue.
             */
            if (armed &&
                pc == 0x80003B2EU &&
                (uint32_t)env->regs[4] == qobj)
            {
                uint16_t a=0,q=0,w=0,r=0;

                cpu_physical_memory_read(qobj+0x0C,&a,2);
                cpu_physical_memory_read(qobj+0x12,&q,2);
                cpu_physical_memory_read(qobj+0x18,&w,2);
                cpu_physical_memory_read(qobj+0x1A,&r,2);

                if (a==0 && q && w!=r)
                {
                    uint32_t g=0;
                    uint32_t f14=0,f18=0,f28=0,f2c=0,f34=0,f38=0;

                    defer_n++;

                    cpu_physical_memory_read(global_addr,&g,4);
                    cpu_physical_memory_read(rec+0x14,&f14,4);
                    cpu_physical_memory_read(rec+0x18,&f18,4);
                    cpu_physical_memory_read(rec+0x28,&f28,4);
                    cpu_physical_memory_read(rec+0x2C,&f2c,4);
                    cpu_physical_memory_read(rec+0x34,&f34,4);
                    cpu_physical_memory_read(rec+0x38,&f38,4);

                    R20EA_LOG(
                        "TARGET=FT_DEFER N=%u "
                        "A=%04X Q=%04X W=%04X R=%04X "
                        "GLOBAL=%08X "
                        "F14=%08X F18=%08X F28=%08X "
                        "F2C=%08X F34=%08X F38=%08X",
                        defer_n,a,q,w,r,g,
                        f14,f18,f28,f2c,f34,f38);
                }
            }

            /*
             * 0x80003BE8 is the known target read-index update.
             * Log the scheduler state exactly when a deferred entry
             * is successfully consumed.
             */
            if (armed &&
                pc == 0x80003BE8U &&
                (uint32_t)env->regs[4] == qobj)
            {
                uint16_t r=0,w=0,q=0;
                uint32_t g=0;
                uint32_t f14=0,f18=0,f28=0,f2c=0,f34=0,f38=0;

                cpu_physical_memory_read(qobj+0x1A,&r,2);
                cpu_physical_memory_read(qobj+0x18,&w,2);
                cpu_physical_memory_read(qobj+0x12,&q,2);

                cpu_physical_memory_read(global_addr,&g,4);
                cpu_physical_memory_read(rec+0x14,&f14,4);
                cpu_physical_memory_read(rec+0x18,&f18,4);
                cpu_physical_memory_read(rec+0x28,&f28,4);
                cpu_physical_memory_read(rec+0x2C,&f2c,4);
                cpu_physical_memory_read(rec+0x34,&f34,4);
                cpu_physical_memory_read(rec+0x38,&f38,4);

                drain_n++;

                R20EA_LOG(
                    "TARGET=FT_DRAIN N=%u "
                    "R_OLD=%04X R_NOW=%04X W=%04X Q=%04X "
                    "GLOBAL=%08X "
                    "F14=%08X F18=%08X F28=%08X "
                    "F2C=%08X F34=%08X F38=%08X "
                    "LR=%08X SP=%08X",
                    drain_n,prev_r,r,w,q,g,
                    f14,f18,f28,f2c,f34,f38,
                    (uint32_t)env->regs[14],
                    (uint32_t)env->regs[13]);

                prev_r=r;
            }

            /*
             * Target dispatch witness.
             */
            if (armed &&
                pc == 0x800022ECU &&
                (uint32_t)env->regs[0] == 0x02330062U)
            {
                uint32_t f14=0,f34=0,g=0;

                cpu_physical_memory_read(global_addr,&g,4);
                cpu_physical_memory_read(rec+0x14,&f14,4);
                cpu_physical_memory_read(rec+0x34,&f34,4);

                R20EA_LOG(
                    "TARGET=FT_DISPATCH "
                    "GLOBAL=%08X F14=%08X F34=%08X "
                    "R1=%08X LR=%08X",
                    g,f14,f34,
                    (uint32_t)env->regs[1],
                    (uint32_t)env->regs[14]);
            }
        }

        /* QEMU40PAD-BC-R20FU-F14 */
        if (0)
        {
            static int armed=0;
            static uint32_t rec=0;
            static uint32_t old14=0;
            static unsigned n=0;
            static int dump_done=0;

            const uint32_t target_raw=0x046600C4U;

            if (!armed && pc == 0x80001734U)
            {
                uint32_t arg=(uint32_t)env->regs[0];
                uint32_t raw=0;

                if (arg)
                    cpu_physical_memory_read(arg+0x10,&raw,4);

                if (raw == target_raw)
                {
                    rec=(uint32_t)env->regs[4];
                    cpu_physical_memory_read(rec+0x14,&old14,4);
                    armed=1;

                    R20EA_LOG(
                        "TARGET=FU_ARM REC=%08X F14=%08X",
                        rec,old14);
                }
            }

            if (armed &&
                (pc == 0x80003560U ||
                 pc == 0x800018A6U))
            {
                uint32_t v14=0;

                cpu_physical_memory_read(rec+0x14,&v14,4);

                R20EA_LOG(
                    "TARGET=FU_WRITER N=%u "
                    "PC=%08X F14_OLD=%08X F14_NOW=%08X "
                    "R0=%08X R1=%08X R2=%08X R3=%08X "
                    "R4=%08X R5=%08X R6=%08X R7=%08X "
                    "LR=%08X SP=%08X",
                    n++,
                    pc,old14,v14,
                    (uint32_t)env->regs[0],
                    (uint32_t)env->regs[1],
                    (uint32_t)env->regs[2],
                    (uint32_t)env->regs[3],
                    (uint32_t)env->regs[4],
                    (uint32_t)env->regs[5],
                    (uint32_t)env->regs[6],
                    (uint32_t)env->regs[7],
                    (uint32_t)env->regs[14],
                    (uint32_t)env->regs[13]);

                old14=v14;
            }

            if (armed && !dump_done)
            {
                uint8_t b[16];
                uint32_t a;
                unsigned i;

                dump_done=1;

                for(a=0x80001870U;a<0x800018D0U;a+=16)
                {
                    cpu_physical_memory_read(a,b,16);
                    fprintf(stderr,"[R20FU] CODE=%08X",a);
                    for(i=0;i<16;i++) fprintf(stderr," %02X",b[i]);
                    fprintf(stderr,"\n");
                }

                for(a=0x80003520U;a<0x800035A0U;a+=16)
                {
                    cpu_physical_memory_read(a,b,16);
                    fprintf(stderr,"[R20FU] CODE=%08X",a);
                    for(i=0;i<16;i++) fprintf(stderr," %02X",b[i]);
                    fprintf(stderr,"\n");
                }
            }
        }

        /* QEMU40PAD-BC-R20FV-WAITWAKE */
        if (0)
        {
            static int armed=0;
            static uint32_t rec=0;
            static uint32_t f14_prev=0;
            static uint32_t wait_obj=0;
            static unsigned change_n=0;

            const uint32_t target_raw=0x046600C4U;
            const uint32_t global_addr=0x000045A4U;
            const uint32_t qobj=0x002E6BF4U;

            /*
             * Discover DispDCtrl task record dynamically.
             */
            if (!armed && pc == 0x80001734U)
            {
                uint32_t arg=(uint32_t)env->regs[0];
                uint32_t raw=0;

                if (arg)
                    cpu_physical_memory_read(arg+0x10,&raw,4);

                if (raw == target_raw)
                {
                    rec=(uint32_t)env->regs[4];
                    cpu_physical_memory_read(rec+0x14,&f14_prev,4);
                    armed=1;

                    R20EA_LOG(
                        "TARGET=FV_ARM REC=%08X F14=%08X",
                        rec,f14_prev);
                }
            }

            /*
             * Entry of the apparent wait primitive.
             * Current record must be DispDCtrl.
             */
            if (armed && pc == 0x80003524U)
            {
                uint32_t cur=0;
                cpu_physical_memory_read(global_addr,&cur,4);

                if (cur == rec)
                {
                    uint32_t obj=(uint32_t)env->regs[0];
                    uint32_t count=0;

                    if (obj)
                        cpu_physical_memory_read(obj+0x08,&count,4);

                    R20EA_LOG(
                        "TARGET=FV_WAIT_ENTER "
                        "OBJ=%08X COUNT08=%08X "
                        "R1=%08X LR=%08X SP=%08X",
                        obj,count,
                        (uint32_t)env->regs[1],
                        (uint32_t)env->regs[14],
                        (uint32_t)env->regs[13]);
                }
            }

            /*
             * Observe only actual F14 transitions of target record.
             */
            if (armed)
            {
                uint32_t f14=0;

                cpu_physical_memory_read(rec+0x14,&f14,4);

                if (f14 != f14_prev)
                {
                    uint32_t obj_count=0;

                    if (f14 && f14 != rec)
                        cpu_physical_memory_read(f14+0x08,&obj_count,4);

                    R20EA_LOG(
                        "TARGET=FV_F14_CHANGE N=%u "
                        "OLD=%08X NEW=%08X "
                        "NEW_COUNT08=%08X "
                        "PC=%08X LR=%08X SP=%08X "
                        "R0=%08X R1=%08X R2=%08X R3=%08X "
                        "R4=%08X R5=%08X",
                        change_n++,
                        f14_prev,f14,obj_count,
                        pc,
                        (uint32_t)env->regs[14],
                        (uint32_t)env->regs[13],
                        (uint32_t)env->regs[0],
                        (uint32_t)env->regs[1],
                        (uint32_t)env->regs[2],
                        (uint32_t)env->regs[3],
                        (uint32_t)env->regs[4],
                        (uint32_t)env->regs[5]);

                    if (f14 != rec)
                        wait_obj=f14;

                    f14_prev=f14;
                }
            }

            /*
             * Exact successful wake-side witness: F14 has returned
             * to self at the known unblock path.
             */
            if (armed &&
                pc == 0x800018A6U &&
                (uint32_t)env->regs[4] == rec)
            {
                uint32_t f14=0;
                uint32_t count=0;

                cpu_physical_memory_read(rec+0x14,&f14,4);

                if (wait_obj)
                    cpu_physical_memory_read(wait_obj+0x08,&count,4);

                R20EA_LOG(
                    "TARGET=FV_WAKE_PATH "
                    "F14=%08X WAITOBJ=%08X COUNT08=%08X "
                    "LR=%08X SP=%08X "
                    "R2=%08X R3=%08X",
                    f14,wait_obj,count,
                    (uint32_t)env->regs[14],
                    (uint32_t)env->regs[13],
                    (uint32_t)env->regs[2],
                    (uint32_t)env->regs[3]);
            }

            /*
             * Critical fourth deferred entry.
             */
            if (armed &&
                pc == 0x80003B2EU &&
                (uint32_t)env->regs[4] == qobj)
            {
                uint16_t a=0,q=0,w=0,r=0;

                cpu_physical_memory_read(qobj+0x0C,&a,2);
                cpu_physical_memory_read(qobj+0x12,&q,2);
                cpu_physical_memory_read(qobj+0x18,&w,2);
                cpu_physical_memory_read(qobj+0x1A,&r,2);

                if (a==0 && q==1 && w==4 && r==3)
                {
                    uint32_t f14=0;
                    uint32_t count=0;

                    cpu_physical_memory_read(rec+0x14,&f14,4);

                    if (f14 && f14 != rec)
                        cpu_physical_memory_read(f14+0x08,&count,4);

                    R20EA_LOG(
                        "TARGET=FV_CRITICAL "
                        "F14=%08X COUNT08=%08X "
                        "ACTIVE=%04X QUEUED=%04X "
                        "W18=%04X R1A=%04X",
                        f14,count,a,q,w,r);
                }
            }
        }

        /* QEMU40PAD-BC-R20FW-WAITCOUNT */
        if (0)
        {
            static int armed=0;
            static uint32_t rec=0;

            static int have_wait=0;
            static uint32_t wait_obj=0;
            static uint32_t old_count=0;

            static uint32_t old_f14=0;
            static unsigned count_n=0;
            static unsigned f14_n=0;

            const uint32_t target_raw=0x046600C4U;
            const uint32_t qobj=0x002E6BF4U;

            /*
             * Discover DispDCtrl scheduler record.
             */
            if (!armed && pc == 0x80001734U)
            {
                uint32_t arg=(uint32_t)env->regs[0];
                uint32_t raw=0;

                if (arg)
                    cpu_physical_memory_read(arg+0x10,&raw,4);

                if (raw == target_raw)
                {
                    rec=(uint32_t)env->regs[4];
                    cpu_physical_memory_read(rec+0x14,&old_f14,4);

                    armed=1;

                    R20EA_LOG(
                        "TARGET=FW_ARM "
                        "REC=%08X F14=%08X",
                        rec,old_f14);
                }
            }

            /*
             * Proven wait path:
             *
             * R4 = current task/DispDCtrl
             * R5 = wait object
             * R2 = object/index 0x22B
             */
            if (armed &&
                pc == 0x80003560U &&
                (uint32_t)env->regs[4] == rec &&
                (uint32_t)env->regs[2] == 0x0000022BU)
            {
                uint32_t obj=(uint32_t)env->regs[5];

                if (!have_wait)
                {
                    wait_obj=obj;

                    cpu_physical_memory_read(
                        wait_obj+0x08,&old_count,4);

                    have_wait=1;

                    R20EA_LOG(
                        "TARGET=FW_WAITOBJ "
                        "OBJ=%08X COUNT=%08X "
                        "LR=%08X SP=%08X",
                        wait_obj,old_count,
                        (uint32_t)env->regs[14],
                        (uint32_t)env->regs[13]);
                }
                else if (obj != wait_obj)
                {
                    R20EA_LOG(
                        "TARGET=FW_WAITOBJ_MISMATCH "
                        "KNOWN=%08X NOW=%08X",
                        wait_obj,obj);
                }
            }

            /*
             * Instruction-level software watchpoint on semaphore count.
             */
            if (have_wait && count_n < 32)
            {
                uint32_t count=0;

                cpu_physical_memory_read(
                    wait_obj+0x08,&count,4);

                if (count != old_count)
                {
                    R20EA_LOG(
                        "TARGET=FW_COUNT_CHANGE N=%u "
                        "OBJ=%08X "
                        "OLD=%08X NEW=%08X "
                        "PC=%08X LR=%08X SP=%08X "
                        "R0=%08X R1=%08X "
                        "R2=%08X R3=%08X "
                        "R4=%08X R5=%08X "
                        "R6=%08X R7=%08X",
                        count_n++,
                        wait_obj,
                        old_count,count,
                        pc,
                        (uint32_t)env->regs[14],
                        (uint32_t)env->regs[13],
                        (uint32_t)env->regs[0],
                        (uint32_t)env->regs[1],
                        (uint32_t)env->regs[2],
                        (uint32_t)env->regs[3],
                        (uint32_t)env->regs[4],
                        (uint32_t)env->regs[5],
                        (uint32_t)env->regs[6],
                        (uint32_t)env->regs[7]);

                    old_count=count;
                }
            }

            /*
             * Track only real F14 transitions.
             */
            if (armed && have_wait && f14_n < 32)
            {
                uint32_t f14=0;

                cpu_physical_memory_read(
                    rec+0x14,&f14,4);

                if (f14 != old_f14)
                {
                    R20EA_LOG(
                        "TARGET=FW_F14_CHANGE N=%u "
                        "OLD=%08X NEW=%08X "
                        "COUNT=%08X "
                        "PC=%08X LR=%08X SP=%08X",
                        f14_n++,
                        old_f14,f14,
                        old_count,
                        pc,
                        (uint32_t)env->regs[14],
                        (uint32_t)env->regs[13]);

                    old_f14=f14;
                }
            }

            /*
             * Explicit successful wake witness.
             */
            if (armed && have_wait &&
                pc == 0x800018A6U &&
                (uint32_t)env->regs[4] == rec)
            {
                uint32_t count=0;
                uint32_t f14=0;

                cpu_physical_memory_read(
                    wait_obj+0x08,&count,4);

                cpu_physical_memory_read(
                    rec+0x14,&f14,4);

                R20EA_LOG(
                    "TARGET=FW_WAKE "
                    "OBJ=%08X COUNT=%08X F14=%08X "
                    "LR=%08X SP=%08X "
                    "R0=%08X R1=%08X "
                    "R2=%08X R3=%08X",
                    wait_obj,count,f14,
                    (uint32_t)env->regs[14],
                    (uint32_t)env->regs[13],
                    (uint32_t)env->regs[0],
                    (uint32_t)env->regs[1],
                    (uint32_t)env->regs[2],
                    (uint32_t)env->regs[3]);
            }

            /*
             * Exact known failing deferred state.
             */
            if (armed && have_wait &&
                pc == 0x80003B2EU &&
                (uint32_t)env->regs[4] == qobj)
            {
                uint16_t a=0,q=0,w=0,r=0;

                cpu_physical_memory_read(qobj+0x0C,&a,2);
                cpu_physical_memory_read(qobj+0x12,&q,2);
                cpu_physical_memory_read(qobj+0x18,&w,2);
                cpu_physical_memory_read(qobj+0x1A,&r,2);

                if (a==0 && q==1 && w==4 && r==3)
                {
                    uint32_t count=0;
                    uint32_t f14=0;

                    cpu_physical_memory_read(
                        wait_obj+0x08,&count,4);

                    cpu_physical_memory_read(
                        rec+0x14,&f14,4);

                    R20EA_LOG(
                        "TARGET=FW_CRITICAL "
                        "OBJ=%08X COUNT=%08X F14=%08X "
                        "ACTIVE=%04X QUEUED=%04X "
                        "W18=%04X R1A=%04X",
                        wait_obj,count,f14,
                        a,q,w,r);
                }
            }
        }

        /* QEMU40PAD-BC-R20FX-GIVEWAKE */
        if (0)
        {
            static int armed=0;
            static int dumped=0;

            static uint32_t rec=0;
            static uint32_t wait_obj=0;

            static unsigned give_n=0;
            static unsigned wake_n=0;
            static int give_pending=0;

            const uint32_t target_raw=0x046600C4U;

            /*
             * Discover DispDCtrl scheduler record.
             */
            if (!armed && pc == 0x80001734U)
            {
                uint32_t arg=(uint32_t)env->regs[0];
                uint32_t raw=0;

                if (arg)
                    cpu_physical_memory_read(arg+0x10,&raw,4);

                if (raw == target_raw)
                {
                    rec=(uint32_t)env->regs[4];
                    armed=1;

                    R20EA_LOG(
                        "TARGET=FX_ARM REC=%08X",
                        rec);
                }
            }

            /*
             * Discover semaphore/wait object 0x22B.
             */
            if (armed &&
                !wait_obj &&
                pc == 0x80003560U &&
                (uint32_t)env->regs[4] == rec &&
                (uint32_t)env->regs[2] == 0x0000022BU)
            {
                wait_obj=(uint32_t)env->regs[5];

                R20EA_LOG(
                    "TARGET=FX_WAITOBJ OBJ=%08X",
                    wait_obj);
            }

            /*
             * Static dump of GiveSemaphore side and wake helper.
             */
            if (armed && !dumped)
            {
                uint8_t b[16];
                uint32_t a;
                unsigned i;

                dumped=1;

                for(a=0x800034B0U;a<0x80003524U;a+=16)
                {
                    cpu_physical_memory_read(a,b,16);

                    fprintf(stderr,
                            "[R20FX] GIVE_CODE=%08X",a);

                    for(i=0;i<16;i++)
                        fprintf(stderr," %02X",b[i]);

                    fprintf(stderr,"\n");
                }

                for(a=0x80001870U;a<0x800018C0U;a+=16)
                {
                    cpu_physical_memory_read(a,b,16);

                    fprintf(stderr,
                            "[R20FX] WAKE_CODE=%08X",a);

                    for(i=0;i<16;i++)
                        fprintf(stderr," %02X",b[i]);

                    fprintf(stderr,"\n");
                }
            }

            /*
             * Proven count increment for semaphore 0x22B.
             */
            if (wait_obj &&
                pc == 0x800034FCU &&
                (uint32_t)env->regs[0] == wait_obj)
            {
                uint32_t count=0;
                uint32_t h0=0,h1=0,h2=0,h3=0;

                cpu_physical_memory_read(wait_obj+0x08,&count,4);
                cpu_physical_memory_read(wait_obj+0x0C,&h0,4);
                cpu_physical_memory_read(wait_obj+0x10,&h1,4);
                cpu_physical_memory_read(wait_obj+0x14,&h2,4);
                cpu_physical_memory_read(wait_obj+0x18,&h3,4);

                give_n++;
                give_pending=1;

                R20EA_LOG(
                    "TARGET=FX_GIVE N=%u "
                    "OBJ=%08X COUNT=%08X "
                    "O0C=%08X O10=%08X "
                    "O14=%08X O18=%08X "
                    "LR=%08X SP=%08X "
                    "R1=%08X R2=%08X R3=%08X "
                    "R4=%08X R5=%08X R6=%08X R7=%08X",
                    give_n,
                    wait_obj,count,
                    h0,h1,h2,h3,
                    (uint32_t)env->regs[14],
                    (uint32_t)env->regs[13],
                    (uint32_t)env->regs[1],
                    (uint32_t)env->regs[2],
                    (uint32_t)env->regs[3],
                    (uint32_t)env->regs[4],
                    (uint32_t)env->regs[5],
                    (uint32_t)env->regs[6],
                    (uint32_t)env->regs[7]);
            }

            /*
             * RTOS wake/list-removal path.
             *
             * Log every task reaching it after a Give, not just DispDCtrl.
             */
            if (armed &&
                give_pending &&
                pc == 0x800018A6U)
            {
                uint32_t task=(uint32_t)env->regs[4];
                uint32_t f14=0;
                uint32_t state48=0;
                uint32_t state4d=0;

                if (task)
                {
                    cpu_physical_memory_read(task+0x14,&f14,4);
                    cpu_physical_memory_read(task+0x48,&state48,4);
                    cpu_physical_memory_read(task+0x4D,&state4d,1);
                }

                wake_n++;

                R20EA_LOG(
                    "TARGET=FX_WAKE N=%u "
                    "AFTER_GIVE=%u "
                    "TASK=%08X TARGETTASK=%d "
                    "F14=%08X S48=%08X S4D=%02X "
                    "LR=%08X SP=%08X "
                    "R0=%08X R1=%08X R2=%08X R3=%08X",
                    wake_n,give_n,
                    task,task==rec,
                    f14,state48,state4d & 0xFF,
                    (uint32_t)env->regs[14],
                    (uint32_t)env->regs[13],
                    (uint32_t)env->regs[0],
                    (uint32_t)env->regs[1],
                    (uint32_t)env->regs[2],
                    (uint32_t)env->regs[3]);

                /*
                 * We care about the first wake decision associated
                 * with this Give.
                 */
                give_pending=0;
            }
        }

        /* QEMU40PAD-BC-R20FY-GIVESCHED */
        if (0)
        {
            static int armed=0;
            static int dumped=0;
            static uint32_t rec=0;
            static uint32_t wait_obj=0;
            static unsigned give0_n=0;
            static unsigned sched_n=0;

            const uint32_t target_raw=0x046600C4U;

            if (!armed && pc == 0x80001734U)
            {
                uint32_t arg=(uint32_t)env->regs[0];
                uint32_t raw=0;

                if (arg)
                    cpu_physical_memory_read(arg+0x10,&raw,4);

                if (raw == target_raw)
                {
                    rec=(uint32_t)env->regs[4];
                    armed=1;

                    R20EA_LOG(
                        "TARGET=FY_ARM REC=%08X",
                        rec);
                }
            }

            if (armed &&
                !wait_obj &&
                pc == 0x80003560U &&
                (uint32_t)env->regs[4] == rec &&
                (uint32_t)env->regs[2] == 0x0000022BU)
            {
                wait_obj=(uint32_t)env->regs[5];

                R20EA_LOG(
                    "TARGET=FY_WAITOBJ OBJ=%08X",
                    wait_obj);
            }

            if (armed && !dumped)
            {
                uint8_t b[16];
                uint32_t a;
                unsigned i;

                dumped=1;

                for(a=0x80000830U;a<0x80000920U;a+=16)
                {
                    cpu_physical_memory_read(a,b,16);

                    fprintf(stderr,
                            "[R20FY] SCHED_CODE=%08X",a);

                    for(i=0;i<16;i++)
                        fprintf(stderr," %02X",b[i]);

                    fprintf(stderr,"\n");
                }
            }

            /*
             * At 0x34FC the increment has already happened.
             * Only count==0 enters the wake/scheduler path.
             */
            if (wait_obj &&
                pc == 0x800034FCU &&
                (uint32_t)env->regs[0] == wait_obj)
            {
                uint32_t count=0;

                cpu_physical_memory_read(
                    wait_obj+0x08,&count,4);

                if (count == 0)
                {
                    give0_n++;

                    R20EA_LOG(
                        "TARGET=FY_GIVE0 N=%u "
                        "OBJ=%08X COUNT=%08X "
                        "LR=%08X SP=%08X "
                        "R0=%08X R1=%08X R2=%08X R3=%08X",
                        give0_n,
                        wait_obj,count,
                        (uint32_t)env->regs[14],
                        (uint32_t)env->regs[13],
                        (uint32_t)env->regs[0],
                        (uint32_t)env->regs[1],
                        (uint32_t)env->regs[2],
                        (uint32_t)env->regs[3]);
                }
            }

            /*
             * Target of BL at 0x8000351A.
             */
            if (wait_obj &&
                pc == 0x8000087EU)
            {
                uint32_t f14=0;
                uint32_t cur=0;

                cpu_physical_memory_read(rec+0x14,&f14,4);
                cpu_physical_memory_read(0x000045A4U,&cur,4);

                sched_n++;

                R20EA_LOG(
                    "TARGET=FY_SCHED_ENTRY N=%u "
                    "CUR=%08X TARGETREC=%08X F14=%08X "
                    "R0=%08X R1=%08X R2=%08X R3=%08X "
                    "R4=%08X R5=%08X R6=%08X R7=%08X "
                    "LR=%08X SP=%08X",
                    sched_n,
                    cur,rec,f14,
                    (uint32_t)env->regs[0],
                    (uint32_t)env->regs[1],
                    (uint32_t)env->regs[2],
                    (uint32_t)env->regs[3],
                    (uint32_t)env->regs[4],
                    (uint32_t)env->regs[5],
                    (uint32_t)env->regs[6],
                    (uint32_t)env->regs[7],
                    (uint32_t)env->regs[14],
                    (uint32_t)env->regs[13]);
            }

            /*
             * Real unblock path; record every task, no pending heuristic.
             */
            if (armed &&
                pc == 0x800018A6U)
            {
                uint32_t task=(uint32_t)env->regs[4];
                uint32_t f14=0;

                if (task)
                    cpu_physical_memory_read(task+0x14,&f14,4);

                R20EA_LOG(
                    "TARGET=FY_UNBLOCK "
                    "TASK=%08X TARGETTASK=%d "
                    "F14=%08X "
                    "LR=%08X SP=%08X "
                    "R0=%08X R1=%08X R2=%08X R3=%08X",
                    task,
                    task==rec,
                    f14,
                    (uint32_t)env->regs[14],
                    (uint32_t)env->regs[13],
                    (uint32_t)env->regs[0],
                    (uint32_t)env->regs[1],
                    (uint32_t)env->regs[2],
                    (uint32_t)env->regs[3]);
            }
        }

        /* QEMU40PAD-BC-R20FZ-GIVEHELPER */
        if (0)
        {
            static int armed=0;
            static uint32_t rec=0;
            static uint32_t wait_obj=0;
            static uint32_t prev_f14=0;
            static unsigned helper_n=0;
            static unsigned wake_n=0;

            const uint32_t target_raw=0x046600C4U;

            if (!armed && pc == 0x80001734U)
            {
                uint32_t arg=(uint32_t)env->regs[0];
                uint32_t raw=0;

                if (arg)
                    cpu_physical_memory_read(arg+0x10,&raw,4);

                if (raw == target_raw)
                {
                    rec=(uint32_t)env->regs[4];
                    cpu_physical_memory_read(rec+0x14,&prev_f14,4);
                    armed=1;

                    R20EA_LOG(
                        "TARGET=FZ_ARM REC=%08X F14=%08X",
                        rec,prev_f14);
                }
            }

            if (armed &&
                !wait_obj &&
                pc == 0x80003560U &&
                (uint32_t)env->regs[4] == rec &&
                (uint32_t)env->regs[2] == 0x0000022BU)
            {
                wait_obj=(uint32_t)env->regs[5];

                R20EA_LOG(
                    "TARGET=FZ_WAITOBJ OBJ=%08X",
                    wait_obj);
            }

            /*
             * True helper called by BL at 0x8000351C.
             * Thumb LR after that BL is 0x80003521.
             */
            if (wait_obj &&
                pc == 0x80000880U &&
                (uint32_t)env->regs[14] == 0x80003521U)
            {
                uint32_t count=0;

                cpu_physical_memory_read(wait_obj+0x08,&count,4);

                helper_n++;

                R20EA_LOG(
                    "TARGET=FZ_HELPER N=%u "
                    "OBJ=%08X COUNT=%08X "
                    "R0=%08X R1=%08X R2=%08X R3=%08X "
                    "R4=%08X R5=%08X R6=%08X R7=%08X "
                    "LR=%08X SP=%08X",
                    helper_n,
                    wait_obj,count,
                    (uint32_t)env->regs[0],
                    (uint32_t)env->regs[1],
                    (uint32_t)env->regs[2],
                    (uint32_t)env->regs[3],
                    (uint32_t)env->regs[4],
                    (uint32_t)env->regs[5],
                    (uint32_t)env->regs[6],
                    (uint32_t)env->regs[7],
                    (uint32_t)env->regs[14],
                    (uint32_t)env->regs[13]);
            }

            /*
             * Log only real F14 transitions of DispDCtrl.
             */
            if (armed)
            {
                uint32_t f14=0;
                cpu_physical_memory_read(rec+0x14,&f14,4);

                if (f14 != prev_f14)
                {
                    R20EA_LOG(
                        "TARGET=FZ_F14 "
                        "OLD=%08X NEW=%08X "
                        "PC=%08X LR=%08X SP=%08X",
                        prev_f14,f14,
                        pc,
                        (uint32_t)env->regs[14],
                        (uint32_t)env->regs[13]);

                    if (prev_f14 == wait_obj &&
                        f14 == rec)
                    {
                        wake_n++;

                        R20EA_LOG(
                            "TARGET=FZ_TARGET_WAKE N=%u "
                            "PC=%08X LR=%08X",
                            wake_n,
                            pc,
                            (uint32_t)env->regs[14]);
                    }

                    prev_f14=f14;
                }
            }
        }

        /* QEMU40PAD-BC-R20GA-HELPER */
        if (0)
        {
            static int armed=0;
            static uint32_t rec=0;
            static uint32_t obj22b=0;
            static uint32_t obj22f=0;
            static unsigned call_n=0;

            const uint32_t target_raw=0x046600C4U;

            if (!armed && pc == 0x80001734U)
            {
                uint32_t arg=(uint32_t)env->regs[0];
                uint32_t raw=0;

                if (arg)
                    cpu_physical_memory_read(arg+0x10,&raw,4);

                if (raw == target_raw)
                {
                    rec=(uint32_t)env->regs[4];
                    armed=1;

                    R20EA_LOG(
                        "TARGET=GA_ARM REC=%08X",
                        rec);
                }
            }

            /*
             * Discover objects from the wait primitive itself.
             */
            if (armed &&
                pc == 0x80003560U &&
                (uint32_t)env->regs[4] == rec)
            {
                uint32_t id=(uint32_t)env->regs[2];
                uint32_t obj=(uint32_t)env->regs[5];

                if (id == 0x22B && !obj22b)
                {
                    obj22b=obj;
                    R20EA_LOG(
                        "TARGET=GA_OBJ22B OBJ=%08X",
                        obj22b);
                }

                if (id == 0x22F && !obj22f)
                {
                    obj22f=obj;
                    R20EA_LOG(
                        "TARGET=GA_OBJ22F OBJ=%08X",
                        obj22f);
                }
            }

            /*
             * Helper entry, only for the two interesting objects.
             */
            if (armed &&
                pc == 0x80000880U &&
                (uint32_t)env->regs[14] == 0x80003521U)
            {
                uint32_t r0=(uint32_t)env->regs[0];

                if (r0 == obj22b || r0 == obj22f)
                {
                    uint32_t c=0,o0c=0,o10=0,o14=0,o18=0;

                    cpu_physical_memory_read(r0+0x08,&c,4);
                    cpu_physical_memory_read(r0+0x0C,&o0c,4);
                    cpu_physical_memory_read(r0+0x10,&o10,4);
                    cpu_physical_memory_read(r0+0x14,&o14,4);
                    cpu_physical_memory_read(r0+0x18,&o18,4);

                    call_n++;

                    R20EA_LOG(
                        "TARGET=GA_ENTRY N=%u "
                        "OBJ=%08X TYPE=%s "
                        "C08=%08X O0C=%08X O10=%08X "
                        "O14=%08X O18=%08X "
                        "R1=%08X R2=%08X R3=%08X "
                        "SP=%08X",
                        call_n,r0,
                        r0==obj22b ? "22B" : "22F",
                        c,o0c,o10,o14,o18,
                        (uint32_t)env->regs[1],
                        (uint32_t)env->regs[2],
                        (uint32_t)env->regs[3],
                        (uint32_t)env->regs[13]);
                }
            }

            /*
             * Immediately after the initial object-resolution branch.
             * R4 is the structure that will then receive +0x48.
             */
            if (armed &&
                pc == 0x8000089CU)
            {
                uint32_t r4=(uint32_t)env->regs[4];

                if (r4 == obj22b || r4 == obj22f)
                {
                    R20EA_LOG(
                        "TARGET=GA_RESOLVED "
                        "R4=%08X TYPE=%s "
                        "R0=%08X R1=%08X R2=%08X R3=%08X "
                        "LR=%08X SP=%08X",
                        r4,
                        r4==obj22b ? "22B" : "22F",
                        (uint32_t)env->regs[0],
                        (uint32_t)env->regs[1],
                        (uint32_t)env->regs[2],
                        (uint32_t)env->regs[3],
                        (uint32_t)env->regs[14],
                        (uint32_t)env->regs[13]);
                }
            }

            /*
             * Snapshot at +0x48 manipulation stage.
             */
            if (armed &&
                pc == 0x800008A0U)
            {
                uint32_t r4=(uint32_t)env->regs[4];

                if (r4 == obj22b+0x48 ||
                    r4 == obj22f+0x48)
                {
                    R20EA_LOG(
                        "TARGET=GA_PLUS48 "
                        "BASE=%08X TYPE=%s "
                        "R4=%08X "
                        "R0=%08X R1=%08X R2=%08X R3=%08X "
                        "LR=%08X",
                        r4-0x48,
                        r4==(obj22b+0x48) ? "22B" : "22F",
                        r4,
                        (uint32_t)env->regs[0],
                        (uint32_t)env->regs[1],
                        (uint32_t)env->regs[2],
                        (uint32_t)env->regs[3],
                        (uint32_t)env->regs[14]);
                }
            }

            /*
             * Keep actual F14 transitions for correlation.
             */
            if (armed)
            {
                static uint32_t old14=0;
                static int init14=0;
                uint32_t f14=0;

                cpu_physical_memory_read(rec+0x14,&f14,4);

                if (!init14)
                {
                    old14=f14;
                    init14=1;
                }
                else if (f14 != old14)
                {
                    R20EA_LOG(
                        "TARGET=GA_F14 "
                        "OLD=%08X NEW=%08X "
                        "PC=%08X LR=%08X",
                        old14,f14,
                        pc,
                        (uint32_t)env->regs[14]);

                    old14=f14;
                }
            }
        }

        /* QEMU40PAD-BC-R20GB-RESOLVER */
        if (0)
        {
            static int armed=0;
            static uint32_t rec=0;
            static uint32_t obj22b=0;
            static uint32_t obj22f=0;

            static uint32_t current_obj=0;
            static uint32_t last22b=0xFFFFFFFFU;
            static uint32_t last22f=0xFFFFFFFFU;

            static unsigned n22b=0;
            static unsigned n22f=0;

            const uint32_t target_raw=0x046600C4U;

            if (!armed && pc == 0x80001734U)
            {
                uint32_t arg=(uint32_t)env->regs[0];
                uint32_t raw=0;

                if (arg)
                    cpu_physical_memory_read(arg+0x10,&raw,4);

                if (raw == target_raw)
                {
                    rec=(uint32_t)env->regs[4];
                    armed=1;

                    R20EA_LOG(
                        "TARGET=GB_ARM REC=%08X",
                        rec);
                }
            }

            /*
             * Discover 22B / 22F objects.
             */
            if (armed &&
                pc == 0x80003560U &&
                (uint32_t)env->regs[4] == rec)
            {
                uint32_t id=(uint32_t)env->regs[2];
                uint32_t obj=(uint32_t)env->regs[5];

                if (id == 0x22B && !obj22b)
                {
                    obj22b=obj;
                    R20EA_LOG(
                        "TARGET=GB_OBJ22B OBJ=%08X",
                        obj22b);
                }

                if (id == 0x22F && !obj22f)
                {
                    obj22f=obj;
                    R20EA_LOG(
                        "TARGET=GB_OBJ22F OBJ=%08X",
                        obj22f);
                }
            }

            /*
             * Entry into helper from GiveSemaphore.
             */
            if (armed &&
                pc == 0x80000880U &&
                (uint32_t)env->regs[14] == 0x80003521U)
            {
                uint32_t obj=(uint32_t)env->regs[0];

                if (obj == obj22b || obj == obj22f)
                    current_obj=obj;
                else
                    current_obj=0;
            }

            /*
             * Immediately after:
             *
             *   BL 0x8000265C
             *   MOV R4,R0
             *
             * Therefore R4 is the task/record resolved
             * from the RTOS object.
             */
            if (armed &&
                current_obj &&
                pc == 0x80000894U)
            {
                uint32_t resolved=(uint32_t)env->regs[4];
                uint32_t p8=0;
                uint32_t f14=0;
                uint8_t s48=0,s49=0;

                if (resolved)
                {
                    cpu_physical_memory_read(
                        resolved+0x08,&p8,4);
                    cpu_physical_memory_read(
                        resolved+0x14,&f14,4);
                    cpu_physical_memory_read(
                        resolved+0x48,&s48,1);
                    cpu_physical_memory_read(
                        resolved+0x49,&s49,1);
                }

                if (current_obj == obj22b)
                {
                    n22b++;

                    if (resolved != last22b ||
                        resolved == rec ||
                        n22b <= 8)
                    {
                        R20EA_LOG(
                            "TARGET=GB_RESOLVE "
                            "TYPE=22B N=%u "
                            "OBJ=%08X TASK=%08X TARGETTASK=%d "
                            "P8=%08X F14=%08X "
                            "S48=%02X S49=%02X "
                            "LR=%08X SP=%08X",
                            n22b,
                            current_obj,resolved,
                            resolved==rec,
                            p8,f14,
                            s48,s49,
                            (uint32_t)env->regs[14],
                            (uint32_t)env->regs[13]);
                    }

                    last22b=resolved;
                }
                else
                {
                    n22f++;

                    if (resolved != last22f ||
                        n22f <= 8)
                    {
                        R20EA_LOG(
                            "TARGET=GB_RESOLVE "
                            "TYPE=22F N=%u "
                            "OBJ=%08X TASK=%08X TARGETTASK=%d "
                            "P8=%08X F14=%08X "
                            "S48=%02X S49=%02X "
                            "LR=%08X SP=%08X",
                            n22f,
                            current_obj,resolved,
                            resolved==rec,
                            p8,f14,
                            s48,s49,
                            (uint32_t)env->regs[14],
                            (uint32_t)env->regs[13]);
                    }

                    last22f=resolved;
                }

                current_obj=0;
            }

            /*
             * Real F14 changes of DispDCtrl for correlation.
             */
            if (armed)
            {
                static int init=0;
                static uint32_t old14=0;
                uint32_t f14=0;

                cpu_physical_memory_read(rec+0x14,&f14,4);

                if (!init)
                {
                    old14=f14;
                    init=1;
                }
                else if (f14 != old14)
                {
                    R20EA_LOG(
                        "TARGET=GB_F14 "
                        "OLD=%08X NEW=%08X "
                        "PC=%08X LR=%08X",
                        old14,f14,
                        pc,
                        (uint32_t)env->regs[14]);

                    old14=f14;
                }
            }
        }

        /* QEMU40PAD-BC-R20GC-READY */
        if (0)
        {
            static int armed=0;
            static uint32_t rec=0;
            static unsigned cycle=0;

            const uint32_t target_raw=0x046600C4U;

            if (!armed && pc == 0x80001734U)
            {
                uint32_t arg=(uint32_t)env->regs[0];
                uint32_t raw=0;

                if (arg)
                    cpu_physical_memory_read(arg+0x10,&raw,4);

                if (raw == target_raw)
                {
                    rec=(uint32_t)env->regs[4];
                    armed=1;

                    R20EA_LOG(
                        "TARGET=GC_ARM REC=%08X",
                        rec);
                }
            }

#define GC_DUMP(tag) do {                                    \
                uint32_t p8=0,f14=0,f18=0,f28=0,f2c=0,f34=0; \
                uint8_t s48=0,s49=0,s4d=0;                   \
                cpu_physical_memory_read(rec+0x08,&p8,4);     \
                cpu_physical_memory_read(rec+0x14,&f14,4);    \
                cpu_physical_memory_read(rec+0x18,&f18,4);    \
                cpu_physical_memory_read(rec+0x28,&f28,4);    \
                cpu_physical_memory_read(rec+0x2C,&f2c,4);    \
                cpu_physical_memory_read(rec+0x34,&f34,4);    \
                cpu_physical_memory_read(rec+0x48,&s48,1);    \
                cpu_physical_memory_read(rec+0x49,&s49,1);    \
                cpu_physical_memory_read(rec+0x4D,&s4d,1);    \
                R20EA_LOG(                                    \
                    "TARGET=GC_%s CYCLE=%u "                  \
                    "P8=%08X F14=%08X F18=%08X "              \
                    "F28=%08X F2C=%08X F34=%08X "             \
                    "S48=%02X S49=%02X S4D=%02X "             \
                    "R0=%08X R1=%08X R2=%08X R3=%08X "       \
                    "R4=%08X LR=%08X SP=%08X",                \
                    tag,cycle,p8,f14,f18,f28,f2c,f34,          \
                    s48,s49,s4d,                               \
                    (uint32_t)env->regs[0],                    \
                    (uint32_t)env->regs[1],                    \
                    (uint32_t)env->regs[2],                    \
                    (uint32_t)env->regs[3],                    \
                    (uint32_t)env->regs[4],                    \
                    (uint32_t)env->regs[14],                   \
                    (uint32_t)env->regs[13]);                  \
            } while(0)

            /*
             * After resolver:
             * MOV R4,R0 has completed.
             */
            if (armed &&
                pc == 0x80000894U &&
                (uint32_t)env->regs[4] == rec)
            {
                cycle++;
                GC_DUMP("RESOLVED");
            }

            /*
             * After +0x48/+0x49 task flag update.
             * R4 has been restored to task base by post-index write.
             */
            if (armed &&
                pc == 0x800008AEU &&
                (uint32_t)env->regs[4] == rec)
            {
                GC_DUMP("FLAGS_DONE");
            }

            /*
             * Immediately before ready-list insertion region.
             */
            if (armed &&
                pc == 0x800008BCU &&
                (uint32_t)env->regs[4] == rec)
            {
                GC_DUMP("READY_PRE");
            }

            /*
             * Immediately after the BL into the list helper.
             * Previous reconstruction places BL around 0x800008C0.
             */
            if (armed &&
                pc == 0x800008C4U)
            {
                uint32_t f14=0;

                cpu_physical_memory_read(rec+0x14,&f14,4);

                if ((uint32_t)env->regs[4] == rec ||
                    f14 == rec ||
                    f14 == 0x002E3A90U)
                {
                    GC_DUMP("READY_POST");
                }
            }

            /*
             * Actual transition back to self.
             */
            if (armed &&
                pc == 0x800018A6U &&
                (uint32_t)env->regs[4] == rec)
            {
                GC_DUMP("SELF");
            }

#undef GC_DUMP
        }

        /* QEMU40PAD-BC-R20GD-READYWAIT */
        if (0)
        {
            static int armed=0;
            static int dumped=0;
            static int active=0;

            static uint32_t rec=0;
            static uint32_t wait_obj=0;
            static unsigned cycle=0;
            static unsigned self_n=0;

            const uint32_t target_raw=0x046600C4U;

#define GD_STATE(tag) do {                                   \
                uint32_t f14=0,f18=0,f28=0,f2c=0,f34=0;      \
                uint32_t w08=0,w0c=0,w10=0,w14=0;            \
                uint32_t w18=0,w1c=0,w20=0,w24=0;            \
                uint8_t s48=0,s49=0,s4d=0;                   \
                cpu_physical_memory_read(rec+0x14,&f14,4);    \
                cpu_physical_memory_read(rec+0x18,&f18,4);    \
                cpu_physical_memory_read(rec+0x28,&f28,4);    \
                cpu_physical_memory_read(rec+0x2C,&f2c,4);    \
                cpu_physical_memory_read(rec+0x34,&f34,4);    \
                cpu_physical_memory_read(rec+0x48,&s48,1);    \
                cpu_physical_memory_read(rec+0x49,&s49,1);    \
                cpu_physical_memory_read(rec+0x4D,&s4d,1);    \
                if (wait_obj) {                               \
                    cpu_physical_memory_read(wait_obj+0x08,&w08,4); \
                    cpu_physical_memory_read(wait_obj+0x0C,&w0c,4); \
                    cpu_physical_memory_read(wait_obj+0x10,&w10,4); \
                    cpu_physical_memory_read(wait_obj+0x14,&w14,4); \
                    cpu_physical_memory_read(wait_obj+0x18,&w18,4); \
                    cpu_physical_memory_read(wait_obj+0x1C,&w1c,4); \
                    cpu_physical_memory_read(wait_obj+0x20,&w20,4); \
                    cpu_physical_memory_read(wait_obj+0x24,&w24,4); \
                }                                             \
                R20EA_LOG(                                    \
                    "TARGET=GD_%s CYCLE=%u "                   \
                    "F14=%08X F18=%08X F28=%08X F2C=%08X F34=%08X " \
                    "S48=%02X S49=%02X S4D=%02X "             \
                    "W08=%08X W0C=%08X W10=%08X W14=%08X "    \
                    "W18=%08X W1C=%08X W20=%08X W24=%08X "    \
                    "R0=%08X R1=%08X R2=%08X R3=%08X "       \
                    "R4=%08X LR=%08X SP=%08X",                \
                    tag,cycle,                                 \
                    f14,f18,f28,f2c,f34,s48,s49,s4d,          \
                    w08,w0c,w10,w14,w18,w1c,w20,w24,          \
                    (uint32_t)env->regs[0],                    \
                    (uint32_t)env->regs[1],                    \
                    (uint32_t)env->regs[2],                    \
                    (uint32_t)env->regs[3],                    \
                    (uint32_t)env->regs[4],                    \
                    (uint32_t)env->regs[14],                   \
                    (uint32_t)env->regs[13]);                  \
            } while(0)

            if (!armed && pc == 0x80001734U)
            {
                uint32_t arg=(uint32_t)env->regs[0];
                uint32_t raw=0;

                if (arg)
                    cpu_physical_memory_read(arg+0x10,&raw,4);

                if (raw == target_raw)
                {
                    rec=(uint32_t)env->regs[4];
                    armed=1;

                    R20EA_LOG(
                        "TARGET=GD_ARM REC=%08X",
                        rec);
                }
            }

            /*
             * Discover semaphore 22B.
             */
            if (armed &&
                !wait_obj &&
                pc == 0x80003560U &&
                (uint32_t)env->regs[4] == rec &&
                (uint32_t)env->regs[2] == 0x22BU)
            {
                wait_obj=(uint32_t)env->regs[5];

                R20EA_LOG(
                    "TARGET=GD_WAITOBJ OBJ=%08X",
                    wait_obj);
            }

            /*
             * One-time static code evidence.
             */
            if (armed && !dumped)
            {
                uint8_t b[16];
                uint32_t a;
                unsigned i;

                dumped=1;

                for(a=0x80000870U;a<0x800008F0U;a+=16)
                {
                    cpu_physical_memory_read(a,b,16);
                    fprintf(stderr,"[R20GD] READY_CODE=%08X",a);
                    for(i=0;i<16;i++)
                        fprintf(stderr," %02X",b[i]);
                    fprintf(stderr,"\n");
                }

                for(a=0x80001860U;a<0x800018D0U;a+=16)
                {
                    cpu_physical_memory_read(a,b,16);
                    fprintf(stderr,"[R20GD] UNLINK_CODE=%08X",a);
                    for(i=0;i<16;i++)
                        fprintf(stderr," %02X",b[i]);
                    fprintf(stderr,"\n");
                }

                for(a=0x80002640U;a<0x80002720U;a+=16)
                {
                    cpu_physical_memory_read(a,b,16);
                    fprintf(stderr,"[R20GD] LIST_CODE=%08X",a);
                    for(i=0;i<16;i++)
                        fprintf(stderr," %02X",b[i]);
                    fprintf(stderr,"\n");
                }
            }

            /*
             * Exact GiveSemaphore helper for semaphore 22B.
             */
            if (armed && wait_obj &&
                pc == 0x80000880U &&
                (uint32_t)env->regs[0] == wait_obj &&
                (uint32_t)env->regs[14] == 0x80003521U)
            {
                cycle++;
                active=1;
                GD_STATE("ENTRY");
            }

            /*
             * Resolver has returned and MOV R4,R0 completed.
             */
            if (active &&
                pc == 0x80000894U &&
                (uint32_t)env->regs[4] == rec)
            {
                GD_STATE("RESOLVED");
            }

            if (active &&
                pc == 0x800008AEU &&
                (uint32_t)env->regs[4] == rec)
            {
                GD_STATE("FLAGS");
            }

            if (active &&
                pc == 0x800008BCU &&
                (uint32_t)env->regs[4] == rec)
            {
                GD_STATE("LIST_PRE");
            }

            /*
             * Candidate list helper itself.
             */
            if (active &&
                pc == 0x800026C0U)
            {
                GD_STATE("LIST_ENTRY");
            }

            /*
             * Return from the list helper / continuation in 0x80000880.
             */
            if (active &&
                pc == 0x800008C4U &&
                (uint32_t)env->regs[4] == rec)
            {
                GD_STATE("LIST_POST");
                active=0;
            }

            /*
             * Real wait-list unlink / self transition.
             */
            if (armed &&
                pc == 0x800018A6U &&
                (uint32_t)env->regs[4] == rec)
            {
                self_n++;
                GD_STATE("SELF");

                R20EA_LOG(
                    "TARGET=GD_SELF_COUNT N=%u CYCLE=%u",
                    self_n,cycle);
            }

#undef GD_STATE
        }

        /* QEMU40PAD-BC-R20GE-RING */
        if (0)
        {
            typedef struct {
                uint32_t n, type, pc;
                uint32_t f14, w08;
                uint32_t r0,r1,r2,r3,r4,r5,lr,sp;
                uint8_t s48,s49,s4d;
            } ge_evt_t;

            static ge_evt_t ring[64];
            static unsigned seq=0, pos=0;
            static int armed=0, dumped=0, active=0;
            static uint32_t rec=0, wait_obj=0;

            const uint32_t target_raw=0x046600C4U;
            const uint32_t qobj=0x002E6BF4U;

#define GE_RECORD(t) do {                                    \
                ge_evt_t *e=&ring[pos++ & 63];               \
                uint32_t f14=0,w08=0;                         \
                uint8_t s48=0,s49=0,s4d=0;                   \
                if(rec) {                                     \
                    cpu_physical_memory_read(rec+0x14,&f14,4);\
                    cpu_physical_memory_read(rec+0x48,&s48,1);\
                    cpu_physical_memory_read(rec+0x49,&s49,1);\
                    cpu_physical_memory_read(rec+0x4D,&s4d,1);\
                }                                             \
                if(wait_obj)                                  \
                    cpu_physical_memory_read(wait_obj+8,&w08,4);\
                e->n=seq++; e->type=(t); e->pc=pc;            \
                e->f14=f14; e->w08=w08;                       \
                e->r0=(uint32_t)env->regs[0];                 \
                e->r1=(uint32_t)env->regs[1];                 \
                e->r2=(uint32_t)env->regs[2];                 \
                e->r3=(uint32_t)env->regs[3];                 \
                e->r4=(uint32_t)env->regs[4];                 \
                e->r5=(uint32_t)env->regs[5];                 \
                e->lr=(uint32_t)env->regs[14];                \
                e->sp=(uint32_t)env->regs[13];                \
                e->s48=s48; e->s49=s49; e->s4d=s4d;          \
            } while(0)

            if(!armed && pc==0x80001734U)
            {
                uint32_t arg=(uint32_t)env->regs[0],raw=0;
                if(arg) cpu_physical_memory_read(arg+0x10,&raw,4);

                if(raw==target_raw)
                {
                    rec=(uint32_t)env->regs[4];
                    armed=1;
                    GE_RECORD(1); /* ARM */
                }
            }

            /* DispDCtrl enters the known 0x22B wait object. */
            if(armed &&
               pc==0x80003560U &&
               (uint32_t)env->regs[4]==rec &&
               (uint32_t)env->regs[2]==0x22BU)
            {
                wait_obj=(uint32_t)env->regs[5];
                GE_RECORD(2); /* WAIT22B */
            }

            /* Exact Give-side helper for the discovered object. */
            if(wait_obj &&
               pc==0x80000880U &&
               (uint32_t)env->regs[0]==wait_obj &&
               (uint32_t)env->regs[14]==0x80003521U)
            {
                active=1;
                GE_RECORD(3); /* HELPER ENTRY */
            }

            if(active &&
               pc==0x80000894U &&
               (uint32_t)env->regs[4]==rec)
                GE_RECORD(4); /* RESOLVED */

            if(active &&
               pc==0x800008AEU &&
               (uint32_t)env->regs[4]==rec)
                GE_RECORD(5); /* FLAGS */

            if(active &&
               pc==0x800008BCU &&
               (uint32_t)env->regs[4]==rec)
                GE_RECORD(6); /* LIST PRE */

            if(active && pc==0x800026C0U)
                GE_RECORD(7); /* LIST ENTRY */

            if(active &&
               pc==0x800008C4U &&
               (uint32_t)env->regs[4]==rec)
            {
                GE_RECORD(8); /* LIST POST */
                active=0;
            }

            if(armed &&
               pc==0x800018A6U &&
               (uint32_t)env->regs[4]==rec)
                GE_RECORD(9); /* SELF/UNLINK PATH */

            /*
             * Dump only at the proven failing deferred state.
             */
            if(armed && !dumped &&
               pc==0x80003B2EU &&
               (uint32_t)env->regs[4]==qobj)
            {
                uint16_t a=0,q=0,w=0,r=0;

                cpu_physical_memory_read(qobj+0x0C,&a,2);
                cpu_physical_memory_read(qobj+0x12,&q,2);
                cpu_physical_memory_read(qobj+0x18,&w,2);
                cpu_physical_memory_read(qobj+0x1A,&r,2);

                if(a==0 && q==1 && w==4 && r==3)
                {
                    unsigned total=seq;
                    unsigned start=total>64 ? total-64 : 0;
                    unsigned i;

                    dumped=1;

                    R20EA_LOG(
                        "TARGET=GE_CRITICAL REC=%08X WAITOBJ=%08X "
                        "EVENTS=%u ACTIVE=%04X Q=%04X W=%04X R=%04X",
                        rec,wait_obj,total,a,q,w,r);

                    for(i=start;i<total;i++)
                    {
                        ge_evt_t *e=&ring[i & 63];

                        R20EA_LOG(
                            "TARGET=GE_EVT N=%u T=%u PC=%08X "
                            "F14=%08X W08=%08X "
                            "S48=%02X S49=%02X S4D=%02X "
                            "R0=%08X R1=%08X R2=%08X R3=%08X "
                            "R4=%08X R5=%08X LR=%08X SP=%08X",
                            e->n,e->type,e->pc,
                            e->f14,e->w08,
                            e->s48,e->s49,e->s4d,
                            e->r0,e->r1,e->r2,e->r3,
                            e->r4,e->r5,e->lr,e->sp);
                    }
                }
            }

#undef GE_RECORD
        }

        /* QEMU40PAD-BC-R20GF-UNLINKCALLER */
        if (0)
        {
            typedef struct {
                uint32_t n,type,pc;
                uint32_t f14,w08;
                uint32_t r0,r1,r2,r3,r4,r5,r6,r7,lr,sp;
                uint8_t s4d;
            } gf_evt_t;

            static gf_evt_t ring[64];
            static unsigned seq=0,pos=0;
            static int armed=0,dumped=0;
            static uint32_t rec=0,wait_obj=0;

            const uint32_t target_raw=0x046600C4U;
            const uint32_t qobj=0x002E6BF4U;

#define GF_REC(t) do {                                       \
                gf_evt_t *e=&ring[pos++ & 63];               \
                uint32_t f14=0,w08=0;                         \
                uint8_t s4d=0;                               \
                if(rec) {                                    \
                    cpu_physical_memory_read(rec+0x14,&f14,4);\
                    cpu_physical_memory_read(rec+0x4D,&s4d,1);\
                }                                            \
                if(wait_obj)                                 \
                    cpu_physical_memory_read(wait_obj+8,&w08,4);\
                e->n=seq++; e->type=(t); e->pc=pc;           \
                e->f14=f14; e->w08=w08; e->s4d=s4d;          \
                e->r0=env->regs[0]; e->r1=env->regs[1];      \
                e->r2=env->regs[2]; e->r3=env->regs[3];      \
                e->r4=env->regs[4]; e->r5=env->regs[5];      \
                e->r6=env->regs[6]; e->r7=env->regs[7];      \
                e->lr=env->regs[14]; e->sp=env->regs[13];    \
            } while(0)

            if(!armed && pc==0x80001734U)
            {
                uint32_t arg=env->regs[0],raw=0;
                if(arg)
                    cpu_physical_memory_read(arg+0x10,&raw,4);

                if(raw==target_raw)
                {
                    rec=env->regs[4];
                    armed=1;
                    GF_REC(1);
                }
            }

            if(armed &&
               pc==0x80003560U &&
               env->regs[4]==rec &&
               env->regs[2]==0x22BU)
            {
                wait_obj=env->regs[5];
                GF_REC(2); /* WAIT22B */
            }

            /*
             * Suspected Thumb BL site whose successful LR is 0x80000DBF.
             */
            if(armed &&
               pc>=0x80000DB0U &&
               pc<=0x80000DC4U)
                GF_REC(3); /* CALLER REGION */

            /*
             * Function containing the proven unlink/self operation.
             */
            if(armed &&
               pc==0x80001868U)
                GF_REC(4); /* UNLINK FUNCTION ENTRY */

            /*
             * Exact successful transition.
             */
            if(armed &&
               pc==0x800018A6U &&
               env->regs[4]==rec)
                GF_REC(5); /* SELF */

            /*
             * A few internal branch points from the static dump.
             */
            if(armed &&
               (pc==0x80001882U ||
                pc==0x8000188AU ||
                pc==0x80001894U ||
                pc==0x8000189EU ||
                pc==0x800018A4U))
                GF_REC(6); /* UNLINK INTERNAL */

            if(armed && !dumped &&
               pc==0x80003B2EU &&
               env->regs[4]==qobj)
            {
                uint16_t a=0,q=0,w=0,r=0;

                cpu_physical_memory_read(qobj+0x0C,&a,2);
                cpu_physical_memory_read(qobj+0x12,&q,2);
                cpu_physical_memory_read(qobj+0x18,&w,2);
                cpu_physical_memory_read(qobj+0x1A,&r,2);

                if(a==0 && q==1 && w==4 && r==3)
                {
                    unsigned total=seq;
                    unsigned start=total>64 ? total-64 : 0;
                    unsigned i;
                    uint8_t b[16];
                    uint32_t x;
                    unsigned j;

                    dumped=1;

                    R20EA_LOG(
                        "TARGET=GF_CRITICAL REC=%08X WAITOBJ=%08X "
                        "EVENTS=%u",
                        rec,wait_obj,total);

                    /*
                     * Dump suspected caller only now, so zero early timing cost.
                     */
                    for(x=0x80000D80U;x<0x80000DE0U;x+=16)
                    {
                        cpu_physical_memory_read(x,b,16);

                        fprintf(stderr,
                            "[R20GF] CALLER_CODE=%08X",x);

                        for(j=0;j<16;j++)
                            fprintf(stderr," %02X",b[j]);

                        fprintf(stderr,"\n");
                    }

                    for(i=start;i<total;i++)
                    {
                        gf_evt_t *e=&ring[i & 63];

                        R20EA_LOG(
                            "TARGET=GF_EVT N=%u T=%u PC=%08X "
                            "F14=%08X W08=%08X S4D=%02X "
                            "R0=%08X R1=%08X R2=%08X R3=%08X "
                            "R4=%08X R5=%08X R6=%08X R7=%08X "
                            "LR=%08X SP=%08X",
                            e->n,e->type,e->pc,
                            e->f14,e->w08,e->s4d,
                            e->r0,e->r1,e->r2,e->r3,
                            e->r4,e->r5,e->r6,e->r7,
                            e->lr,e->sp);
                    }
                }
            }

#undef GF_REC
        }

        /* QEMU40PAD-BC-R20GG-READYSELECT */
        if (0)
        {
            typedef struct {
                uint32_t n,t,pc;
                uint32_t cur,f14;
                uint32_t q0,q4,t0,t4;
                uint32_t r0,r1,r2,r3,r4,r5,r6,r7,lr;
            } gg_evt_t;

            static gg_evt_t ring[64];
            static unsigned seq=0,pos=0;
            static int armed=0,dumped=0;
            static uint32_t rec=0,wait_obj=0;
            static uint32_t readyq=0;

            const uint32_t target_raw=0x046600C4U;
            const uint32_t qobj=0x002E6BF4U;

#define GG_REC(type) do {                                    \
                gg_evt_t *e=&ring[pos++ & 63];               \
                uint32_t cur=0,f14=0,q0=0,q4=0,t0=0,t4=0;    \
                cpu_physical_memory_read(0x45A4,&cur,4);      \
                if(rec) {                                    \
                    cpu_physical_memory_read(rec+0x14,&f14,4);\
                    cpu_physical_memory_read(rec+0,&t0,4);    \
                    cpu_physical_memory_read(rec+4,&t4,4);    \
                }                                            \
                if(readyq) {                                 \
                    cpu_physical_memory_read(readyq+0,&q0,4);\
                    cpu_physical_memory_read(readyq+4,&q4,4);\
                }                                            \
                e->n=seq++; e->t=(type); e->pc=pc;           \
                e->cur=cur; e->f14=f14;                      \
                e->q0=q0; e->q4=q4; e->t0=t0; e->t4=t4;     \
                e->r0=env->regs[0]; e->r1=env->regs[1];      \
                e->r2=env->regs[2]; e->r3=env->regs[3];      \
                e->r4=env->regs[4]; e->r5=env->regs[5];      \
                e->r6=env->regs[6]; e->r7=env->regs[7];      \
                e->lr=env->regs[14];                         \
            } while(0)

            if(!armed && pc==0x80001734U)
            {
                uint32_t arg=env->regs[0],raw=0;
                if(arg)
                    cpu_physical_memory_read(arg+0x10,&raw,4);

                if(raw==target_raw)
                {
                    rec=env->regs[4];
                    armed=1;
                    readyq=0x002E0DF4U + 0x12U*8U;
                    GG_REC(1);
                }
            }

            if(armed &&
               pc==0x80003560U &&
               env->regs[4]==rec &&
               env->regs[2]==0x22BU)
            {
                wait_obj=env->regs[5];
                GG_REC(2);       /* wait 22B */
            }

            /*
             * Exact insertion of DispDCtrl into priority-0x12 queue.
             */
            if(armed &&
               pc==0x800026C0U &&
               env->regs[0]==readyq &&
               env->regs[1]==rec)
                GG_REC(3);       /* list entry */

            if(armed &&
               pc==0x800008C4U &&
               env->regs[4]==rec)
                GG_REC(4);       /* after insertion */

            /*
             * Scheduler bookkeeping immediately following insertion.
             */
            if(armed &&
               (pc==0x800008C6U ||
                pc==0x800008CAU ||
                pc==0x800008CEU ||
                pc==0x800008D0U ||
                pc==0x800008D4U ||
                pc==0x800008D8U ||
                pc==0x800008DCU ||
                pc==0x800008E8U))
                GG_REC(5);

            /*
             * Wrapper that invokes scheduler/task-state function.
             */
            if(armed &&
               pc>=0x80000DB0U &&
               pc<=0x80000DC2U)
                GG_REC(6);

            /*
             * Which task is actually being processed.
             */
            if(armed &&
               (pc==0x80001882U ||
                pc==0x800018A6U))
                GG_REC(7);

            if(armed && !dumped &&
               pc==0x80003B2EU &&
               env->regs[4]==qobj)
            {
                uint16_t a=0,q=0,w=0,r=0;

                cpu_physical_memory_read(qobj+0x0C,&a,2);
                cpu_physical_memory_read(qobj+0x12,&q,2);
                cpu_physical_memory_read(qobj+0x18,&w,2);
                cpu_physical_memory_read(qobj+0x1A,&r,2);

                if(a==0 && q==1 && w==4 && r==3)
                {
                    unsigned total=seq;
                    unsigned start=total>64 ? total-64 : 0;
                    unsigned i;

                    dumped=1;

                    R20EA_LOG(
                        "TARGET=GG_CRITICAL REC=%08X READYQ=%08X EVENTS=%u",
                        rec,readyq,total);

                    for(i=start;i<total;i++)
                    {
                        gg_evt_t *e=&ring[i & 63];

                        R20EA_LOG(
                            "TARGET=GG_EVT N=%u T=%u PC=%08X "
                            "CUR=%08X F14=%08X "
                            "Q0=%08X Q4=%08X "
                            "T0=%08X T4=%08X "
                            "R0=%08X R1=%08X R2=%08X R3=%08X "
                            "R4=%08X R5=%08X R6=%08X R7=%08X "
                            "LR=%08X",
                            e->n,e->t,e->pc,
                            e->cur,e->f14,
                            e->q0,e->q4,e->t0,e->t4,
                            e->r0,e->r1,e->r2,e->r3,
                            e->r4,e->r5,e->r6,e->r7,
                            e->lr);
                    }
                }
            }

#undef GG_REC
        }

        /* QEMU40PAD-BC-R20GH-DEQUEUE */
        if (0)
        {
            typedef struct {
                uint32_t n,t,pc;
                uint32_t hiq,q0,q4,f14;
                uint32_t r0,r1,r2,r3,r4,r5,lr,sp;
            } gh_evt_t;

            static gh_evt_t ring[64];
            static unsigned seq=0,pos=0;
            static int armed=0,dumped=0;
            static int pop_active=0;

            static uint32_t rec=0;
            static uint32_t pop_lr=0;

            const uint32_t target_raw=0x046600C4U;
            const uint32_t qobj=0x002E6BF4U;
            const uint32_t readyq=0x002E0E84U;

#define GH_REC(type) do {                                    \
                gh_evt_t *e=&ring[pos++ & 63];               \
                uint32_t hiq=0,q0=0,q4=0,f14=0;              \
                cpu_physical_memory_read(0x45B0,&hiq,4);      \
                cpu_physical_memory_read(readyq+0,&q0,4);    \
                cpu_physical_memory_read(readyq+4,&q4,4);    \
                if(rec)                                       \
                    cpu_physical_memory_read(rec+0x14,&f14,4);\
                e->n=seq++; e->t=(type); e->pc=pc;           \
                e->hiq=hiq; e->q0=q0; e->q4=q4; e->f14=f14; \
                e->r0=env->regs[0]; e->r1=env->regs[1];      \
                e->r2=env->regs[2]; e->r3=env->regs[3];      \
                e->r4=env->regs[4]; e->r5=env->regs[5];      \
                e->lr=env->regs[14]; e->sp=env->regs[13];    \
            } while(0)

            if(!armed && pc==0x80001734U)
            {
                uint32_t arg=env->regs[0],raw=0;

                if(arg)
                    cpu_physical_memory_read(arg+0x10,&raw,4);

                if(raw==target_raw)
                {
                    rec=env->regs[4];
                    armed=1;
                    GH_REC(1);
                }
            }

            /*
             * Exact insertion of DispDCtrl into ready queue 0x12.
             */
            if(armed &&
               pc==0x800026C0U &&
               env->regs[0]==readyq &&
               env->regs[1]==rec)
                GH_REC(2);

            if(armed &&
               pc==0x800008C4U &&
               env->regs[4]==rec)
                GH_REC(3);

            /*
             * 0x8000265C appears to be the list extractor.
             * Capture specifically calls operating on the 0x12 queue.
             */
            if(armed &&
               pc==0x8000265CU &&
               env->regs[0]==readyq)
            {
                pop_active=1;
                pop_lr=env->regs[14];
                GH_REC(4);
            }

            /*
             * Last instruction region of 0x8000265C.
             * Record R0 before returning to caller.
             */
            if(pop_active &&
               pc==0x80002682U)
            {
                GH_REC(5);
                pop_active=0;
            }

            /*
             * Also catch execution at the caller's return address,
             * if it is encountered as a TB-visible PC.
             */
            if(armed &&
               pop_lr &&
               pc==(pop_lr & ~1U))
            {
                GH_REC(6);
                pop_lr=0;
            }

            /*
             * Track only changes around highest-ready queue bookkeeping.
             */
            if(armed &&
               (pc==0x800008C4U ||
                pc==0x800008C6U ||
                pc==0x800008CAU ||
                pc==0x800008CCU ||
                pc==0x800008E6U ||
                pc==0x800008E8U ||
                pc==0x800008EAU))
                GH_REC(7);

            if(armed && !dumped &&
               pc==0x80003B2EU &&
               env->regs[4]==qobj)
            {
                uint16_t a=0,q=0,w=0,r=0;

                cpu_physical_memory_read(qobj+0x0C,&a,2);
                cpu_physical_memory_read(qobj+0x12,&q,2);
                cpu_physical_memory_read(qobj+0x18,&w,2);
                cpu_physical_memory_read(qobj+0x1A,&r,2);

                if(a==0 && q==1 && w==4 && r==3)
                {
                    unsigned total=seq;
                    unsigned start=total>64 ? total-64 : 0;
                    unsigned i;

                    dumped=1;

                    R20EA_LOG(
                        "TARGET=GH_CRITICAL REC=%08X READYQ=%08X "
                        "EVENTS=%u",
                        rec,readyq,total);

                    for(i=start;i<total;i++)
                    {
                        gh_evt_t *e=&ring[i & 63];

                        R20EA_LOG(
                            "TARGET=GH_EVT N=%u T=%u PC=%08X "
                            "HIQ=%08X Q0=%08X Q4=%08X F14=%08X "
                            "R0=%08X R1=%08X R2=%08X R3=%08X "
                            "R4=%08X R5=%08X LR=%08X SP=%08X",
                            e->n,e->t,e->pc,
                            e->hiq,e->q0,e->q4,e->f14,
                            e->r0,e->r1,e->r2,e->r3,
                            e->r4,e->r5,e->lr,e->sp);
                    }
                }
            }

#undef GH_REC
        }

        /* QEMU40PAD-BC-R20GI-WRITER */
        if (0)
        {
            typedef struct {
                uint32_t n,mask,pc,lr;
                uint32_t oq0,nq0,oq4,nq4;
                uint32_t ohi,nhi,of14,nf14;
                uint32_t r0,r1,r2,r3,r4,r5,r6,r7,sp;
                uint8_t os4d,ns4d;
            } gi_evt_t;

            static gi_evt_t ring[128];
            static unsigned seq=0,pos=0;

            static int armed=0,dumped=0,initialized=0;
            static uint32_t rec=0;

            static uint32_t old_q0=0,old_q4=0;
            static uint32_t old_hi=0,old_f14=0;
            static uint8_t old_s4d=0;

            const uint32_t target_raw=0x046600C4U;
            const uint32_t qobj=0x002E6BF4U;
            const uint32_t rq=0x002E0E84U;

#define GI_CAPTURE(mask_,q0_,q4_,hi_,f14_,s4d_) do {         \
                gi_evt_t *e=&ring[pos++ & 127];              \
                e->n=seq++;                                  \
                e->mask=(mask_);                             \
                e->pc=pc;                                    \
                e->lr=env->regs[14];                         \
                e->oq0=old_q0; e->nq0=(q0_);                 \
                e->oq4=old_q4; e->nq4=(q4_);                 \
                e->ohi=old_hi; e->nhi=(hi_);                 \
                e->of14=old_f14; e->nf14=(f14_);             \
                e->os4d=old_s4d; e->ns4d=(s4d_);             \
                e->r0=env->regs[0]; e->r1=env->regs[1];      \
                e->r2=env->regs[2]; e->r3=env->regs[3];      \
                e->r4=env->regs[4]; e->r5=env->regs[5];      \
                e->r6=env->regs[6]; e->r7=env->regs[7];      \
                e->sp=env->regs[13];                         \
            } while(0)

            if(!armed && pc==0x80001734U)
            {
                uint32_t arg=env->regs[0],raw=0;

                if(arg)
                    cpu_physical_memory_read(arg+0x10,&raw,4);

                if(raw==target_raw)
                {
                    rec=env->regs[4];
                    armed=1;
                }
            }

            if(armed)
            {
                uint32_t q0=0,q4=0,hi=0,f14=0;
                uint8_t s4d=0;

                cpu_physical_memory_read(rq+0,&q0,4);
                cpu_physical_memory_read(rq+4,&q4,4);
                cpu_physical_memory_read(0x45B0,&hi,4);
                cpu_physical_memory_read(rec+0x14,&f14,4);
                cpu_physical_memory_read(rec+0x4D,&s4d,1);

                if(!initialized)
                {
                    old_q0=q0; old_q4=q4;
                    old_hi=hi; old_f14=f14;
                    old_s4d=s4d;
                    initialized=1;
                }
                else
                {
                    uint32_t mask=0;

                    if(q0 != old_q0)   mask |= 1;
                    if(q4 != old_q4)   mask |= 2;
                    if(hi != old_hi)   mask |= 4;
                    if(f14 != old_f14) mask |= 8;
                    if(s4d != old_s4d) mask |= 16;

                    if(mask)
                    {
                        GI_CAPTURE(mask,q0,q4,hi,f14,s4d);

                        old_q0=q0;
                        old_q4=q4;
                        old_hi=hi;
                        old_f14=f14;
                        old_s4d=s4d;
                    }
                }
            }

            if(armed && !dumped &&
               pc==0x80003B2EU &&
               env->regs[4]==qobj)
            {
                uint16_t a=0,q=0,w=0,r=0;

                cpu_physical_memory_read(qobj+0x0C,&a,2);
                cpu_physical_memory_read(qobj+0x12,&q,2);
                cpu_physical_memory_read(qobj+0x18,&w,2);
                cpu_physical_memory_read(qobj+0x1A,&r,2);

                if(a==0 && q==1 && w==4 && r==3)
                {
                    unsigned total=seq;
                    unsigned start=total>128 ? total-128 : 0;
                    unsigned i;

                    dumped=1;

                    R20EA_LOG(
                        "TARGET=GI_CRITICAL REC=%08X READYQ=%08X "
                        "EVENTS=%u",
                        rec,rq,total);

                    for(i=start;i<total;i++)
                    {
                        gi_evt_t *e=&ring[i & 127];

                        R20EA_LOG(
                            "TARGET=GI_EVT N=%u MASK=%02X "
                            "PC=%08X LR=%08X "
                            "Q0=%08X>%08X Q4=%08X>%08X "
                            "HI=%08X>%08X "
                            "F14=%08X>%08X S4D=%02X>%02X "
                            "R0=%08X R1=%08X R2=%08X R3=%08X "
                            "R4=%08X R5=%08X R6=%08X R7=%08X "
                            "SP=%08X",
                            e->n,e->mask,e->pc,e->lr,
                            e->oq0,e->nq0,
                            e->oq4,e->nq4,
                            e->ohi,e->nhi,
                            e->of14,e->nf14,
                            e->os4d,e->ns4d,
                            e->r0,e->r1,e->r2,e->r3,
                            e->r4,e->r5,e->r6,e->r7,
                            e->sp);
                    }
                }
            }

#undef GI_CAPTURE
        }

        /* QEMU40PAD-BC-R20GJ-DISPATCH */
        if (0)
        {
            typedef struct {
                uint32_t n,t,pc,lr;
                uint32_t hi,q0,q4,f14;
                uint32_t r0,r1,r2,r3,r4,r5,r6,r7,sp;
                uint8_t s4d;
            } gj_evt_t;

            static gj_evt_t ring[96];
            static unsigned seq=0,pos=0;
            static int armed=0,dumped=0;
            static uint32_t rec=0;

            const uint32_t target_raw=0x046600C4U;
            const uint32_t qobj=0x002E6BF4U;
            const uint32_t rq=0x002E0E84U;

#define GJ_REC(type) do {                                    \
                gj_evt_t *e=&ring[pos++ % 96];               \
                uint32_t hi=0,q0=0,q4=0,f14=0;               \
                uint8_t s4d=0;                               \
                cpu_physical_memory_read(0x45B0,&hi,4);      \
                cpu_physical_memory_read(rq+0,&q0,4);        \
                cpu_physical_memory_read(rq+4,&q4,4);        \
                if(rec) {                                    \
                    cpu_physical_memory_read(rec+0x14,&f14,4);\
                    cpu_physical_memory_read(rec+0x4D,&s4d,1);\
                }                                            \
                e->n=seq++; e->t=(type); e->pc=pc;           \
                e->lr=env->regs[14];                         \
                e->hi=hi; e->q0=q0; e->q4=q4;               \
                e->f14=f14; e->s4d=s4d;                     \
                e->r0=env->regs[0]; e->r1=env->regs[1];      \
                e->r2=env->regs[2]; e->r3=env->regs[3];      \
                e->r4=env->regs[4]; e->r5=env->regs[5];      \
                e->r6=env->regs[6]; e->r7=env->regs[7];      \
                e->sp=env->regs[13];                         \
            } while(0)

            if(!armed && pc==0x80001734U)
            {
                uint32_t arg=env->regs[0],raw=0;

                if(arg)
                    cpu_physical_memory_read(arg+0x10,&raw,4);

                if(raw==target_raw)
                {
                    rec=env->regs[4];
                    armed=1;
                    GJ_REC(1);
                }
            }

            /*
             * Dispatcher/caller around return address 0x80000975.
             */
            if(armed &&
               pc>=0x80000940U &&
               pc<=0x800009B0U)
                GJ_REC(2);

            /*
             * Exact ready-list remove routine.
             */
            if(armed &&
               pc>=0x80002684U &&
               pc<=0x800026B8U &&
               (env->regs[0]==rq ||
                env->regs[1]==rec ||
                env->regs[2]==rec ||
                env->regs[4]==rec))
                GJ_REC(3);

            /*
             * Successful task-state transition.
             */
            if(armed &&
               (pc==0x800018A2U ||
                pc==0x800018A6U) &&
               env->regs[4]==rec)
                GJ_REC(4);

            if(armed && !dumped &&
               pc==0x80003B2EU &&
               env->regs[4]==qobj)
            {
                uint16_t a=0,q=0,w=0,r=0;

                cpu_physical_memory_read(qobj+0x0C,&a,2);
                cpu_physical_memory_read(qobj+0x12,&q,2);
                cpu_physical_memory_read(qobj+0x18,&w,2);
                cpu_physical_memory_read(qobj+0x1A,&r,2);

                if(a==0 && q==1 && w==4 && r==3)
                {
                    unsigned total=seq;
                    unsigned start=total>96 ? total-96 : 0;
                    unsigned i,j;
                    uint8_t b[16];
                    uint32_t x;

                    dumped=1;

                    R20EA_LOG(
                        "TARGET=GJ_CRITICAL REC=%08X EVENTS=%u",
                        rec,total);

                    for(x=0x80000920U;x<0x800009C0U;x+=16)
                    {
                        cpu_physical_memory_read(x,b,16);
                        fprintf(stderr,
                            "[R20GJ] DISPATCH_CODE=%08X",x);

                        for(j=0;j<16;j++)
                            fprintf(stderr," %02X",b[j]);

                        fprintf(stderr,"\n");
                    }

                    for(i=start;i<total;i++)
                    {
                        gj_evt_t *e=&ring[i % 96];

                        R20EA_LOG(
                            "TARGET=GJ_EVT N=%u T=%u PC=%08X LR=%08X "
                            "HI=%08X Q0=%08X Q4=%08X "
                            "F14=%08X S4D=%02X "
                            "R0=%08X R1=%08X R2=%08X R3=%08X "
                            "R4=%08X R5=%08X R6=%08X R7=%08X "
                            "SP=%08X",
                            e->n,e->t,e->pc,e->lr,
                            e->hi,e->q0,e->q4,
                            e->f14,e->s4d,
                            e->r0,e->r1,e->r2,e->r3,
                            e->r4,e->r5,e->r6,e->r7,
                            e->sp);
                    }
                }
            }

#undef GJ_REC
        }

        /* QEMU40PAD-BC-R20GK-BLOCKSCHED */
        if (0)
        {
            typedef struct {
                uint32_t n,t,pc,lr;
                uint32_t cur,hiq,q0,q4,f14;
                uint32_t r0,r1,r2,r3,r4,r5,r6,r7,sp;
                uint8_t s48,s49,s4d;
            } gk_evt_t;

            static gk_evt_t ring[128];
            static unsigned seq=0,pos=0;
            static int armed=0,dumped=0;
            static uint32_t rec=0;

            const uint32_t target_raw=0x046600C4U;
            const uint32_t qobj=0x002E6BF4U;
            const uint32_t rq=0x002E0E84U;

#define GK_REC(type) do {                                    \
                gk_evt_t *e=&ring[pos++ & 127];              \
                uint32_t cur=0,hiq=0,q0=0,q4=0,f14=0;        \
                uint8_t s48=0,s49=0,s4d=0;                  \
                cpu_physical_memory_read(0x45A4,&cur,4);     \
                cpu_physical_memory_read(0x45B0,&hiq,4);     \
                cpu_physical_memory_read(rq+0,&q0,4);        \
                cpu_physical_memory_read(rq+4,&q4,4);        \
                if(rec) {                                    \
                    cpu_physical_memory_read(rec+0x14,&f14,4);\
                    cpu_physical_memory_read(rec+0x48,&s48,1);\
                    cpu_physical_memory_read(rec+0x49,&s49,1);\
                    cpu_physical_memory_read(rec+0x4D,&s4d,1);\
                }                                            \
                e->n=seq++; e->t=(type); e->pc=pc;           \
                e->lr=env->regs[14];                         \
                e->cur=cur; e->hiq=hiq;                     \
                e->q0=q0; e->q4=q4; e->f14=f14;             \
                e->s48=s48; e->s49=s49; e->s4d=s4d;         \
                e->r0=env->regs[0]; e->r1=env->regs[1];      \
                e->r2=env->regs[2]; e->r3=env->regs[3];      \
                e->r4=env->regs[4]; e->r5=env->regs[5];      \
                e->r6=env->regs[6]; e->r7=env->regs[7];      \
                e->sp=env->regs[13];                         \
            } while(0)

            if(!armed && pc==0x80001734U)
            {
                uint32_t arg=env->regs[0],raw=0;

                if(arg)
                    cpu_physical_memory_read(arg+0x10,&raw,4);

                if(raw==target_raw)
                {
                    rec=env->regs[4];
                    armed=1;
                    GK_REC(1);
                }
            }

            /* Semaphore wait/block path for DispDCtrl. */
            if(armed &&
               (pc==0x80003560U ||
                pc==0x8000356CU ||
                pc==0x80003570U))
                GK_REC(2);

            /* block-current-task */
            if(armed &&
               (pc==0x8000095EU ||
                pc==0x80000970U ||
                pc==0x80000974U ||
                pc==0x8000098EU ||
                pc==0x80000992U ||
                pc==0x80000996U))
                GK_REC(3);

            /* scheduler/reselect called from 0x8000098E */
            if(armed &&
               pc>=0x8000085CU &&
               pc<=0x8000087EU)
                GK_REC(4);

            /* successful resume completion */
            if(armed &&
               (pc==0x800018A2U ||
                pc==0x800018A6U) &&
               env->regs[4]==rec)
                GK_REC(5);

            /* wake helper */
            if(armed &&
               (pc==0x80000880U ||
                pc==0x80000894U ||
                pc==0x800008C4U) &&
               env->regs[4]==rec)
                GK_REC(6);

            if(armed && !dumped &&
               pc==0x80003B2EU &&
               env->regs[4]==qobj)
            {
                uint16_t a=0,q=0,w=0,r=0;

                cpu_physical_memory_read(qobj+0x0C,&a,2);
                cpu_physical_memory_read(qobj+0x12,&q,2);
                cpu_physical_memory_read(qobj+0x18,&w,2);
                cpu_physical_memory_read(qobj+0x1A,&r,2);

                if(a==0 && q==1 && w==4 && r==3)
                {
                    unsigned total=seq;
                    unsigned start=total>128 ? total-128 : 0;
                    unsigned i,j;
                    uint32_t x;
                    uint8_t b[16];

                    dumped=1;

                    R20EA_LOG(
                        "TARGET=GK_CRITICAL REC=%08X EVENTS=%u",
                        rec,total);

                    for(x=0x80000840U;x<0x80000880U;x+=16)
                    {
                        cpu_physical_memory_read(x,b,16);
                        fprintf(stderr,
                            "[R20GK] SCHED_CODE=%08X",x);
                        for(j=0;j<16;j++)
                            fprintf(stderr," %02X",b[j]);
                        fprintf(stderr,"\n");
                    }

                    for(x=0x80003540U;x<0x80003590U;x+=16)
                    {
                        cpu_physical_memory_read(x,b,16);
                        fprintf(stderr,
                            "[R20GK] WAIT_CODE=%08X",x);
                        for(j=0;j<16;j++)
                            fprintf(stderr," %02X",b[j]);
                        fprintf(stderr,"\n");
                    }

                    for(i=start;i<total;i++)
                    {
                        gk_evt_t *e=&ring[i & 127];

                        R20EA_LOG(
                            "TARGET=GK_EVT N=%u T=%u PC=%08X LR=%08X "
                            "CUR=%08X HIQ=%08X "
                            "Q0=%08X Q4=%08X "
                            "F14=%08X S48=%02X S49=%02X S4D=%02X "
                            "R0=%08X R1=%08X R2=%08X R3=%08X "
                            "R4=%08X R5=%08X R6=%08X R7=%08X "
                            "SP=%08X",
                            e->n,e->t,e->pc,e->lr,
                            e->cur,e->hiq,e->q0,e->q4,
                            e->f14,e->s48,e->s49,e->s4d,
                            e->r0,e->r1,e->r2,e->r3,
                            e->r4,e->r5,e->r6,e->r7,
                            e->sp);
                    }
                }
            }

#undef GK_REC
        }

        /* QEMU40PAD-BC-R20GL-CURRENTWRITER */
        if (0)
        {
            typedef struct {
                uint32_t n,t,pc,lr;
                uint32_t ocur,ncur,hiq,q0,q4,f14;
                uint32_t r0,r1,r2,r3,r4,r5,r6,r7,sp;
                uint8_t s49,s4d;
            } gl_evt_t;

            static gl_evt_t ring[128];
            static unsigned seq=0,pos=0;
            static int armed=0,dumped=0,init=0;
            static uint32_t rec=0,old_cur=0;
            static uint32_t old_f14=0;
            static uint8_t old_s4d=0;

            const uint32_t target_raw=0x046600C4U;
            const uint32_t qobj=0x002E6BF4U;
            const uint32_t rq=0x002E0E84U;

#define GL_REC(type,oc,nc) do {                              \
                gl_evt_t *e=&ring[pos++ & 127];              \
                uint32_t hiq=0,q0=0,q4=0,f14=0;              \
                uint8_t s49=0,s4d=0;                         \
                cpu_physical_memory_read(0x45B0,&hiq,4);     \
                cpu_physical_memory_read(rq+0,&q0,4);        \
                cpu_physical_memory_read(rq+4,&q4,4);        \
                if(rec) {                                    \
                    cpu_physical_memory_read(rec+0x14,&f14,4);\
                    cpu_physical_memory_read(rec+0x49,&s49,1);\
                    cpu_physical_memory_read(rec+0x4D,&s4d,1);\
                }                                            \
                e->n=seq++; e->t=(type); e->pc=pc;           \
                e->lr=env->regs[14];                         \
                e->ocur=(oc); e->ncur=(nc);                  \
                e->hiq=hiq; e->q0=q0; e->q4=q4;             \
                e->f14=f14; e->s49=s49; e->s4d=s4d;         \
                e->r0=env->regs[0]; e->r1=env->regs[1];      \
                e->r2=env->regs[2]; e->r3=env->regs[3];      \
                e->r4=env->regs[4]; e->r5=env->regs[5];      \
                e->r6=env->regs[6]; e->r7=env->regs[7];      \
                e->sp=env->regs[13];                         \
            } while(0)

            if(!armed && pc==0x80001734U)
            {
                uint32_t arg=env->regs[0],raw=0;

                if(arg)
                    cpu_physical_memory_read(arg+0x10,&raw,4);

                if(raw==target_raw)
                {
                    rec=env->regs[4];
                    armed=1;
                }
            }

            if(armed)
            {
                uint32_t cur=0,f14=0;
                uint8_t s4d=0;

                cpu_physical_memory_read(0x45A4,&cur,4);
                cpu_physical_memory_read(rec+0x14,&f14,4);
                cpu_physical_memory_read(rec+0x4D,&s4d,1);

                if(!init)
                {
                    old_cur=cur;
                    old_f14=f14;
                    old_s4d=s4d;
                    init=1;
                }
                else
                {
                    if(cur != old_cur)
                    {
                        GL_REC(1,old_cur,cur);
                        old_cur=cur;
                    }

                    if(f14 != old_f14 || s4d != old_s4d)
                    {
                        GL_REC(2,cur,cur);
                        old_f14=f14;
                        old_s4d=s4d;
                    }
                }

                /*
                 * Proven successful resume points for target task.
                 */
                if((pc==0x800018A2U ||
                    pc==0x800018A6U) &&
                   env->regs[4]==rec)
                    GL_REC(3,cur,cur);
            }

            if(armed && !dumped &&
               pc==0x80003B2EU &&
               env->regs[4]==qobj)
            {
                uint16_t a=0,q=0,w=0,r=0;

                cpu_physical_memory_read(qobj+0x0C,&a,2);
                cpu_physical_memory_read(qobj+0x12,&q,2);
                cpu_physical_memory_read(qobj+0x18,&w,2);
                cpu_physical_memory_read(qobj+0x1A,&r,2);

                if(a==0 && q==1 && w==4 && r==3)
                {
                    unsigned total=seq;
                    unsigned start=total>128 ? total-128 : 0;
                    unsigned i;

                    dumped=1;

                    R20EA_LOG(
                        "TARGET=GL_CRITICAL REC=%08X EVENTS=%u",
                        rec,total);

                    for(i=start;i<total;i++)
                    {
                        gl_evt_t *e=&ring[i & 127];

                        R20EA_LOG(
                            "TARGET=GL_EVT N=%u T=%u "
                            "PC=%08X LR=%08X "
                            "CUR=%08X>%08X HIQ=%08X "
                            "Q0=%08X Q4=%08X "
                            "F14=%08X S49=%02X S4D=%02X "
                            "R0=%08X R1=%08X R2=%08X R3=%08X "
                            "R4=%08X R5=%08X R6=%08X R7=%08X "
                            "SP=%08X",
                            e->n,e->t,
                            e->pc,e->lr,
                            e->ocur,e->ncur,e->hiq,
                            e->q0,e->q4,
                            e->f14,e->s49,e->s4d,
                            e->r0,e->r1,e->r2,e->r3,
                            e->r4,e->r5,e->r6,e->r7,
                            e->sp);
                    }
                }
            }

#undef GL_REC
        }

        /* QEMU40PAD-BC-R20GM-POSTSELECT */
        if (0)
        {
            typedef struct {
                uint32_t n,t,cycle,step,pc,lr,sp;
                uint32_t oldcur,cur,f14;
                uint32_t r0,r1,r2,r3,r4,r5,r6,r7;
                uint8_t s49,s4d;
            } gm_evt_t;

            static gm_evt_t ring[256];
            static unsigned seq=0,pos=0;
            static unsigned cycle=0,step=0;
            static int armed=0,dumped=0,init=0,trace=0;
            static uint32_t rec=0,old_cur=0;

            const uint32_t target_raw=0x046600C4U;
            const uint32_t qobj=0x002E6BF4U;

#define GM_REC(type,oldc,newc,st) do {                       \
                gm_evt_t *e=&ring[pos++ & 255];              \
                uint32_t f14=0;                              \
                uint8_t s49=0,s4d=0;                         \
                if(rec) {                                    \
                    cpu_physical_memory_read(rec+0x14,&f14,4);\
                    cpu_physical_memory_read(rec+0x49,&s49,1);\
                    cpu_physical_memory_read(rec+0x4D,&s4d,1);\
                }                                            \
                e->n=seq++; e->t=(type);                     \
                e->cycle=cycle; e->step=(st);                \
                e->pc=pc; e->lr=env->regs[14];               \
                e->sp=env->regs[13];                         \
                e->oldcur=(oldc); e->cur=(newc);             \
                e->f14=f14; e->s49=s49; e->s4d=s4d;         \
                e->r0=env->regs[0]; e->r1=env->regs[1];      \
                e->r2=env->regs[2]; e->r3=env->regs[3];      \
                e->r4=env->regs[4]; e->r5=env->regs[5];      \
                e->r6=env->regs[6]; e->r7=env->regs[7];      \
            } while(0)

            if(!armed && pc==0x80001734U)
            {
                uint32_t arg=env->regs[0],raw=0;

                if(arg)
                    cpu_physical_memory_read(arg+0x10,&raw,4);

                if(raw==target_raw)
                {
                    rec=env->regs[4];
                    armed=1;
                }
            }

            if(armed)
            {
                uint32_t cur=0;
                cpu_physical_memory_read(0x45A4,&cur,4);

                if(!init)
                {
                    old_cur=cur;
                    init=1;
                }
                else
                {
                    if(cur!=old_cur)
                    {
                        if(cur==rec)
                        {
                            cycle++;
                            step=0;
                            trace=24;

                            GM_REC(1,old_cur,cur,step);
                        }

                        old_cur=cur;
                    }

                    if(trace)
                    {
                        step++;
                        GM_REC(2,cur,cur,step);
                        trace--;
                    }

                    if((pc==0x800018A2U ||
                        pc==0x800018A6U) &&
                       env->regs[4]==rec)
                        GM_REC(3,cur,cur,step);
                }
            }

            if(armed && !dumped &&
               pc==0x80003B2EU &&
               env->regs[4]==qobj)
            {
                uint16_t a=0,q=0,w=0,r=0;

                cpu_physical_memory_read(qobj+0x0C,&a,2);
                cpu_physical_memory_read(qobj+0x12,&q,2);
                cpu_physical_memory_read(qobj+0x18,&w,2);
                cpu_physical_memory_read(qobj+0x1A,&r,2);

                if(a==0 && q==1 && w==4 && r==3)
                {
                    unsigned total=seq;
                    unsigned start=total>256 ? total-256 : 0;
                    unsigned i,j;
                    uint32_t x;
                    uint8_t b[16];

                    dumped=1;

                    R20EA_LOG(
                        "TARGET=GM_CRITICAL REC=%08X EVENTS=%u CYCLES=%u",
                        rec,total,cycle);

                    for(x=0x80000820U;x<0x80000860U;x+=16)
                    {
                        cpu_physical_memory_read(x,b,16);
                        fprintf(stderr,
                            "[R20GM] SWITCH_A=%08X",x);
                        for(j=0;j<16;j++)
                            fprintf(stderr," %02X",b[j]);
                        fprintf(stderr,"\n");
                    }

                    for(x=0x80000AC0U;x<0x80000B30U;x+=16)
                    {
                        cpu_physical_memory_read(x,b,16);
                        fprintf(stderr,
                            "[R20GM] SWITCH_B=%08X",x);
                        for(j=0;j<16;j++)
                            fprintf(stderr," %02X",b[j]);
                        fprintf(stderr,"\n");
                    }

                    for(i=start;i<total;i++)
                    {
                        gm_evt_t *e=&ring[i & 255];

                        R20EA_LOG(
                            "TARGET=GM_EVT N=%u T=%u C=%u STEP=%u "
                            "PC=%08X LR=%08X SP=%08X "
                            "CUR=%08X>%08X "
                            "F14=%08X S49=%02X S4D=%02X "
                            "R0=%08X R1=%08X R2=%08X R3=%08X "
                            "R4=%08X R5=%08X R6=%08X R7=%08X",
                            e->n,e->t,e->cycle,e->step,
                            e->pc,e->lr,e->sp,
                            e->oldcur,e->cur,
                            e->f14,e->s49,e->s4d,
                            e->r0,e->r1,e->r2,e->r3,
                            e->r4,e->r5,e->r6,e->r7);
                    }
                }
            }

#undef GM_REC
        }

        /* QEMU40PAD-BC-R20GN-GOODBAD */
        if (0)
        {
            enum { GNMAX=128 };

            typedef struct {
                uint32_t pc,lr,sp,cur,f14;
                uint32_t r0,r1,r2,r3,r4,r5,r6,r7;
                uint32_t frame[6];
                uint32_t ctx[8];
                uint8_t s49,s4d,snap;
            } gn_evt_t;

            static gn_evt_t work[GNMAX],good[GNMAX],bad[GNMAX];
            static unsigned wn=0,gn=0,bn=0;
            static unsigned cycle=0,work_cycle=0;
            static int armed=0,init=0,tracing=0;
            static int have_good=0,have_bad=0,dumped=0;
            static uint32_t rec=0,old_cur=0;

            const uint32_t target_raw=0x046600C4U;
            const uint32_t qobj=0x002E6BF4U;

#define GN_CAP(dst_,idx_) do {                               \
                gn_evt_t *e=&(dst_)[(idx_)];                 \
                uint32_t i;                                  \
                e->pc=pc; e->lr=env->regs[14];               \
                e->sp=env->regs[13];                         \
                cpu_physical_memory_read(0x45A4,&e->cur,4);  \
                cpu_physical_memory_read(rec+0x14,&e->f14,4);\
                cpu_physical_memory_read(rec+0x49,&e->s49,1);\
                cpu_physical_memory_read(rec+0x4D,&e->s4d,1);\
                e->r0=env->regs[0]; e->r1=env->regs[1];      \
                e->r2=env->regs[2]; e->r3=env->regs[3];      \
                e->r4=env->regs[4]; e->r5=env->regs[5];      \
                e->r6=env->regs[6]; e->r7=env->regs[7];      \
                e->snap=0;                                   \
                for(i=0;i<6;i++) e->frame[i]=0;              \
                for(i=0;i<8;i++) e->ctx[i]=0;                \
                if(pc==0x800008ECU || pc==0xFE0DD692U) {     \
                    e->snap=1;                               \
                    for(i=0;i<6;i++)                         \
                        cpu_physical_memory_read(             \
                            0x800007E8U+i*4,&e->frame[i],4);  \
                    for(i=0;i<8;i++)                         \
                        cpu_physical_memory_read(             \
                            rec+0x50+i*4,&e->ctx[i],4);       \
                }                                            \
            } while(0)

            if(!armed && pc==0x80001734U)
            {
                uint32_t arg=env->regs[0],raw=0;
                if(arg)
                    cpu_physical_memory_read(arg+0x10,&raw,4);

                if(raw==target_raw)
                {
                    rec=env->regs[4];
                    armed=1;
                }
            }

            if(armed && !(have_good && have_bad))
            {
                uint32_t cur=0;
                cpu_physical_memory_read(0x45A4,&cur,4);

                if(!init)
                {
                    old_cur=cur;
                    init=1;
                }

                if(!tracing && cur==rec && old_cur!=rec)
                {
                    cycle++;
                    work_cycle=cycle;
                    wn=0;
                    tracing=1;
                }

                if(tracing)
                {
                    if(wn<GNMAX)
                    {
                        GN_CAP(work,wn);
                        wn++;
                    }

                    if((pc==0x800018A2U || pc==0x800018A6U) &&
                       env->regs[4]==rec)
                    {
                        if(!have_good)
                        {
                            unsigned i;
                            gn=wn;
                            for(i=0;i<gn;i++) good[i]=work[i];
                            have_good=1;
                        }
                        tracing=0;
                    }
                    else if(cur!=rec && wn>1)
                    {
                        if(!have_bad)
                        {
                            unsigned i;
                            bn=wn;
                            for(i=0;i<bn;i++) bad[i]=work[i];
                            have_bad=1;
                        }
                        tracing=0;
                    }
                    else if(wn>=GNMAX)
                    {
                        if(!have_bad)
                        {
                            unsigned i;
                            bn=wn;
                            for(i=0;i<bn;i++) bad[i]=work[i];
                            have_bad=1;
                        }
                        tracing=0;
                    }
                }

                old_cur=cur;
            }

            if(armed && !dumped &&
               pc==0x80003B2EU &&
               env->regs[4]==qobj)
            {
                uint16_t a=0,q=0,w=0,r=0;

                cpu_physical_memory_read(qobj+0x0C,&a,2);
                cpu_physical_memory_read(qobj+0x12,&q,2);
                cpu_physical_memory_read(qobj+0x18,&w,2);
                cpu_physical_memory_read(qobj+0x1A,&r,2);

                if(a==0 && q==1 && w==4 && r==3)
                {
                    unsigned i,j;
                    uint8_t b[16];
                    uint32_t x;

                    dumped=1;

                    R20EA_LOG(
                        "TARGET=GN_CRITICAL REC=%08X GOOD=%d GN=%u "
                        "BAD=%d BN=%u CYCLES=%u",
                        rec,have_good,gn,have_bad,bn,cycle);

                    for(x=0x800008D0U;x<0x80000910U;x+=16)
                    {
                        cpu_physical_memory_read(x,b,16);
                        fprintf(stderr,"[R20GN] SWITCH=%08X",x);
                        for(j=0;j<16;j++) fprintf(stderr," %02X",b[j]);
                        fprintf(stderr,"\n");
                    }

                    for(x=0xFE0DD680U;x<0xFE0DD700U;x+=16)
                    {
                        cpu_physical_memory_read(x,b,16);
                        fprintf(stderr,"[R20GN] RESTORE=%08X",x);
                        for(j=0;j<16;j++) fprintf(stderr," %02X",b[j]);
                        fprintf(stderr,"\n");
                    }

                    for(i=0;i<gn;i++)
                    {
                        gn_evt_t *e=&good[i];

                        R20EA_LOG(
                            "TARGET=GN_GOOD STEP=%u PC=%08X LR=%08X "
                            "SP=%08X CUR=%08X F14=%08X S49=%02X S4D=%02X "
                            "R0=%08X R1=%08X R2=%08X R3=%08X "
                            "R4=%08X R5=%08X R6=%08X R7=%08X",
                            i,e->pc,e->lr,e->sp,e->cur,e->f14,
                            e->s49,e->s4d,
                            e->r0,e->r1,e->r2,e->r3,
                            e->r4,e->r5,e->r6,e->r7);

                        if(e->snap)
                        {
                            fprintf(stderr,
                                "[R20GN] GOOD_FRAME STEP=%u "
                                "%08X %08X %08X %08X %08X %08X\n",
                                i,
                                e->frame[0],e->frame[1],e->frame[2],
                                e->frame[3],e->frame[4],e->frame[5]);

                            fprintf(stderr,
                                "[R20GN] GOOD_CTX STEP=%u "
                                "%08X %08X %08X %08X "
                                "%08X %08X %08X %08X\n",
                                i,
                                e->ctx[0],e->ctx[1],e->ctx[2],e->ctx[3],
                                e->ctx[4],e->ctx[5],e->ctx[6],e->ctx[7]);
                        }
                    }

                    for(i=0;i<bn;i++)
                    {
                        gn_evt_t *e=&bad[i];

                        R20EA_LOG(
                            "TARGET=GN_BAD STEP=%u PC=%08X LR=%08X "
                            "SP=%08X CUR=%08X F14=%08X S49=%02X S4D=%02X "
                            "R0=%08X R1=%08X R2=%08X R3=%08X "
                            "R4=%08X R5=%08X R6=%08X R7=%08X",
                            i,e->pc,e->lr,e->sp,e->cur,e->f14,
                            e->s49,e->s4d,
                            e->r0,e->r1,e->r2,e->r3,
                            e->r4,e->r5,e->r6,e->r7);

                        if(e->snap)
                        {
                            fprintf(stderr,
                                "[R20GN] BAD_FRAME STEP=%u "
                                "%08X %08X %08X %08X %08X %08X\n",
                                i,
                                e->frame[0],e->frame[1],e->frame[2],
                                e->frame[3],e->frame[4],e->frame[5]);

                            fprintf(stderr,
                                "[R20GN] BAD_CTX STEP=%u "
                                "%08X %08X %08X %08X "
                                "%08X %08X %08X %08X\n",
                                i,
                                e->ctx[0],e->ctx[1],e->ctx[2],e->ctx[3],
                                e->ctx[4],e->ctx[5],e->ctx[6],e->ctx[7]);
                        }
                    }
                }
            }

#undef GN_CAP
        }

        /* QEMU40PAD-BC-R20GO-WAITRESUME */
        if (0)
        {
            typedef struct {
                uint32_t type,pc,lr,sp,cur,f14;
                uint32_t r0,r1,r2,r3,r4,r5,r6,r7;
                uint32_t g4578,g457c,g4580,g4584,g45a8;
                uint32_t ctx[8];
                uint8_t s49,s4d;
            } go_evt_t;

            static go_evt_t work[20], good[20], bad[20];
            static unsigned wn=0,gn=0,bn=0;
            static int armed=0,phase=0,active=0;
            static int have_good=0,have_bad=0,dumped=0,init=0;
            static uint32_t rec=0,old_cur=0;

            const uint32_t target_raw=0x046600C4U;
            const uint32_t waitobj=0x002E3A90U;
            const uint32_t qobj=0x002E6BF4U;

#define GO_CAP(type_) do {                                   \
                if(wn<20) {                                  \
                    go_evt_t *e=&work[wn++];                  \
                    unsigned z;                               \
                    e->type=(type_); e->pc=pc;                \
                    e->lr=env->regs[14];                      \
                    e->sp=env->regs[13];                      \
                    cpu_physical_memory_read(0x45A4,&e->cur,4);\
                    cpu_physical_memory_read(rec+0x14,&e->f14,4);\
                    cpu_physical_memory_read(rec+0x49,&e->s49,1);\
                    cpu_physical_memory_read(rec+0x4D,&e->s4d,1);\
                    e->r0=env->regs[0]; e->r1=env->regs[1];  \
                    e->r2=env->regs[2]; e->r3=env->regs[3];  \
                    e->r4=env->regs[4]; e->r5=env->regs[5];  \
                    e->r6=env->regs[6]; e->r7=env->regs[7];  \
                    cpu_physical_memory_read(0x4578,&e->g4578,4);\
                    cpu_physical_memory_read(0x457C,&e->g457c,4);\
                    cpu_physical_memory_read(0x4580,&e->g4580,4);\
                    cpu_physical_memory_read(0x4584,&e->g4584,4);\
                    cpu_physical_memory_read(0x45A8,&e->g45a8,4);\
                    for(z=0;z<8;z++)                          \
                        cpu_physical_memory_read(             \
                            rec+0x50+z*4,&e->ctx[z],4);       \
                }                                            \
            } while(0)

            if(!armed && pc==0x80001734U)
            {
                uint32_t arg=env->regs[0],raw=0;
                if(arg)
                    cpu_physical_memory_read(arg+0x10,&raw,4);

                if(raw==target_raw)
                {
                    rec=env->regs[4];
                    armed=1;
                }
            }

            if(armed)
            {
                uint32_t cur=0,f14=0;
                uint8_t s4d=0;

                cpu_physical_memory_read(0x45A4,&cur,4);
                cpu_physical_memory_read(rec+0x14,&f14,4);
                cpu_physical_memory_read(rec+0x4D,&s4d,1);

                if(!init)
                {
                    old_cur=cur;
                    init=1;
                }

                /* Arm only after the real DispDCtrl 0x22B wait. */
                if(pc==0x80003560U &&
                   env->regs[4]==rec &&
                   env->regs[2]==0x22BU &&
                   env->regs[5]==waitobj)
                {
                    phase=1;
                }

                /* A candidate resume begins only from the waiting state. */
                if(phase && !active &&
                   cur==rec && old_cur!=rec &&
                   f14==waitobj && s4d==1)
                {
                    wn=0;
                    active=1;
                    GO_CAP(1);
                }

                if(active)
                {
                    if(pc==0x80000B08U) GO_CAP(2);
                    if(pc==0x80000B0AU) GO_CAP(3);
                    if(pc==0x80000B0CU) GO_CAP(4);
                    if(pc==0x800008ECU) GO_CAP(5);

                    if(pc==0xFE0DD692U) GO_CAP(6);
                    if(pc==0xFE0DD6A0U) GO_CAP(7);
                    if(pc==0xFE0DD6B0U) GO_CAP(8);
                    if(pc==0xFE0DD6C0U) GO_CAP(9);
                    if(pc==0xFE0DD6C8U) GO_CAP(10);
                    if(pc==0xFE0DD6D0U) GO_CAP(11);

                    if((pc==0x800018A2U ||
                        pc==0x800018A6U) &&
                       env->regs[4]==rec)
                    {
                        GO_CAP(12);

                        if(!have_good)
                        {
                            unsigned i;
                            gn=wn;
                            for(i=0;i<gn;i++) good[i]=work[i];
                            have_good=1;
                        }

                        active=0;
                    }
                    else if(cur!=rec)
                    {
                        GO_CAP(13);

                        if(!have_bad)
                        {
                            unsigned i;
                            bn=wn;
                            for(i=0;i<bn;i++) bad[i]=work[i];
                            have_bad=1;
                        }

                        active=0;
                    }
                }

                old_cur=cur;
            }

            if(armed && !dumped &&
               pc==0x80003B2EU &&
               env->regs[4]==qobj)
            {
                uint16_t a=0,q=0,w=0,r=0;

                cpu_physical_memory_read(qobj+0x0C,&a,2);
                cpu_physical_memory_read(qobj+0x12,&q,2);
                cpu_physical_memory_read(qobj+0x18,&w,2);
                cpu_physical_memory_read(qobj+0x1A,&r,2);

                if(a==0 && q==1 && w==4 && r==3)
                {
                    unsigned i;
                    dumped=1;

                    R20EA_LOG(
                        "TARGET=GO_CRITICAL REC=%08X "
                        "GOOD=%d GN=%u BAD=%d BN=%u",
                        rec,have_good,gn,have_bad,bn);

#define GO_DUMP(tag_,arr_,num_) do {                         \
                    for(i=0;i<(num_);i++) {                  \
                        go_evt_t *e=&(arr_)[i];               \
                        R20EA_LOG(                            \
                            "TARGET=GO_" tag_                 \
                            " STEP=%u T=%u PC=%08X LR=%08X "  \
                            "SP=%08X CUR=%08X F14=%08X "      \
                            "S49=%02X S4D=%02X "              \
                            "R0=%08X R1=%08X R2=%08X R3=%08X "\
                            "R4=%08X R5=%08X R6=%08X R7=%08X "\
                            "G4578=%08X G457C=%08X "          \
                            "G4580=%08X G4584=%08X G45A8=%08X "\
                            "CTX=%08X,%08X,%08X,%08X,"        \
                            "%08X,%08X,%08X,%08X",            \
                            i,e->type,e->pc,e->lr,e->sp,      \
                            e->cur,e->f14,e->s49,e->s4d,      \
                            e->r0,e->r1,e->r2,e->r3,          \
                            e->r4,e->r5,e->r6,e->r7,          \
                            e->g4578,e->g457c,e->g4580,       \
                            e->g4584,e->g45a8,                \
                            e->ctx[0],e->ctx[1],e->ctx[2],    \
                            e->ctx[3],e->ctx[4],e->ctx[5],    \
                            e->ctx[6],e->ctx[7]);             \
                    }                                        \
                } while(0)

                    if(have_good) GO_DUMP("GOOD",good,gn);
                    if(have_bad)  GO_DUMP("BAD",bad,bn);

#undef GO_DUMP
                }
            }

#undef GO_CAP
        }

        /* QEMU40PAD-BC-R20GP-POSTRESTORE */
        /* R20GQ_INSTANT_DUMP */
        /* R20GR_FIRST_DIVERGENCE */

        /* QEMU40PAD_BC_R20GW */
        extern volatile unsigned int qemu40_sio3_next_source;
        extern volatile unsigned int qemu40_sio3_pending_source;
        extern volatile unsigned int qemu40_sio3_active_source;
        {
            typedef struct {
                uint32_t n,pc,lr,sp,cpsr,mask;
                uint32_t cur,hiq,f14;
                uint32_t g4578,g4580,g4584,g45a8;
                uint32_t og4578,og4580,og4584,og45a8;
                uint32_t r0,r1,r2,r3,r4,r5,r6,r7;
                uint8_t s49,s4d;
            } gp_evt_t;

            static gp_evt_t tr[160];
            static unsigned tn=0,seq=0;
            static int armed=0,wait_seen=0,active=0;
            static int post=0,bad=0,dumped=0,init=0;
            static uint32_t rec=0,old_cur=0;
            static uint32_t og4578=0,og4580=0,og4584=0,og45a8=0;

            const uint32_t target_raw=0x046600C4U;
            const uint32_t waitobj=0x002E3A90U;
            const uint32_t qobj=0x002E6BF4U;

#define GP_CAP(mask_) do {                                   \
                if(tn<160) {                                 \
                    gp_evt_t *e=&tr[tn++];                    \
                    e->n=seq++; e->pc=pc;                    \
                    e->lr=env->regs[14];                     \
                    e->sp=env->regs[13];                     \
                    e->cpsr=env->uncached_cpsr;              \
                    e->mask=(mask_);                         \
                    cpu_physical_memory_read(0x45A4,&e->cur,4);\
                    cpu_physical_memory_read(0x45B0,&e->hiq,4);\
                    cpu_physical_memory_read(rec+0x14,&e->f14,4);\
                    cpu_physical_memory_read(rec+0x49,&e->s49,1);\
                    cpu_physical_memory_read(rec+0x4D,&e->s4d,1);\
                    cpu_physical_memory_read(0x4578,&e->g4578,4);\
                    cpu_physical_memory_read(0x4580,&e->g4580,4);\
                    cpu_physical_memory_read(0x4584,&e->g4584,4);\
                    cpu_physical_memory_read(0x45A8,&e->g45a8,4);\
                    e->og4578=og4578;                         \
                    e->og4580=og4580;                         \
                    e->og4584=og4584;                         \
                    e->og45a8=og45a8;                         \
                    e->r0=env->regs[0]; e->r1=env->regs[1];  \
                    e->r2=env->regs[2]; e->r3=env->regs[3];  \
                    e->r4=env->regs[4]; e->r5=env->regs[5];  \
                    e->r6=env->regs[6]; e->r7=env->regs[7];  \
                }                                            \
            } while(0)

            if(!armed && pc==0x80001734U)
            {
                uint32_t arg=env->regs[0],raw=0;

                if(arg)
                    cpu_physical_memory_read(arg+0x10,&raw,4);

                if(raw==target_raw)
                {
                    rec=env->regs[4];
                    armed=1;
                }
            }

            if(armed)
            {
                uint32_t cur=0,f14=0;
                uint8_t s4d=0;

                cpu_physical_memory_read(0x45A4,&cur,4);
                cpu_physical_memory_read(rec+0x14,&f14,4);
                cpu_physical_memory_read(rec+0x4D,&s4d,1);

                if(!init)
                {
                    old_cur=cur;
                    init=1;
                }

                /* Real DispDCtrl wait on semaphore 0x22B. */
                if(pc==0x80003560U &&
                   env->regs[4]==rec &&
                   env->regs[2]==0x22BU &&
                   env->regs[5]==waitobj)
                {
                    wait_seen=1;
                }

                /* Candidate resume only from the 0x22B waiting state. */
                if(wait_seen && !active &&
                   cur==rec && old_cur!=rec &&
                   f14==waitobj && s4d==1)
                {
                    active=1;
                    post=0;
                    tn=0;
                    wait_seen=0;
                }

                if(active && pc==0xFE0DD6C0U && !post)
                {
                    cpu_physical_memory_read(0x4578,&og4578,4);
                    cpu_physical_memory_read(0x4580,&og4580,4);
                    cpu_physical_memory_read(0x4584,&og4584,4);
                    cpu_physical_memory_read(0x45A8,&og45a8,4);

                    post=1;
                    GP_CAP(0x100);
                }
                else if(active && post && !bad)
                {
                    uint32_t g4578=0,g4580=0,g4584=0,g45a8=0;
                    uint32_t mask=0;

                    cpu_physical_memory_read(0x4578,&g4578,4);
                    cpu_physical_memory_read(0x4580,&g4580,4);
                    cpu_physical_memory_read(0x4584,&g4584,4);
                    cpu_physical_memory_read(0x45A8,&g45a8,4);

                    if(g4578!=og4578) mask|=1;
                    if(g4580!=og4580) mask|=2;
                    if(g4584!=og4584) mask|=4;
                    if(g45a8!=og45a8) mask|=8;

                    GP_CAP(mask);

                    og4578=g4578;
                    og4580=g4580;
                    og4584=g4584;
                    og45a8=g45a8;

                    /* Good resume: ignore and seek the next 22B cycle. */
                    if(pc==0x800018A2U &&
                       env->regs[4]==rec)
                    {
                        active=0;
                        post=0;
                        tn=0;
                    }

                    /*
                     * The exact anomalous second switch seen in R20GO.
                     */
                    if(mask ||
                       pc==0x800008ECU ||
                       cur!=rec)
                    {
                        unsigned i;

                        bad=1;
                        dumped=1;

                        R20EA_LOG(
                            "TARGET=GW_SIO3_SOURCE ACTIVE=%u PENDING=%u NEXT=%u",
                            qemu40_sio3_active_source,
                            qemu40_sio3_pending_source,
                            qemu40_sio3_next_source);

                        R20EA_LOG(
                            "TARGET=GR_DIVERGENCE REC=%08X EVENTS=%u "
                            "REASON=%03X PC=%08X LR=%08X "
                            "SP=%08X CPSR=%08X",
                            rec,tn,
                            mask |
                            (pc==0x800008ECU ? 0x100U : 0U) |
                            (cur!=rec ? 0x200U : 0U),
                            pc,env->regs[14],
                            env->regs[13],env->uncached_cpsr);

                        for(i=0;i<tn;i++)
                        {
                            gp_evt_t *e=&tr[i];

                            R20EA_LOG(
                                "TARGET=GR_EVT N=%u PC=%08X LR=%08X "
                                "SP=%08X CPSR=%08X MASK=%03X "
                                "CUR=%08X HIQ=%08X "
                                "F14=%08X S49=%02X S4D=%02X "
                                "G4578=%08X>%08X "
                                "G4580=%08X>%08X "
                                "G4584=%08X>%08X "
                                "G45A8=%08X>%08X "
                                "R0=%08X R1=%08X R2=%08X R3=%08X "
                                "R4=%08X R5=%08X R6=%08X R7=%08X",
                                e->n,e->pc,e->lr,e->sp,
                                e->cpsr,e->mask,
                                e->cur,e->hiq,
                                e->f14,e->s49,e->s4d,
                                e->og4578,e->g4578,
                                e->og4580,e->g4580,
                                e->og4584,e->g4584,
                                e->og45a8,e->g45a8,
                                e->r0,e->r1,e->r2,e->r3,
                                e->r4,e->r5,e->r6,e->r7);
                        }

                        active=0;
                        post=0;
                    }

                    if(tn>=160)
                    {
                        active=0;
                        post=0;
                    }
                }

                old_cur=cur;
            }

            if(armed && bad && !dumped &&
               pc==0x80003B2EU &&
               env->regs[4]==qobj)
            {
                uint16_t a=0,q=0,w=0,r=0;

                cpu_physical_memory_read(qobj+0x0C,&a,2);
                cpu_physical_memory_read(qobj+0x12,&q,2);
                cpu_physical_memory_read(qobj+0x18,&w,2);
                cpu_physical_memory_read(qobj+0x1A,&r,2);

                if(a==0 && q==1 && w==4 && r==3)
                {
                    unsigned i,j;
                    uint32_t x;
                    uint8_t b[16];

                    dumped=1;

                    R20EA_LOG(
                        "TARGET=GP_CRITICAL REC=%08X EVENTS=%u",
                        rec,tn);

                    for(x=0x80000880U;x<0x800008F0U;x+=16)
                    {
                        cpu_physical_memory_read(x,b,16);
                        fprintf(stderr,
                            "[R20GP] CALLER=%08X",x);

                        for(j=0;j<16;j++)
                            fprintf(stderr," %02X",b[j]);

                        fprintf(stderr,"\n");
                    }

                    for(x=0xFE0DD6B0U;x<0xFE0DD6E0U;x+=16)
                    {
                        cpu_physical_memory_read(x,b,16);
                        fprintf(stderr,
                            "[R20GP] RESTORE=%08X",x);

                        for(j=0;j<16;j++)
                            fprintf(stderr," %02X",b[j]);

                        fprintf(stderr,"\n");
                    }

                    for(i=0;i<tn;i++)
                    {
                        gp_evt_t *e=&tr[i];

                        R20EA_LOG(
                            "TARGET=GP_EVT N=%u PC=%08X LR=%08X "
                            "SP=%08X CPSR=%08X MASK=%03X "
                            "CUR=%08X HIQ=%08X "
                            "F14=%08X S49=%02X S4D=%02X "
                            "G4578=%08X>%08X "
                            "G4580=%08X>%08X "
                            "G4584=%08X>%08X "
                            "G45A8=%08X>%08X "
                            "R0=%08X R1=%08X R2=%08X R3=%08X "
                            "R4=%08X R5=%08X R6=%08X R7=%08X",
                            e->n,e->pc,e->lr,e->sp,e->cpsr,e->mask,
                            e->cur,e->hiq,e->f14,e->s49,e->s4d,
                            e->og4578,e->g4578,
                            e->og4580,e->g4580,
                            e->og4584,e->g4584,
                            e->og45a8,e->g45a8,
                            e->r0,e->r1,e->r2,e->r3,
                            e->r4,e->r5,e->r6,e->r7);
                    }
                }
            }

#undef GP_CAP
        }


        /* QEMU40PAD_BC_R20GX */
        {
            static int gx_dumped = 0;

            const uint32_t gx_rec = 0x002E2B3CU;
            const uint32_t gx_wait = 0x002E3A90U;
            const uint32_t gx_worker = 0x002E6BF4U;

            extern volatile unsigned int qemu40_sio3_next_source;
            extern volatile unsigned int qemu40_sio3_pending_source;
            extern volatile unsigned int qemu40_sio3_active_source;

            extern volatile unsigned int qemu40_sio3_ring_head;
            extern volatile unsigned int qemu40_sio3_ring_seq[32];
            extern volatile unsigned int qemu40_sio3_ring_kind[32];
            extern volatile unsigned int qemu40_sio3_ring_src[32];
            extern volatile unsigned int qemu40_sio3_ring_irqid[32];
            extern volatile unsigned int qemu40_sio3_ring_sched[32];

            if (qemu40_gy_event21_wait && !gx_dumped &&
                pc == 0x80003B2EU &&
                env->regs[4] == gx_worker)
            {
                uint16_t a=0,q=0,w=0,r=0;

                cpu_physical_memory_read(gx_worker+0x0C,&a,2);
                cpu_physical_memory_read(gx_worker+0x12,&q,2);
                cpu_physical_memory_read(gx_worker+0x18,&w,2);
                cpu_physical_memory_read(gx_worker+0x1A,&r,2);

                if (a==0 && q==1 && w==4 && r==3)
                {
                    unsigned int h,start,n,i;

                    gx_dumped=1;

                    h=qemu40_sio3_ring_head;
                    start=(h>32)?h-32:0;

                    R20EA_LOG(
                        "TARGET=GY_BLOCKER REC=%08X HEAD=%u "
                        "NEXT=%u PENDING=%u ACTIVE=%u "
                        "WA=%u WQ=%u WW=%u WR=%u",
                        gx_rec,h,
                        qemu40_sio3_next_source,
                        qemu40_sio3_pending_source,
                        qemu40_sio3_active_source,
                        a,q,w,r);

                    for(n=start;n<h;n++)
                    {
                        i=n&31;

                        R20EA_LOG(
                            "TARGET=GY_SIO3 N=%u SEQ=%u "
                            "KIND=%u SRC=%u IRQID=%03X SCHED=%u",
                            n,
                            qemu40_sio3_ring_seq[i],
                            qemu40_sio3_ring_kind[i],
                            qemu40_sio3_ring_src[i],
                            qemu40_sio3_ring_irqid[i],
                            qemu40_sio3_ring_sched[i]);
                    }
                }
            }
        }

        /* QEMU40PAD-BC-R20EQ-SILENT */
        {
            static int wake_seen=0;
            static int wake_immediate=0;
            static int wake_deferred=0;
            static uint16_t wake_active=0;
            static uint16_t wake_limit=0;
            static uint16_t wake_queued=0;

            if (rearm && post21_pending && pc == 0x80003AD6U)
            {
                uint32_t base=(uint32_t)env->regs[4];

                wake_seen=1;
                wake_immediate=0;
                wake_deferred=0;

                if (base)
                {
                    cpu_physical_memory_read(base+0x0C,&wake_active,2);
                    cpu_physical_memory_read(base+0x10,&wake_limit,2);
                    cpu_physical_memory_read(base+0x12,&wake_queued,2);
                }
            }

            if (rearm && post21_pending && pc == 0x80003B12U)
                wake_immediate=1;

            if (rearm && post21_pending && pc == 0x80003B18U)
                wake_deferred=1;

            if (rearm && post21_pending &&
                pc == 0x8000237CU && wake_seen)
            {
                uint16_t active_now=0, limit_now=0, queued_now=0;
                uint32_t base=0x002E6BF4U;

                cpu_physical_memory_read(base+0x0C,&active_now,2);
                cpu_physical_memory_read(base+0x10,&limit_now,2);
                cpu_physical_memory_read(base+0x12,&queued_now,2);

                R20EA_LOG(
                    "TARGET=WAKECLASS "
                    "ENTRY_ACTIVE=%04X ENTRY_LIMIT=%04X ENTRY_QUEUED=%04X "
                    "IMMEDIATE=%d DEFERRED=%d "
                    "NOW_ACTIVE=%04X NOW_LIMIT=%04X NOW_QUEUED=%04X",
                    (unsigned)wake_active,
                    (unsigned)wake_limit,
                    (unsigned)wake_queued,
                    wake_immediate,
                    wake_deferred,
                    (unsigned)active_now,
                    (unsigned)limit_now,
                    (unsigned)queued_now);

                wake_seen=0;
            }
        }

        /* QEMU40PAD-BC-R20ER-DRAIN */
        if (0)
        {
            static int deferred_seen=0;
            static int dump_done=0;

            if (rearm && post21_pending && pc == 0x80003B18U)
                deferred_seen=1;

            if (deferred_seen &&
                (pc == 0x80003C7EU ||
                 pc == 0x80002324U ||
                 pc == 0x80002328U))
            {
                uint16_t active=0, limit=0, queued=0;
                uint32_t base=0x002E6BF4U;

                cpu_physical_memory_read(base+0x0C,&active,2);
                cpu_physical_memory_read(base+0x10,&limit,2);
                cpu_physical_memory_read(base+0x12,&queued,2);

                R20EA_LOG(
                    "TARGET=DEFERDRAIN PC=%08X LR=%08X "
                    "ACTIVE=%04X LIMIT=%04X QUEUED=%04X "
                    "R0=%08X R1=%08X R2=%08X R3=%08X SP=%08X",
                    pc,
                    (uint32_t)env->regs[14],
                    (unsigned)active,
                    (unsigned)limit,
                    (unsigned)queued,
                    (uint32_t)env->regs[0],
                    (uint32_t)env->regs[1],
                    (uint32_t)env->regs[2],
                    (uint32_t)env->regs[3],
                    (uint32_t)env->regs[13]);
            }

            if (deferred_seen && !dump_done && pc == 0x8000237CU)
            {
                uint8_t b[16];
                uint32_t a;
                unsigned i;

                dump_done=1;

                for (a=0x80003C40U; a<0x80003CC0U; a+=16)
                {
                    cpu_physical_memory_read(a,b,sizeof(b));
                    fprintf(stderr,"[R20ER] CODE=%08X",a);
                    for(i=0;i<16;i++)
                        fprintf(stderr," %02X",b[i]);
                    fprintf(stderr,"\n");
                }
            }
        }

        /* QEMU40PAD-BC-R20ES-TARGET-DRAIN */
        if (0 && rearm && post21_pending &&
            (pc == 0x80003C76U ||
             pc == 0x80003C7AU ||
             pc == 0x80003C7CU ||
             pc == 0x80003C7EU))
        {
            uint32_t obj=(uint32_t)env->regs[4];

            if (obj == 0x002E6BF4U)
            {
                uint16_t active=0,limit=0,queued=0;

                cpu_physical_memory_read(obj+0x0C,&active,2);
                cpu_physical_memory_read(obj+0x10,&limit,2);
                cpu_physical_memory_read(obj+0x12,&queued,2);

                R20EA_LOG(
                    "TARGET=TARGETDRAIN PC=%08X LR=%08X "
                    "OBJ=%08X ACTIVE=%04X LIMIT=%04X QUEUED=%04X "
                    "R0=%08X R1=%08X R2=%08X R3=%08X SP=%08X",
                    pc,
                    (uint32_t)env->regs[14],
                    obj,
                    (unsigned)active,
                    (unsigned)limit,
                    (unsigned)queued,
                    (uint32_t)env->regs[0],
                    (uint32_t)env->regs[1],
                    (uint32_t)env->regs[2],
                    (uint32_t)env->regs[3],
                    (uint32_t)env->regs[13]);
            }
        }

        /* QEMU40PAD-BC-R20ET-RING */
        if (0 && rearm && post21_pending &&
            (pc == 0x80003B18U ||
             pc == 0x80003B28U ||
             pc == 0x80003A82U ||
             pc == 0x80003AB0U ||
             pc == 0x80003B2EU))
        {
            uint32_t obj=(uint32_t)env->regs[4];

            /*
             * At 3A82 r0 carries the object.
             * Everywhere else in this path r4 carries it.
             */
            if (pc == 0x80003A82U)
                obj=(uint32_t)env->regs[0];

            if (obj == 0x002E6BF4U)
            {
                uint16_t active=0,limit=0,queued=0;
                uint16_t ring20=0,ring22=0;
                uint8_t flags28=0;

                cpu_physical_memory_read(obj+0x0C,&active,2);
                cpu_physical_memory_read(obj+0x10,&limit,2);
                cpu_physical_memory_read(obj+0x12,&queued,2);
                cpu_physical_memory_read(obj+0x20,&ring20,2);
                cpu_physical_memory_read(obj+0x22,&ring22,2);
                cpu_physical_memory_read(obj+0x28,&flags28,1);

                R20EA_LOG(
                    "TARGET=DEFERRING PC=%08X LR=%08X OBJ=%08X "
                    "ACTIVE=%04X LIMIT=%04X QUEUED=%04X "
                    "R20=%04X R22=%04X FLAGS28=%02X "
                    "R0=%08X R1=%08X R2=%08X R3=%08X SP=%08X",
                    pc,
                    (uint32_t)env->regs[14],
                    obj,
                    (unsigned)active,
                    (unsigned)limit,
                    (unsigned)queued,
                    (unsigned)ring20,
                    (unsigned)ring22,
                    (unsigned)flags28,
                    (uint32_t)env->regs[0],
                    (uint32_t)env->regs[1],
                    (uint32_t)env->regs[2],
                    (uint32_t)env->regs[3],
                    (uint32_t)env->regs[13]);
            }
        }

        /* QEMU40PAD-BC-R20EU-FLAGS28 */
        if (0)
        {
            static int init=0;
            static uint8_t old_flags=0;
            uint8_t flags=0;

            cpu_physical_memory_read(0x002E6C1CU,&flags,1);

            if (!init)
            {
                old_flags=flags;
                init=1;
            }
            else if (flags != old_flags)
            {
                R20EA_LOG(
                    "TARGET=FLAGS28CHANGE PC=%08X LR=%08X "
                    "OLD=%02X NEW=%02X BIT1=%u "
                    "R0=%08X R1=%08X R2=%08X R3=%08X SP=%08X",
                    pc,
                    (uint32_t)env->regs[14],
                    (unsigned)old_flags,
                    (unsigned)flags,
                    (unsigned)((flags >> 1) & 1),
                    (uint32_t)env->regs[0],
                    (uint32_t)env->regs[1],
                    (uint32_t)env->regs[2],
                    (uint32_t)env->regs[3],
                    (uint32_t)env->regs[13]);

                old_flags=flags;
            }

            if (pc == 0x80003A82U &&
                (uint32_t)env->regs[0] == 0x002E6BF4U)
            {
                R20EA_LOG(
                    "TARGET=FLAGS28HELPER PC=%08X LR=%08X "
                    "FLAGS=%02X BIT1=%u "
                    "R0=%08X R1=%08X R2=%08X R3=%08X SP=%08X",
                    pc,
                    (uint32_t)env->regs[14],
                    (unsigned)flags,
                    (unsigned)((flags >> 1) & 1),
                    (uint32_t)env->regs[0],
                    (uint32_t)env->regs[1],
                    (uint32_t)env->regs[2],
                    (uint32_t)env->regs[3],
                    (uint32_t)env->regs[13]);
            }
        }

        /* QEMU40PAD-BC-R20EV-RING18 */
        if (0 && rearm && post21_pending &&
            (pc == 0x80003B18U ||
             pc == 0x80003B28U ||
             pc == 0x80003A82U ||
             pc == 0x80003AB2U ||
             pc == 0x80003AB6U ||
             pc == 0x80003AC0U ||
             pc == 0x80003ACAU ||
             pc == 0x80003B2EU))
        {
            uint32_t obj=(uint32_t)env->regs[4];

            if (pc == 0x80003A82U ||
                pc == 0x80003AB2U ||
                pc == 0x80003AB6U ||
                pc == 0x80003AC0U ||
                pc == 0x80003ACAU)
                obj=(uint32_t)env->regs[0];

            if (obj == 0x002E6BF4U)
            {
                uint16_t active=0,limit=0,queued=0,idx18=0;
                uint32_t ring14=0;
                uint8_t flags28=0;

                cpu_physical_memory_read(obj+0x0C,&active,2);
                cpu_physical_memory_read(obj+0x10,&limit,2);
                cpu_physical_memory_read(obj+0x12,&queued,2);
                cpu_physical_memory_read(obj+0x14,&ring14,4);
                cpu_physical_memory_read(obj+0x18,&idx18,2);
                cpu_physical_memory_read(obj+0x28,&flags28,1);

                R20EA_LOG(
                    "TARGET=RING18 PC=%08X LR=%08X "
                    "ACTIVE=%04X LIMIT=%04X QUEUED=%04X "
                    "RING14=%08X IDX18=%04X FLAGS28=%02X "
                    "R0=%08X R1=%08X R2=%08X R3=%08X SP=%08X",
                    pc,
                    (uint32_t)env->regs[14],
                    (unsigned)active,
                    (unsigned)limit,
                    (unsigned)queued,
                    ring14,
                    (unsigned)idx18,
                    (unsigned)flags28,
                    (uint32_t)env->regs[0],
                    (uint32_t)env->regs[1],
                    (uint32_t)env->regs[2],
                    (uint32_t)env->regs[3],
                    (uint32_t)env->regs[13]);
            }
        }

        /* QEMU40PAD-BC-R20EW-STATE */
        if (0)
        {
            static int watch=0;
            static uint16_t old_active=0;
            static uint16_t old_queued=0;
            static uint16_t old_w18=0;
            static uint16_t old_x1a=0;
            static uint16_t old_x20=0;
            static uint16_t old_x22=0;

            uint32_t obj=0x002E6BF4U;

            if (rearm && post21_pending &&
                pc == 0x80003B18U &&
                (uint32_t)env->regs[4] == obj)
            {
                cpu_physical_memory_read(obj+0x0C,&old_active,2);
                cpu_physical_memory_read(obj+0x12,&old_queued,2);
                cpu_physical_memory_read(obj+0x18,&old_w18,2);
                cpu_physical_memory_read(obj+0x1A,&old_x1a,2);
                cpu_physical_memory_read(obj+0x20,&old_x20,2);
                cpu_physical_memory_read(obj+0x22,&old_x22,2);

                watch=1;

                R20EA_LOG(
                    "TARGET=STATESTART "
                    "ACTIVE=%04X QUEUED=%04X "
                    "W18=%04X X1A=%04X X20=%04X X22=%04X",
                    (unsigned)old_active,
                    (unsigned)old_queued,
                    (unsigned)old_w18,
                    (unsigned)old_x1a,
                    (unsigned)old_x20,
                    (unsigned)old_x22);
            }

            if (watch)
            {
                uint16_t active=0,queued=0,w18=0,x1a=0,x20=0,x22=0;

                cpu_physical_memory_read(obj+0x0C,&active,2);
                cpu_physical_memory_read(obj+0x12,&queued,2);
                cpu_physical_memory_read(obj+0x18,&w18,2);
                cpu_physical_memory_read(obj+0x1A,&x1a,2);
                cpu_physical_memory_read(obj+0x20,&x20,2);
                cpu_physical_memory_read(obj+0x22,&x22,2);

                if (active != old_active ||
                    queued != old_queued ||
                    w18 != old_w18 ||
                    x1a != old_x1a ||
                    x20 != old_x20 ||
                    x22 != old_x22)
                {
                    R20EA_LOG(
                        "TARGET=STATECHANGE PC=%08X LR=%08X "
                        "ACTIVE=%04X->%04X QUEUED=%04X->%04X "
                        "W18=%04X->%04X X1A=%04X->%04X "
                        "X20=%04X->%04X X22=%04X->%04X "
                        "R0=%08X R1=%08X R2=%08X R3=%08X SP=%08X",
                        pc,
                        (uint32_t)env->regs[14],
                        (unsigned)old_active,(unsigned)active,
                        (unsigned)old_queued,(unsigned)queued,
                        (unsigned)old_w18,(unsigned)w18,
                        (unsigned)old_x1a,(unsigned)x1a,
                        (unsigned)old_x20,(unsigned)x20,
                        (unsigned)old_x22,(unsigned)x22,
                        (uint32_t)env->regs[0],
                        (uint32_t)env->regs[1],
                        (uint32_t)env->regs[2],
                        (uint32_t)env->regs[3],
                        (uint32_t)env->regs[13]);

                    old_active=active;
                    old_queued=queued;
                    old_w18=w18;
                    old_x1a=x1a;
                    old_x20=x20;
                    old_x22=x22;
                }
            }
        }

        /* QEMU40PAD-BC-R20EX-DEQUEUE */
        if (0)
        {
            static int init=0;
            static uint16_t old_active=0;
            static uint16_t old_w18=0;
            static uint16_t old_r1a=0;

            const uint32_t obj=0x002E6BF4U;

            uint16_t active=0,w18=0,r1a=0;

            cpu_physical_memory_read(obj+0x0C,&active,2);
            cpu_physical_memory_read(obj+0x18,&w18,2);
            cpu_physical_memory_read(obj+0x1A,&r1a,2);

            if (!init)
            {
                old_active=active;
                old_w18=w18;
                old_r1a=r1a;
                init=1;
            }
            else
            {
                if (r1a != old_r1a)
                {
                    R20EA_LOG(
                        "TARGET=R1AWRITE PC=%08X LR=%08X "
                        "ACTIVE=%04X W18=%04X R1A=%04X->%04X "
                        "R0=%08X R1=%08X R2=%08X R3=%08X "
                        "R4=%08X R5=%08X SP=%08X",
                        pc,
                        (uint32_t)env->regs[14],
                        (unsigned)active,
                        (unsigned)w18,
                        (unsigned)old_r1a,
                        (unsigned)r1a,
                        (uint32_t)env->regs[0],
                        (uint32_t)env->regs[1],
                        (uint32_t)env->regs[2],
                        (uint32_t)env->regs[3],
                        (uint32_t)env->regs[4],
                        (uint32_t)env->regs[5],
                        (uint32_t)env->regs[13]);

                    old_r1a=r1a;
                }

                if (active != old_active)
                {
                    R20EA_LOG(
                        "TARGET=ACTIVEWRITE PC=%08X LR=%08X "
                        "ACTIVE=%04X->%04X W18=%04X R1A=%04X "
                        "R0=%08X R1=%08X R2=%08X R3=%08X "
                        "R4=%08X R5=%08X SP=%08X",
                        pc,
                        (uint32_t)env->regs[14],
                        (unsigned)old_active,
                        (unsigned)active,
                        (unsigned)w18,
                        (unsigned)r1a,
                        (uint32_t)env->regs[0],
                        (uint32_t)env->regs[1],
                        (uint32_t)env->regs[2],
                        (uint32_t)env->regs[3],
                        (uint32_t)env->regs[4],
                        (uint32_t)env->regs[5],
                        (uint32_t)env->regs[13]);

                    old_active=active;
                }

                old_w18=w18;
            }
        }

        /* QEMU40PAD-BC-R20EY-DUMP */
        if (0)
        {
            static int done=0;

            if (!done &&
                pc == 0x80003BE8U &&
                (uint32_t)env->regs[4] == 0x002E6BF4U)
            {
                uint8_t b[16];
                uint32_t a;
                unsigned i;

                done=1;

                for (a=0x80003B80U; a<0x80003CC0U; a+=16)
                {
                    cpu_physical_memory_read(a,b,sizeof(b));

                    fprintf(stderr,"[R20EY] CODE=%08X",a);

                    for(i=0;i<16;i++)
                        fprintf(stderr," %02X",b[i]);

                    fprintf(stderr,"\n");
                }
            }
        }

        /* QEMU40PAD-BC-R20EZ-DISPATCH */
        if (0)
        {
            static int target_queued=0;
            static unsigned post_dispatch_count=0;
            const uint32_t obj=0x002E6BF4U;

            if (pc == 0x80003B2EU &&
                (uint32_t)env->regs[4] == obj)
            {
                uint16_t q=0,w=0,r=0;

                cpu_physical_memory_read(obj+0x12,&q,2);
                cpu_physical_memory_read(obj+0x18,&w,2);
                cpu_physical_memory_read(obj+0x1A,&r,2);

                if (q && w != r)
                {
                    target_queued=1;

                    R20EA_LOG(
                        "TARGET=DISPATCH_ARM "
                        "QUEUED=%04X W18=%04X R1A=%04X",
                        (unsigned)q,
                        (unsigned)w,
                        (unsigned)r);
                }
            }

            /* Entry of dispatcher: r0 is the object. */
            if (pc == 0x800022ECU)
            {
                uint32_t current=(uint32_t)env->regs[0];

                if (current == obj)
                {
                    uint16_t q=0,w=0,r=0,a=0;

                    cpu_physical_memory_read(obj+0x0C,&a,2);
                    cpu_physical_memory_read(obj+0x12,&q,2);
                    cpu_physical_memory_read(obj+0x18,&w,2);
                    cpu_physical_memory_read(obj+0x1A,&r,2);

                    R20EA_LOG(
                        "TARGET=TARGET_DISPATCH PC=%08X LR=%08X "
                        "POST=%d ACTIVE=%04X QUEUED=%04X "
                        "W18=%04X R1A=%04X "
                        "R1=%08X R2=%08X R3=%08X SP=%08X",
                        pc,
                        (uint32_t)env->regs[14],
                        target_queued,
                        (unsigned)a,
                        (unsigned)q,
                        (unsigned)w,
                        (unsigned)r,
                        (uint32_t)env->regs[1],
                        (uint32_t)env->regs[2],
                        (uint32_t)env->regs[3],
                        (uint32_t)env->regs[13]);
                }
                else if (target_queued && post_dispatch_count < 16)
                {
                    R20EA_LOG(
                        "TARGET=OTHER_DISPATCH N=%u "
                        "OBJ=%08X LR=%08X "
                        "R1=%08X R2=%08X R3=%08X SP=%08X",
                        post_dispatch_count,
                        current,
                        (uint32_t)env->regs[14],
                        (uint32_t)env->regs[1],
                        (uint32_t)env->regs[2],
                        (uint32_t)env->regs[3],
                        (uint32_t)env->regs[13]);

                    post_dispatch_count++;
                }
            }

            /*
             * If our target ever reaches the actual worker call
             * after the deferred enqueue, record it.
             * At this point r7 retains dispatcher input r0.
             */
            if (target_queued &&
                pc == 0x80002324U &&
                (uint32_t)env->regs[7] == obj)
            {
                R20EA_LOG(
                    "TARGET=POST_WORKER_CALL "
                    "R7=%08X R6=%08X R8=%08X R4=%08X",
                    (uint32_t)env->regs[7],
                    (uint32_t)env->regs[6],
                    (uint32_t)env->regs[8],
                    (uint32_t)env->regs[4]);
            }
        }

        /* QEMU40PAD-BC-R20FA-HANDLE */
        if (0)
        {
            static int deferred_armed=0;
            static unsigned after_count=0;

            const uint32_t obj=0x002E6BF4U;
            const uint32_t handle=0x02330062U;

            /*
             * Detect the critical deferred enqueue once the entry
             * is fully installed: W18 != R1A and QUEUED != 0.
             */
            if (pc == 0x80003B2EU &&
                (uint32_t)env->regs[4] == obj)
            {
                uint16_t q=0,w=0,r=0;

                cpu_physical_memory_read(obj+0x12,&q,2);
                cpu_physical_memory_read(obj+0x18,&w,2);
                cpu_physical_memory_read(obj+0x1A,&r,2);

                if (q && w != r)
                {
                    deferred_armed=1;

                    R20EA_LOG(
                        "TARGET=FA_ARM QUEUED=%04X W18=%04X R1A=%04X",
                        (unsigned)q,
                        (unsigned)w,
                        (unsigned)r);
                }
            }

            /*
             * Dispatcher entry: R0 is an encoded handle/token,
             * not the resolved object pointer.
             */
            if (pc == 0x800022ECU &&
                (uint32_t)env->regs[0] == handle)
            {
                R20EA_LOG(
                    "TARGET=FA_HANDLE_ENTRY POST=%d "
                    "R0=%08X R1=%08X R2=%08X R3=%08X "
                    "LR=%08X SP=%08X",
                    deferred_armed,
                    (uint32_t)env->regs[0],
                    (uint32_t)env->regs[1],
                    (uint32_t)env->regs[2],
                    (uint32_t)env->regs[3],
                    (uint32_t)env->regs[14],
                    (uint32_t)env->regs[13]);
            }

            /*
             * Immediately before resolver: R7 retains the original
             * token supplied at dispatcher entry.
             */
            if (pc == 0x80002318U &&
                (uint32_t)env->regs[7] == handle)
            {
                R20EA_LOG(
                    "TARGET=FA_RESOLVE_IN POST=%d "
                    "R7=%08X R0=%08X R6=%08X R8=%08X "
                    "R4=%08X LR=%08X SP=%08X",
                    deferred_armed,
                    (uint32_t)env->regs[7],
                    (uint32_t)env->regs[0],
                    (uint32_t)env->regs[6],
                    (uint32_t)env->regs[8],
                    (uint32_t)env->regs[4],
                    (uint32_t)env->regs[14],
                    (uint32_t)env->regs[13]);
            }

            /*
             * At 0x80002324 the resolver has returned; R0 should
             * now be the actual object passed to 0x80003B8A.
             */
            if (pc == 0x80002324U &&
                (uint32_t)env->regs[7] == handle)
            {
                R20EA_LOG(
                    "TARGET=FA_WORKER_CALL POST=%d "
                    "HANDLE=%08X RESOLVED=%08X "
                    "R1=%08X R2=%08X R3=%08X SP=%08X",
                    deferred_armed,
                    (uint32_t)env->regs[7],
                    (uint32_t)env->regs[0],
                    (uint32_t)env->regs[1],
                    (uint32_t)env->regs[2],
                    (uint32_t)env->regs[3],
                    (uint32_t)env->regs[13]);
            }

            /*
             * Limited witness that dispatcher activity continues
             * after the target queue became pending.
             */
            if (deferred_armed &&
                pc == 0x800022ECU &&
                after_count < 16)
            {
                R20EA_LOG(
                    "TARGET=FA_AFTER N=%u HANDLE=%08X "
                    "R1=%08X LR=%08X",
                    after_count,
                    (uint32_t)env->regs[0],
                    (uint32_t)env->regs[1],
                    (uint32_t)env->regs[14]);

                after_count++;
            }
        }

        /* QEMU40PAD-BC-R20FB-CRITICAL */
        if (0)
        {
            static int critical=0;
            static unsigned n=0;

            const uint32_t obj=0x002E6BF4U;
            const uint32_t handle=0x02330062U;

            if (!critical &&
                pc == 0x80003B2EU &&
                (uint32_t)env->regs[4] == obj)
            {
                uint16_t q=0,w=0,r=0,a=0;

                cpu_physical_memory_read(obj+0x0C,&a,2);
                cpu_physical_memory_read(obj+0x12,&q,2);
                cpu_physical_memory_read(obj+0x18,&w,2);
                cpu_physical_memory_read(obj+0x1A,&r,2);

                if (a == 0 && q == 1 && w == 4 && r == 3)
                {
                    critical=1;

                    R20EA_LOG(
                        "TARGET=FB_CRITICAL "
                        "ACTIVE=%04X QUEUED=%04X W18=%04X R1A=%04X",
                        (unsigned)a,
                        (unsigned)q,
                        (unsigned)w,
                        (unsigned)r);
                }
            }

            if (critical &&
                pc == 0x800022ECU &&
                n < 32)
            {
                R20EA_LOG(
                    "TARGET=FB_DISPATCH N=%u "
                    "HANDLE=%08X TARGET=%d "
                    "R1=%08X R2=%08X R3=%08X "
                    "LR=%08X SP=%08X",
                    n,
                    (uint32_t)env->regs[0],
                    ((uint32_t)env->regs[0] == handle),
                    (uint32_t)env->regs[1],
                    (uint32_t)env->regs[2],
                    (uint32_t)env->regs[3],
                    (uint32_t)env->regs[14],
                    (uint32_t)env->regs[13]);

                n++;
            }

            if (critical &&
                pc == 0x80002324U &&
                (uint32_t)env->regs[7] == handle)
            {
                R20EA_LOG(
                    "TARGET=FB_TARGET_WORKER "
                    "HANDLE=%08X RESOLVED=%08X",
                    (uint32_t)env->regs[7],
                    (uint32_t)env->regs[0]);
            }
        }

        /* QEMU40PAD-BC-R20FC-DUMP */
        if (0)
        {
            static int done=0;

            if (!done &&
                pc == 0x00001D05U)
            {
                uint8_t b[16];
                uint32_t a;
                unsigned i;

                done=1;

                for (a=0x00001CC0U; a<0x00001D30U; a+=16)
                {
                    cpu_physical_memory_read(a,b,sizeof(b));

                    fprintf(stderr,"[R20FC] CODE=%08X",a);

                    for(i=0;i<16;i++)
                        fprintf(stderr," %02X",b[i]);

                    fprintf(stderr,"\n");
                }
            }
        }

        /* QEMU40PAD-BC-R20FD-DUMP */
        {
            static int done=0;

            /*
             * 0x1D05 is a Thumb return address, therefore use it
             * as LR witness at dispatcher entry rather than PC.
             */
            if (!done &&
                pc == 0x800022ECU &&
                (uint32_t)env->regs[14] == 0x00001D05U)
            {
                uint8_t b[16];
                uint32_t a;
                unsigned i;

                done=1;

                R20EA_LOG(
                    "TARGET=FD_TRIGGER PC=%08X LR=%08X "
                    "R0=%08X R1=%08X R2=%08X R3=%08X",
                    pc,
                    (uint32_t)env->regs[14],
                    (uint32_t)env->regs[0],
                    (uint32_t)env->regs[1],
                    (uint32_t)env->regs[2],
                    (uint32_t)env->regs[3]);

                for (a=0x00001CC0U; a<0x00001D30U; a+=16)
                {
                    cpu_physical_memory_read(a,b,sizeof(b));

                    fprintf(stderr,"[R20FD] CODE=%08X",a);

                    for(i=0;i<16;i++)
                        fprintf(stderr," %02X",b[i]);

                    fprintf(stderr,"\n");
                }
            }
        }

        /* QEMU40PAD-BC-R20EE-QUEUE-PRIMITIVE */
        if (rearm && post21_pending &&
            pc < 0x00001E80U &&
            end > 0x00001D80U)
        {
            R20EA_LOG(
                "TARGET=QUEUEPATH PC=%08X SIZE=%u "
                "LR=%08X R0=%08X R1=%08X R2=%08X R3=%08X "
                "R4=%08X R5=%08X SP=%08X",
                pc,
                (unsigned)tb->size,
                (uint32_t)env->regs[14],
                (uint32_t)env->regs[0],
                (uint32_t)env->regs[1],
                (uint32_t)env->regs[2],
                (uint32_t)env->regs[3],
                (uint32_t)env->regs[4],
                (uint32_t)env->regs[5],
                (uint32_t)env->regs[13]);
        }

        /* QEMU40PAD-BC-R20EC-LOWRAM-PATH
         *
         * Trace only the low-RAM Thumb dispatcher while this
         * particular event21 post is inside FE43515C.
         */
        if (rearm && post21_pending &&
            pc < 0x00002500U &&
            end > 0x00001F00U &&
            post21_lowtrace < 80)
        {
            const char *mark="";

            if (0x0000235AU >= pc && 0x0000235AU < end)
                mark=" ENTRY235A";
            else if (0x0000226AU >= pc && 0x0000226AU < end)
                mark=" CALL226A";

            R20EA_LOG(
                "TARGET=LOWPATH N=%u PC=%08X SIZE=%u "
                "LR=%08X R0=%08X R1=%08X R2=%08X R3=%08X "
                "SP=%08X%s",
                ++post21_lowtrace,
                pc,
                (unsigned)tb->size,
                (uint32_t)env->regs[14],
                (uint32_t)env->regs[0],
                (uint32_t)env->regs[1],
                (uint32_t)env->regs[2],
                (uint32_t)env->regs[3],
                (uint32_t)env->regs[13],
                mark);
        }

        /*
         * FE138704 is immediately after BLX FE43515C.
         * R0 is therefore the low-level DispDCtrl post result.
         */
        if (rearm && post21_pending &&
            R20EA_HIT(0xFE138704U))
        {
            uint32_t c[4]={0};

            if (post21_ctrl)
                cpu_physical_memory_read(
                    post21_ctrl,c,sizeof(c));

            R20EA_LOG(
                "TARGET=POST21_LOWRET R0=%08X CTRL=%08X "
                "C0=%08X C1=%08X C2=%08X C3=%08X",
                (uint32_t)env->regs[0],
                post21_ctrl,
                c[0],c[1],c[2],c[3]);

            post21_pending=0;
        }

        /*
         * Consumer registered by DispDCtrl.
         * For FE11087E the event/input is R1.
         */
        if (rearm &&
            R20EA_HIT(0xFE11087EU) &&
            (uint32_t)env->regs[1]==21U)
        {
            R20EA_LOG(
                "TARGET=CONSUMER21 R0=%08X R1=%08X R2=%08X "
                "R3=%08X LR=%08X",
                (uint32_t)env->regs[0],
                (uint32_t)env->regs[1],
                (uint32_t)env->regs[2],
                (uint32_t)env->regs[3],
                (uint32_t)env->regs[14]);
        }

        /* QEMU40PAD-BC-R20EF-CALLBACK-PATH */
        if (rearm &&
            pc < 0xFE110570U &&
            end > 0xFE110530U)
        {
            R20EA_LOG(
                "TARGET=CALLBACKPATH PC=%08X SIZE=%u "
                "LR=%08X R0=%08X R1=%08X R2=%08X R3=%08X "
                "R4=%08X R5=%08X SP=%08X",
                pc,
                (unsigned)tb->size,
                (uint32_t)env->regs[14],
                (uint32_t)env->regs[0],
                (uint32_t)env->regs[1],
                (uint32_t)env->regs[2],
                (uint32_t)env->regs[3],
                (uint32_t)env->regs[4],
                (uint32_t)env->regs[5],
                (uint32_t)env->regs[13]);
        }

        /* Event21 supplied callback. */
        if (rearm && R20EA_HIT(0xFE110538U))
            R20EA_LOG("TARGET=EVENT21_CALLBACK LR=%08X",
                (uint32_t)env->regs[14]);

        /* Keep proven completion/wait witnesses from R20DM-R2. */
        if (rearm &&
            R20EA_HIT(0xFE138912U) &&
            (uint32_t)env->regs[0]==0x046C0070U)
            R20EA_LOG("TARGET=EVENT21_GIVE LR=%08X",
                (uint32_t)env->regs[14]);

        if (rearm &&
            R20EA_HIT(0xFE1388F2U) &&
            (uint32_t)env->regs[14]==0xFE468523U)
        {
            qemu40_gy_event21_wait = 1;
            R20EA_LOG("TARGET=EVENT21_WAIT");
        }

        if (rearm &&
            R20EA_HIT(0xFE13890EU) &&
            (uint32_t)env->regs[4]==0x046C0070U)
        {
            qemu40_gy_event21_wait = 0;
            R20EA_LOG("TARGET=EVENT21_WAIT_RETURN");
        }

        /* First localSet arms the exact historical rearm condition. */
        if (R20EA_HIT(0xFE119232U))
        {
            uint32_t r2=(uint32_t)env->regs[2];

            R20EA_LOG("TARGET=LOCALSET R2=%08X",r2);

            if (!first_localset)
                first_localset=1;
        }

#undef R20EA_LOG
#undef R20EA_HIT
    }

    if (current_cpu->cpu_index)
    {
        /* ignore CPU1 for now */
        return;
    }

    if (qemu_loglevel_mask(EOS_LOG_AUTOEXEC) &&
        saved_loglevel != 0 &&
        saved_loglevel != qemu_loglevel)
    {
        if ((tb->pc & ~0x40000000) == 0x800000)
        {
            fprintf(stderr, "[EOS] enabling verbose logging for autoexec.bin...\n");
            qemu_loglevel = saved_loglevel;
            saved_loglevel = 0;
        }
    }

    if (qemu_loglevel_mask(EOS_LOG_TASKS))
    {
        eos_tasks_log_exec(cpu, tb);
    }

    if (qemu_loglevel_mask(EOS_LOG_CALLSTACK))
    {
        /* - callstack only exposes this functionality
         *   to other "modules" on request
         * - calls is verbose and implies callstack
         */
        eos_callstack_log_exec(cpu, tb);
    }

    if (qemu_loglevel_mask(EOS_LOG_RAM_MEMCHK))
    {
        ARMCPU *arm_cpu = ARM_CPU(cpu);
        CPUARMState *env = &arm_cpu->env;
        eos_memcheck_log_exec(tb->pc, env);
    }

#ifdef BKT_CROSSCHECK_EXEC
    eos_bkt_log_exec();
#endif

    if (qemu_loglevel_mask(EOS_LOG_DEBUGMSG) && DebugMsg_addr)
    {
        static uint32_t prev_pc = 0;
        if (tb->pc == DebugMsg_addr && tb->pc != prev_pc)
        {
            if (qemu_loglevel_mask(EOS_LOG_DEBUGMSG) &&
                qemu_loglevel_mask(EOS_LOG_VERBOSE))
            {
                eos_callstack_print_verbose();
            }
            // SJE this is now done the Qemu 4 way, by instrumenting
            // instructions, not TBs
            //
            // SJE TODO: more of the above should probably be moved
            // into the per instruction plugin
            //DebugMsg_log();
        }
        prev_pc = tb->pc;
    }
}

static void load_symbols(const char *elf_filename)
{
    fprintf(stderr, "[EOS] loading symbols from %s ", elf_filename);
    uint64_t lo, hi;
    int size = load_elf(elf_filename, NULL, NULL, NULL, NULL,
                        &lo, &hi, 0, EM_ARM, 1, 0);
    fprintf(stderr, "(%X - %X)\n", (int) lo, (int) hi);
    assert(size > 0);
}

void eos_getenv_hex(const char *env_name, uint32_t *var, uint32_t default_value)
{
    char *env = getenv(env_name);

    if (env)
    {
        *var = strtoul(env, NULL, 16);
    }
    else
    {
        *var = default_value;
    }
}

void eos_logging_init(void)
{
    eos_getenv_hex("QEMU_EOS_DEBUGMSG", &DebugMsg_addr, 0);

    if (qemu_loglevel_mask(EOS_LOG_CALLSTACK    |
                           EOS_LOG_RAM_MEMCHK   |
                           EOS_LOG_TASKS        |
                           EOS_LOG_AUTOEXEC     |
                           EOS_LOG_DEBUGMSG     |
                           0))
    {
        fprintf(stderr, "[EOS] enabling code execution logging.\n");
        cpu_set_tb_exec_cb(tb_exec_cb);
    }

    if (qemu_loglevel_mask(EOS_LOG_MEM))
    {
        int mem_access_mode =
            (qemu_loglevel_mask(EOS_LOG_MEM_R) ? PROT_READ : 0) |
            (qemu_loglevel_mask(EOS_LOG_MEM_W) ? PROT_WRITE : 0);

        fprintf(stderr, "[EOS] enabling memory access logging (%s%s).\n",
            (mem_access_mode & PROT_READ) ? "R" : "",
            (mem_access_mode & PROT_WRITE) ? "W" : ""
        );

        memory_set_access_logging_cb(eos_log_mem, mem_access_mode);

        /* make sure the backends are enabled */
        if (qemu_loglevel_mask(EOS_PR(EOS_LOG_RAM_R))) assert(qemu_loglevel_mask(EOS_LOG_RAM_R));
        if (qemu_loglevel_mask(EOS_PR(EOS_LOG_RAM_W))) assert(qemu_loglevel_mask(EOS_LOG_RAM_W));
        if (qemu_loglevel_mask(EOS_PR(EOS_LOG_ROM_R))) assert(qemu_loglevel_mask(EOS_LOG_ROM_R));
        if (qemu_loglevel_mask(EOS_PR(EOS_LOG_ROM_W))) assert(qemu_loglevel_mask(EOS_LOG_ROM_W));
    }

    if (qemu_loglevel_mask(EOS_LOG_RAM_MEMCHK))
    {
        eos_memcheck_init();
    }

    if (qemu_loglevel_mask(CPU_LOG_TB_NOCHAIN))
    {
        fprintf(stderr, "[EOS] enabling singlestep.\n");
        singlestep = 1;
    }

    const char *ml_path = getenv("QEMU_ML_PATH");
    if (ml_path && ml_path[0])
    {
        char sym[512];
        snprintf(sym, sizeof(sym), "%s/autoexec", ml_path);
        load_symbols(sym);
        snprintf(sym, sizeof(sym), "%s/magiclantern", ml_path);
        load_symbols(sym);
    }

    if (qemu_loglevel_mask(EOS_LOG_AUTOEXEC) && qemu_loglevel)
    {
        saved_loglevel = qemu_loglevel;
        qemu_loglevel &= ~(
            EOS_LOG_VERBOSE |
            EOS_LOG_CALLS   |
            EOS_LOG_IO      |
            EOS_LOG_MEM     |
            CPU_LOG_EXEC    |
        0);

        if (saved_loglevel != qemu_loglevel)
        {
            fprintf(stderr, "[EOS] disabling verbose logging until autoexec.bin starts...\n");
        }
    }
}
