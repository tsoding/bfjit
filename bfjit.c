#include <stdio.h>
#include <stdint.h>

#include <sys/mman.h>

#define NOB_IMPLEMENTATION
#include "nob.h"

#define JIT_MEMORY_CAP (10*1000*1000)

typedef enum {
    OP_INC             = '+',
    OP_DEC             = '-',
    OP_LEFT            = '<',
    OP_RIGHT           = '>',
    OP_OUTPUT          = '.',
    OP_INPUT           = ',',
    OP_JUMP_IF_ZERO    = '[',
    OP_JUMP_IF_NONZERO = ']',
} Op_Kind;

typedef struct {
    Op_Kind kind;
    size_t operand;
} Op;

typedef struct {
    Op *items;
    size_t count;
    size_t capacity;
} Ops;

typedef struct {
    Nob_String_View content;
    size_t pos;
} Lexer;

bool is_bf_cmd(char ch)
{
    const char *cmds = "+-<>,.[]";
    return strchr(cmds, ch) != NULL;
}

char lexer_next(Lexer *l)
{
    while (l->pos < l->content.count && !is_bf_cmd(l->content.data[l->pos])) {
        l->pos += 1;
    }
    if (l->pos >= l->content.count) return 0;
    return l->content.data[l->pos++];
}

typedef struct {
    size_t *items;
    size_t count;
    size_t capacity;
} Addrs;

bool interpret(Ops ops)
{
    bool result = true;
    // TODO: there is a memory management discrepancy between interpretation and JIT.
    // Interpretation automatically extends the memory, but JIT has a fixed size memory (to simplify implementation).
    // This discrepancy should be closed somehow
    Nob_String_Builder memory = {0};
    nob_da_append(&memory, 0);
    size_t head = 0;
    size_t ip = 0;
    while (ip < ops.count) {
        Op op = ops.items[ip];
        switch (op.kind) {
            case OP_INC: {
                memory.items[head] += op.operand;
                ip += 1;
            } break;

            case OP_DEC: {
                memory.items[head] -= op.operand;
                ip += 1;
            } break;

            case OP_LEFT: {
                if (head < op.operand) {
                    printf("RUNTIME ERROR: Memory underflow");
                    nob_return_defer(false);
                }
                head -= op.operand;
                ip += 1;
            } break;

            case OP_RIGHT: {
                head += op.operand;
                while (head >= memory.count) {
                    nob_da_append(&memory, 0);
                }
                ip += 1;
            } break;

            case OP_INPUT: {
                for (size_t i = 0; i < op.operand; ++i) {
                    fread(&memory.items[head], 1, 1, stdin);
                }
                ip += 1;
            } break;

            case OP_OUTPUT: {
                for (size_t i = 0; i < op.operand; ++i) {
                    fwrite(&memory.items[head], 1, 1, stdout);
                }
                ip += 1;
            } break;

            case OP_JUMP_IF_ZERO: {
                if (memory.items[head] == 0) {
                    ip = op.operand;
                } else {
                    ip += 1;
                }
            } break;

            case OP_JUMP_IF_NONZERO: {
                if (memory.items[head] != 0) {
                    ip = op.operand;
                } else {
                    ip += 1;
                }
            } break;
        }
    }

defer:
    nob_da_free(memory);
    return result;
}

typedef struct {
    void (*run)(void *memory);
    size_t len;
} Code;

void free_code(Code code)
{
    munmap(code.run, code.len);
}

typedef struct {
    size_t operand_byte_addr;
    size_t src_byte_addr;
    size_t dst_op_index;
} Backpatch;

typedef struct {
    Backpatch *items;
    size_t count;
    size_t capacity;
} Backpatches;

bool jit_compile(Ops ops, Code *code)
{
    bool result = true;
    Nob_String_Builder sb = {0};
    Backpatches backpatches = {0};
    Addrs addrs = {0};

    for (size_t i = 0; i < ops.count; ++i) {
        Op op = ops.items[i];
        nob_da_append(&addrs, sb.count);
        switch (op.kind) {
            case OP_INC: {
                assert(op.operand < 256 && "TODO: support bigger operands");
                nob_sb_append_cstr(&sb, "\x80\x07"); // add byte[rdi],
                nob_da_append(&sb, op.operand&0xFF);
            } break;

            case OP_DEC: {
                assert(op.operand < 256 && "TODO: support bigger operands");
                nob_sb_append_cstr(&sb, "\x80\x2f"); // sub byte[rdi],
                nob_da_append(&sb, op.operand&0xFF);
            } break;

            // TODO: range checks for OP_LEFT and OP_RIGHT
            case OP_LEFT: {
                nob_sb_append_cstr(&sb, "\x48\x81\xef"); // sub rdi,
                uint32_t operand = (uint32_t)op.operand;
                nob_da_append_many(&sb, &operand, sizeof(operand));
            } break;

            case OP_RIGHT: {
                nob_sb_append_cstr(&sb, "\x48\x81\xc7"); // add rdi,
                uint32_t operand = (uint32_t)op.operand;
                nob_da_append_many(&sb, &operand, sizeof(operand));
            } break;

            case OP_OUTPUT: {
                for (size_t i = 0; i < op.operand; ++i) {
                    nob_sb_append_cstr(&sb, "\x57");                            // push rdi
                    nob_da_append_many(&sb, "\x48\xc7\xc0\x01\x00\x00\x00", 7); // mov rax, 1
                    nob_sb_append_cstr(&sb, "\x48\x89\xfe");                    // mov rsi, rdi
                    nob_da_append_many(&sb, "\x48\xc7\xc7\x01\x00\x00\x00", 7); // mov rdi, 1
                    nob_da_append_many(&sb, "\x48\xc7\xc2\x01\x00\x00\x00", 7); // mov rdx, 1
                    nob_sb_append_cstr(&sb, "\x0f\x05");                        // syscall
                    nob_sb_append_cstr(&sb, "\x5f");                            // pop rdi
                }
            } break;

            case OP_INPUT: {
                for (size_t i = 0; i < op.operand; ++i) {
                    nob_sb_append_cstr(&sb, "\x57");                            // push rdi
                    nob_da_append_many(&sb, "\x48\xc7\xc0\x00\x00\x00\x00", 7); // mov rax, 0
                    nob_sb_append_cstr(&sb, "\x48\x89\xfe");                    // mov rsi, rdi
                    nob_da_append_many(&sb, "\x48\xc7\xc7\x00\x00\x00\x00", 7); // mov rdi, 0
                    nob_da_append_many(&sb, "\x48\xc7\xc2\x01\x00\x00\x00", 7); // mov rdx, 1
                    nob_sb_append_cstr(&sb, "\x0f\x05");                        // syscall
                    nob_sb_append_cstr(&sb, "\x5f");                            // pop rdi
                }
            } break;

            case OP_JUMP_IF_ZERO: {
                nob_sb_append_cstr(&sb, "\x8a\x07");     // mov al, byte [rdi]
                nob_sb_append_cstr(&sb, "\x84\xc0");     // test al, al
                nob_sb_append_cstr(&sb, "\x0f\x84");     // jz
                size_t operand_byte_addr = sb.count;
                nob_da_append_many(&sb, "\x00\x00\x00\x00", 4);
                size_t src_byte_addr = sb.count;

                Backpatch bp = {
                    .operand_byte_addr = operand_byte_addr,
                    .src_byte_addr = src_byte_addr,
                    .dst_op_index = op.operand,
                };

                nob_da_append(&backpatches, bp);
            } break;

            case OP_JUMP_IF_NONZERO: {
                nob_sb_append_cstr(&sb, "\x8a\x07");     // mov al, byte [rdi]
                nob_sb_append_cstr(&sb, "\x84\xc0");     // test al, al
                nob_sb_append_cstr(&sb, "\x0f\x85");     // jnz
                size_t operand_byte_addr = sb.count;
                nob_da_append_many(&sb, "\x00\x00\x00\x00", 4);
                size_t src_byte_addr = sb.count;

                Backpatch bp = {
                    .operand_byte_addr = operand_byte_addr,
                    .src_byte_addr = src_byte_addr,
                    .dst_op_index = op.operand,
                };

                nob_da_append(&backpatches, bp);
            } break;

            default: assert(0 && "Unreachable");
        }
    }
    nob_da_append(&addrs, sb.count);

    for (size_t i = 0; i < backpatches.count; ++i) {
        Backpatch bp = backpatches.items[i];
        int32_t src_addr = bp.src_byte_addr;
        int32_t dst_addr = addrs.items[bp.dst_op_index];
        int32_t operand = dst_addr - src_addr;
        memcpy(&sb.items[bp.operand_byte_addr], &operand, sizeof(operand));
    }

    nob_sb_append_cstr(&sb, "\xC3");

    code->len = sb.count;
    code->run = mmap(NULL, sb.count, PROT_EXEC | PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (code->run == MAP_FAILED) {
        nob_log(NOB_ERROR, "Could not allocate executable memory: %s", strerror(errno));
        nob_return_defer(false);
    }

    // TODO: switch the permissions to only-exec after finishing copying the code. See mprotect(2).
    memcpy(code->run, sb.items, code->len);

defer:
    if (!result) {
        free_code(*code);
        memset(code, 0, sizeof(*code));
    }
    nob_da_free(sb);
    nob_da_free(backpatches);
    nob_da_free(addrs);
    return result;
}

bool generate_ops(const char *file_path, Ops *ops)
{
    bool result = true;
    Nob_String_Builder sb = {0};
    Addrs stack = {0};

    if (!nob_read_entire_file(file_path, &sb)) {
        nob_return_defer(false);
    }
    Lexer l = {
        .content = {
            .data = sb.items,
            .count = sb.count,
        },
    };
    char c = lexer_next(&l);
    while (c) {
        switch (c) {
            case '.':
            case ',':
            case '<':
            case '>':
            case '-':
            case '+': {
                size_t count = 1;
                char s = lexer_next(&l);
                while (s == c) {
                    count += 1;
                    s = lexer_next(&l);
                }
                Op op = {
                    .kind = c,
                    .operand = count,
                };
                nob_da_append(ops, op);
                c = s;
            } break;

            case '[': {
                size_t addr = ops->count;
                Op op = {
                    .kind = c,
                    .operand = 0,
                };
                nob_da_append(ops, op);
                nob_da_append(&stack, addr);

                c = lexer_next(&l);
            } break;

            case ']': {
                if (stack.count == 0) {
                    // TODO: reports rows and columns
                    printf("%s [%zu]: ERROR: Unbalanced loop\n", file_path, l.pos);
                    nob_return_defer(false);
                }

                size_t addr = stack.items[--stack.count];
                Op op = {
                    .kind = c,
                    .operand = addr + 1,
                };
                nob_da_append(ops, op);
                ops->items[addr].operand = ops->count;

                c = lexer_next(&l);
            } break;

            default: {}
        }
    }

    if (stack.count > 0) {
        // TODO: report the location of opening unbalanced bracket
        printf("%s [%zu]: ERROR: Unbalanced loop\n", file_path, l.pos);
        nob_return_defer(false);
    }

defer:
    if (!result) {
        nob_da_free(*ops);
        memset(ops, 0, sizeof(*ops));
    }
    nob_da_free(sb);
    nob_da_free(stack);
    return result;
}

void usage(const char *program)
{
    nob_log(NOB_ERROR, "Usage: %s [--no-jit] <input.bf>", program);
}

int main(int argc, char **argv)
{
    int result = 0;
    Ops ops = {0};
    Code code = {0};
    void *memory = NULL;

    const char *program = nob_shift_args(&argc, &argv);

    bool no_jit = false;
    const char *file_path = NULL;

    while (argc > 0) {
        const char *flag = nob_shift_args(&argc, &argv);
        if (strcmp(flag, "--no-jit") == 0) {
            no_jit = true;
        } else {
            if (file_path != NULL) {
                usage(program);
                // TODO(multifile): what if we allowed providing several files and executed them sequencially
                // preserving the state of the machine between them? Maybe complicated by TODO(dead).
                nob_log(NOB_ERROR, "Providing several files is not supported");
                nob_return_defer(1);
            }

            file_path = flag;
        }
    }

    if (file_path == NULL) {
        usage(program);
        nob_log(NOB_ERROR, "No input is provided");
        nob_return_defer(1);
    }

    if (!generate_ops(file_path, &ops)) nob_return_defer(1);

    if (no_jit) {
        nob_log(NOB_INFO, "JIT: off");
        if (!interpret(ops)) nob_return_defer(1);
    } else {
        nob_log(NOB_INFO, "JIT: on");
        if (!jit_compile(ops, &code)) nob_return_defer(1);
        memory = malloc(JIT_MEMORY_CAP);
        memset(memory, 0, JIT_MEMORY_CAP);
        assert(memory != NULL);
        code.run(memory);
    }

defer:
    nob_da_free(ops);
    free_code(code);
    free(memory);
    return result;
}

// TODO: Add more interesting examples.
//   Check https://brainfuck.org/ for inspiration
// TODO(dead): Dead code eliminate first loop which traditionally used as a comment.
//   May not work well if we start sequencially executing several files,
//   because consequent files may not start from the zero state.
//   See TODO(multifile).
// TODO: Optimize pattern [-] to just set the current cell to 0.
//   Probably on the level of IR.
// TODO: Windows port.
//   - [ ] Platform specific mapping of executable memory
//   - [ ] Platform specific stdio from JIT compiled machine code
