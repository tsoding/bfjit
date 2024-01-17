#define NOB_IMPLEMENTATION
#include "nob.h"

#include <sys/mman.h>

typedef void(*run)(const char *buf, size_t size);

int main(int argc, char **argv)
{
    const char *program = nob_shift_args(&argc, &argv);

    if (argc <= 0) {
        nob_log(NOB_ERROR, "Usage: %s <input.bin>", program);
        nob_log(NOB_ERROR, "No input is provided");
        return 1;
    }

    const char *file_path = nob_shift_args(&argc, &argv);
    Nob_String_Builder sb = {0};
    if (!nob_read_entire_file(file_path, &sb)) return 1;

    void *code = mmap(NULL, sb.count, PROT_EXEC | PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (code == MAP_FAILED) {
        nob_log(NOB_ERROR, "Could not allocate executable memory: %s", strerror(errno));
        return 1;
    }

    memcpy(code, sb.items, sb.count);

    const char *message = "urmom";
    ((run)code)(message, strlen(message));

    return 0;
}
