#define NOB_IMPLEMENTATION
#include "nob.h"

bool compile_binary(const char *input, const char *output)
{
    Nob_Cmd cmd = {0};
    nob_cmd_append(&cmd, "cc", "-Wall", "-Wextra", "-ggdb", "-o", output, input);
    bool result = nob_cmd_run_sync(cmd);
    free(cmd.items);
    return result;
}

int main(int argc, char **argv)
{
    NOB_GO_REBUILD_URSELF(argc, argv);
    if (!compile_binary("bfjit.c", "bfjit")) return 1;
    if (!compile_binary("runbin.c", "runbin")) return 1;
    return 0;
}
