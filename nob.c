#define NOB_IMPLEMENTATION
#include "nob.h"

int main(int argc, char **argv)
{
    NOB_GO_REBUILD_URSELF(argc, argv);
    Nob_Cmd cmd = {0};

    cmd.count = 0;
    nob_cmd_append(&cmd, "cc", "-Wall", "-Wextra", "-ggdb", "-o", "bfjit", "bfjit.c");
    if (!nob_cmd_run_sync(cmd)) return 1;

    cmd.count = 0;
    nob_cmd_append(&cmd, "cc", "-Wall", "-Wextra", "-ggdb", "-o", "runbin", "runbin.c");
    if (!nob_cmd_run_sync(cmd)) return 1;

    return 0;
}
