#define _POSIX_C_SOURCE 200809L
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <ctype.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <semaphore.h>
#include <errno.h>

#define SHM_SIZE 8192

static void err_exit(const char *msg) {
    char buf[256];
    int n = snprintf(buf, sizeof(buf), "%s: %d\n", msg, errno);
    if (n > 0) write(2, buf, (size_t)n);
    _exit(1);
}

static void write_str(const char *s) {
    write(2, s, strlen(s));
}

int main(int argc, char **argv) {

    if (argc != 5) {
        write_str("Usage: child2 <shm_c1_c2> <shm_c2_p> <sem_c1_c2> <sem_c2_p>\n");
        return 2;
    }

    const char *shm_in_name  = argv[1];
    const char *shm_out_name = argv[2];
    const char *sem_in_name  = argv[3];
    const char *sem_out_name = argv[4];

    int fd_in  = shm_open(shm_in_name,  O_RDWR, 0);
    int fd_out = shm_open(shm_out_name, O_RDWR, 0);
    if (fd_in == -1 || fd_out == -1)
        err_exit("shm_open child2");

    void *shm_in = mmap(NULL, SHM_SIZE, PROT_READ | PROT_WRITE, MAP_SHARED, fd_in, 0);
    void *shm_out = mmap(NULL, SHM_SIZE, PROT_READ | PROT_WRITE, MAP_SHARED, fd_out, 0);
    if (shm_in == MAP_FAILED || shm_out == MAP_FAILED)
        err_exit("mmap child2");

    sem_t *sem_in  = sem_open(sem_in_name, 0);
    sem_t *sem_out = sem_open(sem_out_name, 0);
    if (sem_in == SEM_FAILED || sem_out == SEM_FAILED)
        err_exit("sem_open child2");

    while (1) {

        if (sem_wait(sem_in) == -1)
            err_exit("sem_wait child2");

        uint32_t len;
        memcpy(&len, shm_in, sizeof(len));

        if (len == 0) {
            uint32_t zero = 0;
            memcpy(shm_out, &zero, sizeof(zero));
            sem_post(sem_out);
            break;
        }

        if (len + sizeof(len) > SHM_SIZE) {
            write_str("child2: too large\n");
            continue;
        }

        char *tmp = malloc(len + 1);
        if (!tmp)
            err_exit("malloc child2");

        memcpy(tmp, (char*)shm_in + sizeof(len), len);
        tmp[len] = '\0';

        for (uint32_t i = 0; i < len; ++i) {
            if (isspace((unsigned char)tmp[i]))
                tmp[i] = '_';
        }

        memcpy(shm_out, &len, sizeof(len));
        memcpy((char*)shm_out + sizeof(len), tmp, len);

        sem_post(sem_out);
        free(tmp);
    }

    munmap(shm_in, SHM_SIZE);
    munmap(shm_out, SHM_SIZE);
    close(fd_in);
    close(fd_out);
    sem_close(sem_in);
    sem_close(sem_out);

    return 0;
}
