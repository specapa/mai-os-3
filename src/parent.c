#define _POSIX_C_SOURCE 200809L
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <semaphore.h>
#include <sys/wait.h>
#include <errno.h>
#include <sys/types.h>

#define SHM_SIZE 8192
#define LINE_BUF 4096

static void write_all(int fd, const void *buf, size_t len) {
    const char *p = (const char*)buf;
    while (len > 0) {
        ssize_t w = write(fd, p, len);
        if (w == -1) {
            if (errno == EINTR) continue;
            _exit(2);
        }
        p += w;
        len -= (size_t)w;
    }
}

static void fatal_errno_exit(const char *prefix) {
    char tmp[512];
    int n = snprintf(tmp, sizeof(tmp), "%s: %s\n", prefix, strerror(errno));
    if (n < 0) _exit(2);
    write_all(STDERR_FILENO, tmp, (size_t)n);
    _exit(EXIT_FAILURE);
}

static void fatal_msg_exit(const char *msg) {
    size_t len = strlen(msg);
    write_all(STDERR_FILENO, msg, len);
    write_all(STDERR_FILENO, "\n", 1);
    _exit(EXIT_FAILURE);
}

static int create_and_map_shm(const char *name, size_t size, void **out_addr, int *out_fd) {
    int fd = shm_open(name, O_RDWR | O_CREAT | O_EXCL, 0600);
    if (fd == -1) return -1;
    if (ftruncate(fd, size) == -1) {
        close(fd);
        shm_unlink(name);
        return -1;
    }
    void *addr = mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (addr == MAP_FAILED) {
        close(fd);
        shm_unlink(name);
        return -1;
    }
    *out_addr = addr;
    *out_fd = fd;
    return 0;
}

static ssize_t read_line(int fd, char *buf, size_t maxlen) {
    size_t pos = 0;
    char c;
    for (;;) {
        ssize_t r = read(fd, &c, 1);
        if (r == 0) {
            return (ssize_t)pos;
        }
        if (r == -1) {
            if (errno == EINTR) continue;
            return -1;
        }
        if (c == '\n') {
            return (ssize_t)pos;
        }
        if (pos + 1 < maxlen) {
            buf[pos++] = c;
        } else {
            while (c != '\n') {
                ssize_t r2 = read(fd, &c, 1);
                if (r2 <= 0) break;
                if (c == '\n') break;
            }
            return (ssize_t)pos;
        }
    }
}

int main(void) {
    pid_t pid = getpid();
    char shm_p_c1_name[128], shm_c1_c2_name[128], shm_c2_p_name[128];
    char sem_p_c1_name[128], sem_c1_c2_name[128], sem_c2_p_name[128];

    int n;
    n = snprintf(shm_p_c1_name, sizeof(shm_p_c1_name), "/lab13_shm_p_c1_%d", pid);
    if (n < 0) fatal_msg_exit("snprintf failed");
    n = snprintf(shm_c1_c2_name, sizeof(shm_c1_c2_name), "/lab13_shm_c1_c2_%d", pid);
    if (n < 0) fatal_msg_exit("snprintf failed");
    n = snprintf(shm_c2_p_name, sizeof(shm_c2_p_name), "/lab13_shm_c2_p_%d", pid);
    if (n < 0) fatal_msg_exit("snprintf failed");

    n = snprintf(sem_p_c1_name, sizeof(sem_p_c1_name), "/lab13_sem_p_c1_%d", pid);
    if (n < 0) fatal_msg_exit("snprintf failed");
    n = snprintf(sem_c1_c2_name, sizeof(sem_c1_c2_name), "/lab13_sem_c1_c2_%d", pid);
    if (n < 0) fatal_msg_exit("snprintf failed");
    n = snprintf(sem_c2_p_name, sizeof(sem_c2_p_name), "/lab13_sem_c2_p_%d", pid);
    if (n < 0) fatal_msg_exit("snprintf failed");

    void *shm_p_c1 = NULL, *shm_c1_c2 = NULL, *shm_c2_p = NULL;
    int fd1, fd2, fd3;

    if (create_and_map_shm(shm_p_c1_name, SHM_SIZE, &shm_p_c1, &fd1) == -1)
        fatal_errno_exit("shm_open p->c1");
    if (create_and_map_shm(shm_c1_c2_name, SHM_SIZE, &shm_c1_c2, &fd2) == -1)
        fatal_errno_exit("shm_open c1->c2");
    if (create_and_map_shm(shm_c2_p_name, SHM_SIZE, &shm_c2_p, &fd3) == -1)
        fatal_errno_exit("shm_open c2->p");

    sem_t *sem_p_c1 = sem_open(sem_p_c1_name, O_CREAT | O_EXCL, 0600, 0);
    sem_t *sem_c1_c2 = sem_open(sem_c1_c2_name, O_CREAT | O_EXCL, 0600, 0);
    sem_t *sem_c2_p = sem_open(sem_c2_p_name, O_CREAT | O_EXCL, 0600, 0);
    if (sem_p_c1 == SEM_FAILED || sem_c1_c2 == SEM_FAILED || sem_c2_p == SEM_FAILED)
        fatal_errno_exit("sem_open");

    pid_t c1 = fork();
    if (c1 == -1) fatal_errno_exit("fork c1");
    if (c1 == 0) {
        execl("./child1", "child1",
              shm_p_c1_name, shm_c1_c2_name,
              sem_p_c1_name, sem_c1_c2_name,
              (char*)NULL);
        char msg[256];
        int ln = snprintf(msg, sizeof(msg), "execl child1 failed: %s\n", strerror(errno));
        if (ln > 0) write_all(STDERR_FILENO, msg, (size_t)ln);
        _exit(127);
    }

    pid_t c2 = fork();
    if (c2 == -1) fatal_errno_exit("fork c2");
    if (c2 == 0) {
        execl("./child2", "child2",
              shm_c1_c2_name, shm_c2_p_name,
              sem_c1_c2_name, sem_c2_p_name,
              (char*)NULL);
        char msg[256];
        int ln = snprintf(msg, sizeof(msg), "execl child2 failed: %s\n", strerror(errno));
        if (ln > 0) write_all(STDERR_FILENO, msg, (size_t)ln);
        _exit(127);
    }

    char *buf = malloc(LINE_BUF);
    if (!buf) fatal_msg_exit("malloc failed");

    const char *prompt = "Введите строки. Пустая строка (просто Enter) завершает.\n";
    write_all(STDOUT_FILENO, prompt, strlen(prompt));

    while (1) {
        ssize_t len = read_line(STDIN_FILENO, buf, LINE_BUF);
        if (len == -1) {
            free(buf);
            fatal_errno_exit("read");
        }
        if (len == 0) {
            uint32_t msg_len = 0;
            memcpy(shm_p_c1, &msg_len, sizeof(msg_len));
            if (sem_post(sem_p_c1) == -1) fatal_errno_exit("sem_post p->c1");
            break;
        }

        if ((uint32_t)len + sizeof(uint32_t) > SHM_SIZE) {
            char emsg[128];
            int ln = snprintf(emsg, sizeof(emsg), "Строка слишком длинная (ьфч %d)\n", SHM_SIZE - (int)sizeof(uint32_t));
            if (ln > 0) write_all(STDERR_FILENO, emsg, (size_t)ln);
            continue;
        }

        uint32_t msg_len = (uint32_t)len;
        memcpy(shm_p_c1, &msg_len, sizeof(msg_len));
        memcpy((char*)shm_p_c1 + sizeof(msg_len), buf, msg_len);
        if (sem_post(sem_p_c1) == -1) fatal_errno_exit("sem_post p->c1");

        if (sem_wait(sem_c2_p) == -1) fatal_errno_exit("sem_wait c2->p");
        uint32_t rlen;
        memcpy(&rlen, shm_c2_p, sizeof(rlen));
        if (rlen == 0) {
            break;
        }
        if (rlen + sizeof(uint32_t) > SHM_SIZE) {
            const char *msg2 = "Получено слишком много данных\n";
            write_all(STDERR_FILENO, msg2, strlen(msg2));
            continue;
        }
        char *res = malloc((size_t)rlen + 1);
        if (!res) fatal_msg_exit("malloc failed");
        memcpy(res, (char*)shm_c2_p + sizeof(rlen), rlen);
        res[rlen] = '\0';

        char outbuf[LINE_BUF + 64];
        int outn = snprintf(outbuf, sizeof(outbuf), "%s\n", res);
        if (outn > 0) write_all(STDOUT_FILENO, outbuf, (size_t)outn);

        free(res);
    }

    waitpid(c1, NULL, 0);
    waitpid(c2, NULL, 0);

    munmap(shm_p_c1, SHM_SIZE); close(fd1); shm_unlink(shm_p_c1_name);
    munmap(shm_c1_c2, SHM_SIZE); close(fd2); shm_unlink(shm_c1_c2_name);
    munmap(shm_c2_p, SHM_SIZE); close(fd3); shm_unlink(shm_c2_p_name);

    sem_close(sem_p_c1); sem_unlink(sem_p_c1_name);
    sem_close(sem_c1_c2); sem_unlink(sem_c1_c2_name);
    sem_close(sem_c2_p); sem_unlink(sem_c2_p_name);

    free(buf);
    return 0;
}
