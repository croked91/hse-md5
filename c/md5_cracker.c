#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <signal.h>
#include <openssl/evp.h>
#include <semaphore.h>
#include <fcntl.h>
#include <sys/sysinfo.h>

#define CHARSET "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
#define MAX_LENGTH 10
#define BUFFER_SIZE 32

void generate_passwords(int length, char *password, int index, int pipe_fd, sem_t *sem);
void md5_hash(const char *password, char *output);
int compare_hashes(const char *hash1, const char *hash2);
void handle_signal(int sig);
void cleanup();

sem_t *sem = NULL;
volatile sig_atomic_t found_password = 0; 
pid_t *pids;
int num_cores;
int num_processes;
clock_t start_time;

void cleanup() {
    if (sem != NULL) {
        sem_close(sem);
        sem_unlink("/password_semaphore");
    }
    free(pids);
}

void sigint_handler(int sig) {
    cleanup();
    exit(0);
}

void sigterm_handler(int sig) {
    exit(0);
}

void handle_signal(int sig) {
    found_password = 1;
    cleanup();
    exit(0);
    fflush(stdout);
}

void terminate_children() {
    for (int i = 0; i < num_cores; i++) {
        if (pids[i] > 0) {
            kill(pids[i], SIGTERM); 
        }
    }
}

int main(int argc, char *argv[]) {
    if (argc != 3) {
        printf("Usage:\n");
        printf("  %s <md5_hash> <length>\n", argv[0]);
        return 1;
    }

    char *hash = argv[1];
    if (strlen(hash) != 32) {
        printf("Invalid MD5 hash length\n");
        return 1;
    }

    int length = atoi(argv[2]);
    if (length < 1 || length > MAX_LENGTH) {
        printf("Invalid password length\n");
        return 1;
    }

    printf("Preparing...\n");

    int pipe_fd[2];
    if (pipe(pipe_fd) == -1) {
        perror("pipe");
        return 1;
    }

    sem = sem_open("/password_semaphore", O_CREAT, 0644, 1);
    if (sem == SEM_FAILED) {
        perror("sem_open");
        return 1;
    }

    signal(SIGUSR1, handle_signal);
    signal(SIGINT, sigint_handler);

    num_cores = sysconf(_SC_NPROCESSORS_ONLN);
    if (num_cores < 1) {
        printf("Failed to detect number of CPU cores\n");
        return 1;
    }

    num_processes = num_cores - 1;

    pids = malloc(num_cores * sizeof(pid_t));

    for (int i = 0; i < num_processes; i++) {
        pids[i] = fork();
        if (pids[i] == -1) {
            perror("fork");
            return 1;
        }

        if (pids[i] == 0) {
            signal(SIGTERM, sigterm_handler);
            close(pipe_fd[1]);

            char password[BUFFER_SIZE];
            ssize_t bytes_read;
            while ((bytes_read = read(pipe_fd[0], password, sizeof(password))) > 0) {
                password[bytes_read] = '\0';

                if (strlen(password) == 0) continue;

                char md5_result[BUFFER_SIZE];

                md5_hash(password, md5_result);
                printf("Trying: %s\r", password);
                fflush(stdout);

                if (compare_hashes(md5_result, hash) == 0) {
                    printf("Password found: %s\n", password);
                    kill(getppid(), SIGUSR1); 
                    close(pipe_fd[0]);
                    exit(0);
                }

                sem_post(sem);
            }

            close(pipe_fd[0]);
            exit(1);
        }
    }

    printf("Created %d processes...\n", num_processes);

    close(pipe_fd[0]);

    char password[BUFFER_SIZE] = {0};
    
    printf("It's a password generation...\n");
    generate_passwords(length, password, 0, pipe_fd[1], sem);
    printf("Password generation finished...\n");

    if (!found_password) {
        printf("Password not found. Probably you are usiing invalid charset or length.\n");
    }

    terminate_children();

    for (int i = 0; i < num_cores; i++) {
        int status;
        waitpid(pids[i], &status, 0);
    }


    cleanup();

    return 0;
}


void generate_passwords(int length, char *password, int index, int pipe_fd, sem_t *sem) {
    if (found_password) return;

    if (index == length) {
        password[length] = '\0';

        sem_wait(sem);
        write(pipe_fd, password, strlen(password) + 1);

        return;
    }

    for (int i = 0; i < strlen(CHARSET); i++) {
        if (found_password) return;

        password[index] = CHARSET[i];
        generate_passwords(length, password, index + 1, pipe_fd, sem);
        if (found_password) break;
    }
    password[index] = '\0';
}

void md5_hash(const char *password, char *output) {
    unsigned char hash[EVP_MAX_MD_SIZE];
    unsigned int length;
    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();

    EVP_DigestInit_ex(mdctx, EVP_md5(), NULL);
    EVP_DigestUpdate(mdctx, password, strlen(password));
    EVP_DigestFinal_ex(mdctx, hash, &length);
    EVP_MD_CTX_free(mdctx);

    for (unsigned int i = 0; i < length; i++) {
        sprintf(&output[i * 2], "%02x", hash[i]);
    }
    output[length * 2] = '\0';
}



int compare_hashes(const char *hash1, const char *hash2) {
    return strncmp(hash1, hash2, 32);
}