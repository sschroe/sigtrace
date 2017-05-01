#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <signal.h>
#include <string.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/ptrace.h>
#include <getopt.h>
#include <unistd.h>
#include <stdint.h>

static uint8_t running = 1;

static void signal_handler(int signum)
{
    if (signum == SIGINT ||
        signum == SIGTERM) {

        running = 0;
    }
}

/* Returns string with the signal name. enum values are mapped here
 * rather than the plain value as the values may differ depending
 * on the platform. */
static const char * const get_signal_name_from_id(const int signal) {
    switch (signal) {
#ifdef SIGHUP
        case SIGHUP: return "SIGHUP";
#endif

#ifdef SIGINT
        case SIGINT: return "SIGINT";
#endif

#ifdef SIGQUIT
        case SIGQUIT: return "SIGQUIT";
#endif

#ifdef SIGILL
        case SIGILL: return "SIGILL";
#endif

#ifdef SIGABRT
        case SIGABRT: return "SIGABRT";
#endif

#ifdef SIGFPE
        case SIGFPE: return "SIGFPE";
#endif

#ifdef SIGKILL
        case SIGKILL: return "SIGKILL";
#endif

#ifdef SIGSEGV
        case SIGSEGV: return "SIGSEGV";
#endif

#ifdef SIGPIPE
        case SIGPIPE: return "SIGPIPE";
#endif

#ifdef SIGALRM
        case SIGALRM: return "SIGALRM";
#endif

#ifdef SIGTERM
        case SIGTERM: return "SIGTERM";
#endif

#ifdef SIGUSR1
        case SIGUSR1: return "SIGUSR1";
#endif

#ifdef SIGUSR2
        case SIGUSR2: return "SIGUSR2";
#endif

#ifdef SIGCHLD
        case SIGCHLD: return "SIGCHLD";
#endif

#ifdef SIGCONT
        case SIGCONT: return "SIGCONT";
#endif

#ifdef SIGSTOP
        case SIGSTOP: return "SIGSTOP";
#endif

#ifdef SIGTSTP
        case SIGTSTP: return "SIGTSTP";
#endif

#ifdef SIGTTIN
        case SIGTTIN: return "SIGTTIN";
#endif

#ifdef SIGTTOU
        case SIGTTOU: return "SIGTTOU";
#endif

#ifdef SIGBUS
        case SIGBUS: return "SIGBUS";
#endif

#ifdef SIGPOLL
        case SIGPOLL: return "SIGPOLL";
#endif

#ifdef SIGPROF
        case SIGPROF: return "SIGPROF";
#endif

#ifdef SIGSYS
        case SIGSYS: return "SIGSYS";
#endif

#ifdef SIGTRAP
        case SIGTRAP: return "SIGTRAP";
#endif

#ifdef SIGURG
        case SIGURG: return "SIGURG";
#endif

#ifdef SIGVTALRM
        case SIGVTALRM: return "SIGVTALRM";
#endif

#ifdef SIGXCPU
        case SIGXCPU: return "SIGXCPU";
#endif

#ifdef SIGXFSZ
        case SIGXFSZ: return "SIGXFSZ";
#endif

#ifdef SIGEMT
        case SIGEMT: return "SIGEMT";
#endif

#ifdef SIGSTKFLT
        case SIGSTKFLT: return "SIGSTKFLT";
#endif

#ifdef SIGPWR
        case SIGPWR: return "SIGPWR";
#endif

#ifdef SIGINFO
        case SIGINFO: return "SIGINFO";
#endif

#ifdef SIGLOST
        case SIGLOST: return "SIGLOST";
#endif

#ifdef SIGWINCH
        case SIGWINCH: return "SIGWINCH";
#endif
    }

    return "Unknown";
}

/* Prints information for the given process id by reading files from /proc/<pid> */
static void print_process_info(const pid_t pid) {
    printf("  %5d ", pid);

    static const int buffer_size = 100;
    char * const buffer = malloc(buffer_size);

    if (buffer == NULL) {
        return ;
    }

    snprintf(buffer, buffer_size, "/proc/%d/status", pid);

    FILE * const status = fopen(buffer, "r");

    if (status != NULL) {
        int parent = 0;
        size_t n = 0;
        char *line = NULL;
        ssize_t len;

        while ((len = getline(&line, &n, status)) > 0) {
            if (len > 6 && memcmp(line, "PPid:", 5) == 0) {
                parent = atoi(&line[6]);
            } else if (len > 6 && memcmp(line, "Name:", 5) == 0) {
                printf("%.*s", (int)strlen(&line[6]) - 1, &line[6]);
            }
        }

        free(line);
        fclose(status);

        /* Get the executable path if available */
        snprintf(buffer, buffer_size, "/proc/%d/exe", pid);

        len = readlink(buffer, buffer, buffer_size);

        if (len > 0) {
            printf(" [%.*s]", (int)len, buffer);
        }

        printf("\n");

        /* Get cmdline if available */
        snprintf(buffer, buffer_size, "/proc/%d/cmdline", pid);

        FILE * const cmdline = fopen(buffer, "r");

        if (cmdline != NULL) {
            if (fread(buffer, 1, 1, cmdline) > 0 && buffer[0] != 0) {
                printf("  %5s   %c", "", buffer[0]);

                while (fread(buffer, 1, 1, cmdline) > 0) {
                    printf("%c", buffer[0] == 0 ? ' ' : buffer[0]);
                }

                printf("\n");
            }
            fclose(cmdline);
        }

        printf("\n");

        free(buffer);

        if (parent > 0) {
            print_process_info(parent);
        }

        return;
    }

    printf("\n");

    free(buffer);
}

static void print_help() {
    printf(
        "Usage: sigtrace [options] [program] [program args]\n"
        "\n"
        "Options:\n"
        "  -h               - Displays this help\n"
        "  -v               - Show version\n"
        "  -p <pid>         - Attach to pid\n"
        "  -s <signal ids>  - Comma separated list of signals to report (default = all)\n"
        "  -b <signal ids>  - Comma separated list of signals to block\n"
        "  -q               - Disable stdout output\n"
        "  -a               - Attach to the process sending the signal. May help with fast exiting senders.\n"
        "\n"
        "Examples:\n"
        "  sigtrace -a /bin/ls -ahl\n"
        "  sigtrace -b 2,15 -p 1234\n"
    );
}

/* Converts are comma separated list of numbers to a u64 bitmask */
static uint64_t list_to_bitmask(char * const comma_sep_list) {
    uint64_t ret = 0;
    char *arg = NULL;

    for (arg = strtok(comma_sep_list, ",");
         arg != NULL;
         arg = strtok(NULL, ",")) {

        const int value = atoi(arg);

        if (value < 0 || value > sizeof(uint64_t) * 8 - 1) {
            fprintf(stderr, "Ignored value '%s'.", arg);
            continue;
        }

        ret |= 1 << value;
    }

    return ret;
}

static char signal_is_in_bitmask(const int signal, const uint64_t bitmask) {
    return signal > 0 && signal < sizeof(bitmask) * 8 - 1 && bitmask & (1 << signal);
}

int main(int argc, char *argv[], char *envp[]) {
    uint64_t show_signal_mask = ~((uint64_t)1 << SIGTRAP);
    uint64_t block_signal_mask = 0;
    int status;
    uint8_t quiet = 0;
    uint8_t attach_to_sender = 0;
    pid_t pid = 0;

    const struct option option_list[] = {
        {"help", no_argument, 0, 'h'},
        {"version", no_argument, 0, 'v'},
        {"block", required_argument, 0, 'b'},
        {"show", required_argument, 0, 's'},
        {"pid", required_argument, 0, 'p'},
        {"quiet", no_argument, 0, 'q'},
        {"attach_to_sender", no_argument, 0, 'a'},
        {0, 0, 0, 0}
    };

    int option;

    struct sigaction sa = { .sa_handler = signal_handler };

    sigaction(SIGINT, &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);

    while ((option = getopt_long(argc, argv, "+hvb:s:p:qa", &option_list[0], NULL)) > 0) {
        char stop = 0;

        /* Global options */
        switch (option) {
            case 'h':
                print_help();
                return 0;

            case 'v':
                printf("sigtrace version 0.1.0\n");
                return 0;

            case 'b':
                block_signal_mask = list_to_bitmask(optarg);
                break;

            case 's':
                show_signal_mask = list_to_bitmask(optarg);
                break;

            case 'q':
                quiet = 1;
                break;

            case 'a':
                attach_to_sender = 1;
                break;

            case 'p':
                pid = atoi(optarg);
                break;

            default:
                stop = 1;
                break;
        }

        if (stop) {
            break;
        }
    }

    block_signal_mask |= 1 << SIGTRAP; /* Don't forward SIGTRAP */

    if (pid == 0) {
        /* Try to execute the given program as child process */

        if (optind < argc) {
            if ((pid = fork()) < 0) {
                fprintf(stderr, "fork failed: %s\n", strerror(pid));
                return 1;
            }

            if (pid == 0) {
                /* Child process */
                if (ptrace (PTRACE_TRACEME, 0, NULL, NULL) < 0) {
                    fprintf(stderr, "ptrace failed: %s\n", strerror(errno));
                    return 1;
                }

                if (execve(argv[optind], &argv[optind], envp) < 0) {
                    fprintf(stderr, "execve failed: %s\n", strerror(errno));
                    return 1;
                }

                return 0;
            }
        } else {
            fprintf(stderr, "Neither a PID nor a program to execute were given.\n");
            return 1;
        }
    } else {
        if (ptrace (PTRACE_ATTACH, pid, NULL, NULL) < 0) {
            fprintf(stderr, "Attach failed: %s\n", strerror(errno));
            return 1;
        }

        waitpid(pid, &status, 0);

        printf("Attached to %d\n", pid);

        if (ptrace(PTRACE_CONT, pid, NULL, NULL) < 0) {
            fprintf(stderr, "%s\n", strerror(errno));
            return 1;
        }
    }

    while(running) {
        waitpid(pid, &status, 0);

        /* Process has stopped, grab and process the signal. */
        siginfo_t signal;

        if (ptrace(PTRACE_GETSIGINFO, pid, NULL, &signal) < 0) {
            if (errno != ESRCH) {
                fprintf(stderr, "%s\n", strerror(errno));
                return 1;
            }

            break;
        }

        if (quiet == 0 && (signal.si_pid != 0 || signal.si_uid != 0) && signal_is_in_bitmask(signal.si_signo, show_signal_mask)) {
            char attached = 0;

            /* Try to stop the signal sending process to avoid loosing information.
             * Errors are ignored as this is optional. */
            if (attach_to_sender != 0 && ptrace(PTRACE_ATTACH, signal.si_pid, NULL, NULL) == 0) {
                attached = 1;
            }

            printf("Got %s (%d) with uid %u\n",
                    get_signal_name_from_id(signal.si_signo),
                    signal.si_signo,
                    signal.si_uid);

            print_process_info(signal.si_pid);

            if (attached && waitpid(signal.si_pid, &status, 0) > 0) {
                ptrace(PTRACE_DETACH, signal.si_pid, NULL, NULL);
            }
        }

        if (ptrace(PTRACE_CONT, pid, NULL, signal_is_in_bitmask(signal.si_signo, block_signal_mask) ? NULL : (void *)(uintptr_t)signal.si_signo) < 0) {
            if (errno != ESRCH) {
                fprintf(stderr, "%s\n", strerror(errno));
                return 1;
            }

            break;
        }
    }

    ptrace(PTRACE_DETACH, pid, NULL, NULL);

    return 0;
}
