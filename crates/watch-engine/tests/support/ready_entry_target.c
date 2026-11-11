// Self-owned target: waits for the real supervisor, then requires a loopback
// proxy round trip and verifies direct access to the upstream is denied.
#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

static int connect_loopback(int port) {
    struct sockaddr_in address = {0};
    address.sin_family = AF_INET;
    address.sin_port = htons((unsigned short)port);
    address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return -1;
    struct timeval timeout = {2, 0};
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
    if (connect(fd, (struct sockaddr *)&address, sizeof(address)) == 0) return fd;
    close(fd);
    return -1;
}

static int wait_flag(const char *path) {
    for (int n = 0; n < 600; n++) {
        if (access(path, F_OK) == 0) return 1;
        usleep(10000);
    }
    return 0;
}

static int record(const char *path, const char *event) {
    FILE *file = fopen(path, "w");
    if (!file) return 0;
    int ok = fprintf(file, "%s %d\n", event, getpid()) > 0;
    return fclose(file) == 0 && ok;
}

static int run_target(int argc, char **argv) {
    if (!strcmp(FIXTURE_ROLE, "ordinary")) {
        for (;;) pause();
    }
    if (!strcmp(FIXTURE_ROLE, "helper")) {
        if (!record(FIXTURE_ROOT "/helper.ready", "READY")) return 89;
        return wait_flag(FIXTURE_ROOT "/desktop.stop") ? 0 : 104;
    }
    if (!strcmp(FIXTURE_ROLE, "desktop")) {
        pid_t child = fork();
        if (child < 0) return 88;
        if (child == 0) {
            execl(FIXTURE_HELPER, FIXTURE_HELPER, (char *)0);
            _exit(87);
        }
    }
    if (!strcmp(FIXTURE_ROLE, "cli") &&
        (argc != 2 || strcmp(argv[1], "private-argument"))) return 90;
    if (!record(FIXTURE_ROOT "/" FIXTURE_ROLE ".ready", "READY")) return 91;
    if (!wait_flag(FIXTURE_ROOT "/" FIXTURE_ROLE ".go")) return 92;
    const char *proxy = getenv("HTTP_PROXY");
    int port = 0;
    if (!proxy || sscanf(proxy, "http://127.0.0.1:%d", &port) != 1 || port <= 0) return 93;
    if (connect_loopback(FIXTURE_UPSTREAM) >= 0) return 94;
    int fd = connect_loopback(port);
    if (fd < 0) return 95;
    static const char request[] = "CONNECT fixture.invalid:443 HTTP/1.1\r\nHost: fixture.invalid:443\r\n\r\n";
    if (write(fd, request, sizeof(request) - 1) != sizeof(request) - 1) return 96;
    char response[4096] = {0};
    size_t n = 0;
    while (n < sizeof(response) - 1 && !strstr(response, "\r\n\r\n")) {
        if (read(fd, response + n, 1) != 1) return 97;
        n++;
    }
    if (strncmp(response, "HTTP/1.1 200 ", 13)) return 98;
    if (write(fd, "owned!", 6) != 6) return 99;
    for (n = 0; n < 6; n++) if (read(fd, response + n, 1) != 1) return 100;
    if (memcmp(response, "owned!", 6) != 0) return 101;
    close(fd);
    if (!record(FIXTURE_ROOT "/" FIXTURE_ROLE ".result", "TUNNEL_OK")) return 102;
    return wait_flag(FIXTURE_ROOT "/" FIXTURE_ROLE ".stop") ? 0 : 103;
}

int main(int argc, char **argv) {
    int status = run_target(argc, argv);
    if (status != 0) {
        char reason[40];
        snprintf(reason, sizeof(reason), "FAILED %d", status);
        record(FIXTURE_ROOT "/" FIXTURE_ROLE ".result", reason);
    }
    return status;
}
