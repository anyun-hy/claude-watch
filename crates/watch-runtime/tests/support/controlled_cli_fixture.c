// Owned non-AI target. Only loopback fixture ports and inherited stdio are used.
#include <arpa/inet.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

static int dial(int port) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    struct timeval timeout = {3, 0};
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
    struct sockaddr_in address = {.sin_family = AF_INET, .sin_port = htons(port)};
    inet_pton(AF_INET, "127.0.0.1", &address.sin_addr);
    if (connect(fd, (struct sockaddr *)&address, sizeof(address)) != 0) { close(fd); return -1; }
    return fd;
}
static void need(int ok, const char *reason) { if (!ok) { perror(reason); exit(70); } }
static void exact(int fd, char *bytes, int count) {
    while (count) { int n = (int)read(fd, bytes, count); need(n > 0, "complete read"); bytes += n; count -= n; }
}
#ifndef FIXTURE_VERSION
#define FIXTURE_VERSION "A"
#endif
int main(int argc, char **argv) {
    need(argc == 3, "fixture args");
    int gateway = atoi(argv[1]), upstream = atoi(argv[2]), streams[64], count = 0;
    const char *inherited = getenv("CW_FIXTURE_STREAMS");
    if (inherited && *inherited) {
        char copy[512]; snprintf(copy, sizeof(copy), "%s", inherited);
        for (char *fd = strtok(copy, ","); fd; fd = strtok(NULL, ",")) { need(count < 64, "inherited stream bound"); streams[count++] = atoi(fd); }
    }
    setvbuf(stdout, NULL, _IOLBF, 0);
    printf("READY %d %s\n", getpid(), FIXTURE_VERSION);
    char line[256];
    while (fgets(line, sizeof(line), stdin)) {
        if (!strncmp(line, "PING ", 5)) { printf("PONG %d %s", getpid(), line + 5); continue; }
        if (!strncmp(line, "QUIT", 4)) { for (int i = 0; i < count; ++i) close(streams[i]); return 0; }
        if (!strncmp(line, "EXEC ", 5)) {
            char descriptors[512] = {0};
            for (int i = 0; i < count; ++i) { char fd[16]; snprintf(fd, sizeof(fd), "%s%d", i ? "," : "", streams[i]); strncat(descriptors, fd, sizeof(descriptors) - strlen(descriptors) - 1); }
            setenv("CW_FIXTURE_STREAMS", descriptors, 1); line[strcspn(line, "\n")] = 0;
            char *args[] = {line + 5, argv[1], argv[2], NULL}; execv(args[0], args); need(0, "fixture exec");
        }
        if (!strncmp(line, "DIRECT", 6)) { int fd = dial(upstream); need(fd < 0, "direct network must be denied"); puts("DIRECT_DENIED"); continue; }
        if (!strncmp(line, "EOF", 3)) {
            for (int i = 0; i < count; ++i) { char b; int n = (int)read(streams[i], &b, 1); need(n == 0, "real EOF required, errors/timeouts fail"); close(streams[i]); }
            printf("EOF %d\n", count); count = 0; continue;
        }
        int denied = !strncmp(line, "RECONNECT", 9);
        need(denied || !strncmp(line, "OPEN", 4), "fixture command");
        int fd = dial(gateway); need(fd >= 0, "gateway connect");
        char request[256], header[4096] = {0};
        int length = snprintf(request, sizeof(request), "CONNECT 127.0.0.1:%d HTTP/1.1\r\nHost: 127.0.0.1:%d\r\n\r\n", upstream, upstream);
        need(write(fd, request, length) == length, "connect request");
        int used = 0;
        while (used < 4095 && !strstr(header, "\r\n\r\n")) { exact(fd, header + used++, 1); header[used] = 0; }
        if (denied) { char expected[32]; snprintf(expected, sizeof(expected), "HTTP/1.1 %d", atoi(line + 9)); need(!strncmp(header, expected, 12), "reconnect must have the expected explicit rejection status"); close(fd); puts("DENIED"); continue; }
        need(!strncmp(header, "HTTP/1.1 200", 12), "forwarding success");
        need(write(fd, "probe", 5) == 5, "probe write");
        char echo[5]; exact(fd, echo, 5); need(!memcmp(echo, "probe", 5), "probe echo");
        need(count < 64, "fixture stream bound"); streams[count++] = fd; puts("OPENED");
    }
    return 0;
}
