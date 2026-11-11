// Own fixture only. The child runs a syscall-only control loop after fork.
#include <node_api.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

static void reply(int fd, const char *bytes, size_t len) {
    if (write(fd, bytes, len) != (ssize_t)len) _exit(74);
}
static int connection(int gateway, const char *request, size_t size, char *answer) {
    struct sockaddr_in address = {.sin_family=AF_INET, .sin_port=htons(gateway), .sin_addr={htonl(INADDR_LOOPBACK)}};
    int socket_fd = socket(AF_INET, SOCK_STREAM, 0);
    struct timeval timeout = {3, 0};
    if (socket_fd < 0 || setsockopt(socket_fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout))
        || connect(socket_fd, (struct sockaddr *)&address, sizeof(address))
        || write(socket_fd, request, size) != (ssize_t)size) _exit(75);
    int pos=0, tail=0;
    const char end[]="\r\n\r\n";
    char ch;
    while (read(socket_fd, &ch, 1) == 1 && pos < 4096) {
        if (pos < 12) answer[pos] = ch;
        ++pos;
        if (ch == end[tail]) { if (++tail == 4) return socket_fd; }
        else { tail = ch == '\r' ? 1 : 0; }
    }
    _exit(76);
}
static void child_loop(int in, int out, int gateway, const char *request, size_t size) {
    int streams[8], count=0;
    char command;
    while (read(in, &command, 1) == 1) {
        if (command == 'Q') _exit(0);
        if (command == 'P') { reply(out, "PONG\n", 5); continue; }
        if (command == 'E') {
            char unused;
            for (int i=0; i<count; ++i) {
                if (read(streams[i], &unused, 1) != 0) _exit(77);
                close(streams[i]);
            }
            if (count != 1) _exit(78);
            count=0; reply(out,"EOF 1\n",6); continue;
        }
        char answer[12];
        int fd=connection(gateway,request,size,answer);
        if (command == 'O' && count < 8 && !memcmp(answer,"HTTP/1.1 200",12)) {
            char echo[4];
            reply(fd, "fork", 4);
            for (int i=0; i<4; ++i) if (read(fd, &echo[i], 1) != 1) _exit(80);
            if (memcmp(echo,"fork",4)) _exit(81);
            streams[count++]=fd; reply(out,"OPENED\n",7);
        } else if (command == 'D' && !memcmp(answer,"HTTP/1.1 403",12)) {
            close(fd); reply(out,"DENIED\n",7);
        } else _exit(79);
    }
    _exit(0);
}
static napi_value fork_child(napi_env env, napi_callback_info info) {
    napi_value args[4], value;
    size_t n=4;
    char input[1024], output[1024], request[128];
    int32_t gateway, upstream;
    if (napi_get_cb_info(env,info,&n,args,NULL,NULL)!=napi_ok || n!=4
        || napi_get_value_string_utf8(env,args[0],input,sizeof(input),NULL)!=napi_ok
        || napi_get_value_string_utf8(env,args[1],output,sizeof(output),NULL)!=napi_ok
        || napi_get_value_int32(env,args[2],&gateway)!=napi_ok
        || napi_get_value_int32(env,args[3],&upstream)!=napi_ok) {
        napi_throw_error(env,NULL,"fixture arguments"); return NULL;
    }
    int len=snprintf(request,sizeof(request),"CONNECT 127.0.0.1:%d HTTP/1.1\r\nHost: 127.0.0.1:%d\r\n\r\n",upstream,upstream);
    int in=open(input,O_RDONLY|O_CLOEXEC), out=open(output,O_WRONLY|O_CLOEXEC);
    pid_t pid=(in<0 || out<0 || len<0 || (size_t)len>=sizeof(request)) ? -1 : fork();
    if (pid==0) child_loop(in,out,gateway,request,(size_t)len);
    if (in>=0) close(in);
    if (out>=0) close(out);
    if (pid<0) { napi_throw_error(env,NULL,"fixture fork failed"); return NULL; }
    napi_create_int32(env,pid,&value);
    return value;
}
NAPI_MODULE_INIT() {
    napi_value fun;
    napi_create_function(env,"forkChild",NAPI_AUTO_LENGTH,fork_child,NULL,&fun);
    napi_set_named_property(env,exports,"forkChild",fun);
    return exports;
}
