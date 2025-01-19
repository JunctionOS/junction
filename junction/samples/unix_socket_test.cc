#include <errno.h>
#include <pthread.h>
#include <stddef.h>  // for offsetof()
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/uio.h>  // for readv(), writev()
#include <sys/un.h>
#include <unistd.h>

// Change these if you like
#define PATHNAME_SOCK "/tmp/test_sock"
#define ABSTRACT_NAME "abstract_test"  // final sun_path: "\0abstract_test"

// How many bytes we plan to exchange
#define PART1 "HelloPart1"
#define PART2 "AndPart2"
#define REPLY "ReplyFromServer"

// Forward declarations
static void *server_thread_func(void *arg);
static void *client_thread_func(void *arg);

// Encapsulate socket parameters
typedef struct {
  int is_abstract;      // 0 = pathname, 1 = abstract
  char sock_path[108];  // enough space for sockaddr_un.sun_path
} socket_info_t;

////////////////////////////////////////////////////////////////////////////////
// MAIN
////////////////////////////////////////////////////////////////////////////////

static void handle_error(const char *str) {
  perror(str);
  exit(-1);
}

int main(void) {
  // We’ll run two tests: one pathname, one abstract
  socket_info_t path_info, abstract_info;
  memset(&path_info, 0, sizeof(path_info));
  memset(&abstract_info, 0, sizeof(abstract_info));

  // 1) Pathname-based info
  path_info.is_abstract = 0;
  strncpy(path_info.sock_path, PATHNAME_SOCK, sizeof(path_info.sock_path) - 1);

  // 2) Abstract-based info
  abstract_info.is_abstract = 1;
  // For abstract sockets, the first byte will be '\0', then "abstract_test"
  // We'll handle the correct length inside the threads.

  // We'll do each test in sequence:
  // (A) Spawn server thread for PATHNAME, then client thread, join them.
  // (B) Spawn server thread for ABSTRACT, then client thread, join them.

  printf("===== TEST 1: PATHNAME SOCKET =====\n");
  {
    pthread_t s_thr, c_thr;
    // Create server
    pthread_create(&s_thr, NULL, server_thread_func, &path_info);
    // Give the server a tiny head start (not strictly necessary, but helpful)
    usleep(200000);

    // Create client
    pthread_create(&c_thr, NULL, client_thread_func, &path_info);

    // Join
    pthread_join(s_thr, NULL);
    pthread_join(c_thr, NULL);
  }

  printf("\n===== TEST 2: ABSTRACT SOCKET =====\n");
  {
    pthread_t s_thr, c_thr;
    pthread_create(&s_thr, NULL, server_thread_func, &abstract_info);
    usleep(200000);
    pthread_create(&c_thr, NULL, client_thread_func, &abstract_info);

    pthread_join(s_thr, NULL);
    pthread_join(c_thr, NULL);
  }

  printf("\nAll tests completed.\n");
  return 0;
}

////////////////////////////////////////////////////////////////////////////////
// SERVER THREAD
////////////////////////////////////////////////////////////////////////////////

static void *server_thread_func(void *arg) {
  socket_info_t *info = (socket_info_t *)arg;

  // 1) Create socket
  int sfd = socket(AF_UNIX, SOCK_STREAM, 0);
  if (sfd < 0) handle_error("server socket()");

  // 2) Build sockaddr_un
  struct sockaddr_un addr;
  memset(&addr, 0, sizeof(addr));
  addr.sun_family = AF_UNIX;

  socklen_t addr_len;
  if (info->is_abstract) {
    // abstract
    addr.sun_path[0] = '\0';  // leading NUL
    // copy "abstract_test" right after that
    size_t name_len = strlen(ABSTRACT_NAME);
    if (name_len > (sizeof(addr.sun_path) - 2)) {
      fprintf(stderr, "Abstract name too long!\n");
      close(sfd);
      return NULL;
    }
    memcpy(addr.sun_path + 1, ABSTRACT_NAME, name_len);

    // offset of sun_path + 1 (leading NUL) + name_len
    addr_len = offsetof(struct sockaddr_un, sun_path) + 1 + name_len;
  } else {
    // pathname
    // remove old file, just in case
    unlink(info->sock_path);

    strncpy(addr.sun_path, info->sock_path, sizeof(addr.sun_path) - 1);
    addr_len = sizeof(struct sockaddr_un);
  }

  // 3) Bind
  if (bind(sfd, (struct sockaddr *)&addr, addr_len) < 0)
    handle_error("server bind()");

  // 4) Listen
  if (listen(sfd, 5) < 0) handle_error("server listen()");

  printf("Server[%s]: listening...\n",
         info->is_abstract ? "ABSTRACT" : "PATHNAME");

  // 5) Accept client
  int cfd = accept(sfd, NULL, NULL);
  if (cfd < 0) handle_error("server accept()");

  printf("Server[%s]: client connected.\n",
         info->is_abstract ? "ABSTRACT" : "PATHNAME");

  // 6) Receive from client: demonstrate readv()
  // We expect 2 parts: PART1 and PART2
  char buf1[strlen(PART1) + 1] = {0};
  char buf2[strlen(PART2) + 1] = {0};

  struct iovec iov[2];
  iov[0].iov_base = buf1;
  iov[0].iov_len = strlen(PART1);
  iov[1].iov_base = buf2;
  iov[1].iov_len = strlen(PART2);

  ssize_t rd = readv(cfd, iov, 2);
  if (rd < 0) {
    handle_error("server readv()");
  } else {
    if (strncmp(buf1, PART1, strlen(PART1)) ||
        strncmp(buf2, PART2, strlen(PART2))) {
      printf("buffer mismatch\n");
      exit(-1);
    }
  }

  // 7) Send a reply back to client: use write()
  // We'll send a short string: REPLY
  ssize_t wr = write(cfd, REPLY, sizeof(REPLY));
  if (wr < 0) {
    perror("server write()");
  } else {
    printf("Server[%s]: wrote reply (%zd bytes)\n",
           info->is_abstract ? "ABSTRACT" : "PATHNAME", wr);
  }

  // 8) Close client
  close(cfd);

  // 9) Cleanup
  close(sfd);
  if (!info->is_abstract) {
    // remove the pathname socket file
    unlink(info->sock_path);
  }

  printf("Server[%s]: finished.\n",
         info->is_abstract ? "ABSTRACT" : "PATHNAME");
  return NULL;
}

////////////////////////////////////////////////////////////////////////////////
// CLIENT THREAD
////////////////////////////////////////////////////////////////////////////////

static void *client_thread_func(void *arg) {
  socket_info_t *info = (socket_info_t *)arg;

  // 1) Create socket
  int cfd = socket(AF_UNIX, SOCK_STREAM, 0);
  if (cfd < 0) handle_error("client socket()");

  // 2) Build sockaddr_un
  struct sockaddr_un addr;
  memset(&addr, 0, sizeof(addr));
  addr.sun_family = AF_UNIX;

  socklen_t addr_len;
  if (info->is_abstract) {
    addr.sun_path[0] = '\0';
    size_t name_len = strlen(ABSTRACT_NAME);
    memcpy(addr.sun_path + 1, ABSTRACT_NAME, name_len);
    addr_len = offsetof(struct sockaddr_un, sun_path) + 1 + name_len;
  } else {
    strncpy(addr.sun_path, info->sock_path, sizeof(addr.sun_path) - 1);
    addr_len = sizeof(struct sockaddr_un);
  }

  // 3) Connect
  if (connect(cfd, (struct sockaddr *)&addr, addr_len) < 0)
    handle_error("client connect()");
  printf("Client[%s]: connected.\n",
         info->is_abstract ? "ABSTRACT" : "PATHNAME");

  // 4) Send two parts to server using writev()
  struct iovec iov[2];
  iov[0].iov_base = (void *)PART1;
  iov[0].iov_len = strlen(PART1);  // no trailing '\0'
  iov[1].iov_base = (void *)PART2;
  iov[1].iov_len = strlen(PART2);

  ssize_t wrv = writev(cfd, iov, 2);
  if (wrv < 0) {
    handle_error("client writev()");
  } else {
    printf("Client[%s]: writev() sent %zd bytes: ['%s','%s']\n",
           info->is_abstract ? "ABSTRACT" : "PATHNAME", wrv, PART1, PART2);
  }

  // 5) Read server reply with a single read()
  char buf[128];
  memset(buf, 0, sizeof(buf));
  ssize_t rd = read(cfd, buf, sizeof(buf) - 1);
  if (rd < 0) {
    handle_error("client read()");
  } else if (rd == 0) {
    printf("Client[%s]: server closed the connection.\n",
           info->is_abstract ? "ABSTRACT" : "PATHNAME");
    exit(-1);
  } else {
    if (strncmp(buf, REPLY, strlen(REPLY))) {
      printf("reply mismatch\n");
      exit(-1);
    }
    printf("Client[%s]: read() got %zd bytes: '%s'\n",
           info->is_abstract ? "ABSTRACT" : "PATHNAME", rd, buf);
  }

  // 6) Close
  close(cfd);
  printf("Client[%s]: finished.\n",
         info->is_abstract ? "ABSTRACT" : "PATHNAME");
  return NULL;
}