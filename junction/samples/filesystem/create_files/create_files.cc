#define _GNU_SOURCE
#include <dirent.h> /* Defines DT_* constants */
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>

#define handle_error(msg) \
  do {                    \
    perror(msg);          \
    exit(EXIT_FAILURE);   \
  } while (0)

struct linux_dirent {
  long d_ino;
  off_t d_off;
  unsigned short d_reclen;
  char d_name[];
};

#define BUF_SIZE 1024

int populate_memfs() {
  int d1 = open("/memfs/foo", O_RDWR | O_CREAT | O_DIRECTORY, S_IRWXG);
  if (d1 < 0) {
    perror("open");
    return 1;
  }

  int d2 = open("/memfs/foo/bar", O_RDWR | O_CREAT | O_DIRECTORY, S_IRWXG);
  if (d2 < 0) {
    perror("open");
    return 1;
  }

  int d3 = open("/memfs/foo/cat", O_RDWR | O_CREAT | O_DIRECTORY, S_IRWXG);
  if (d3 < 0) {
    perror("open");
    return 1;
  }

  int d4 = open("/memfs/foo/dog", O_RDWR | O_CREAT | O_DIRECTORY, S_IRWXG);
  if (d3 < 0) {
    perror("open");
    return 1;
  }

  int f1 = open("/memfs/foo/cow.txt", O_RDWR | O_CREAT, S_IRWXG);
  if (f1 < 0) {
    perror("open");
    return 1;
  }

  int fd = open("/memfs/foo/bar/test.txt", O_RDWR | O_CREAT, S_IRWXG);

  if (fd < 0) {
    perror("open");
    return 1;
  }

  if (ftruncate(fd, 128)) {
    perror("ftruncate");
    return 1;
  }

  const char txt[] = "hello, world!";
  size_t len = sizeof(txt) / sizeof(char);
  ssize_t n = write(fd, txt, len);
  if ((size_t)n != len) {
    perror("write");
    return 1;
  }

  if (close(d1)) {
    perror("close");
    return 1;
  }
  if (close(d2)) {
    perror("close");
    return 1;
  }
  if (close(d3)) {
    perror("close");
    return 1;
  }
  if (close(d4)) {
    perror("close");
    return 1;
  }
  if (close(f1)) {
    perror("close");
    return 1;
  }

  if (close(fd)) {
    perror("close");
    return 1;
  }

  fd = open("/memfs/foo/bar/test.txt", O_RDONLY);

  if (fd < 0) {
    perror("open");
    return 1;
  }

  char *content = (char *)malloc(sizeof(char) * 128);
  if (!content) {
    perror("malloc");
    return 1;
  }

  len = 5;
  n = read(fd, content, len);
  if ((size_t)n != len) {
    perror("read");
    return 1;
  }

  free(content);

  if (close(fd)) {
    perror("close");
    return 1;
  }

  return 0;
}

// Source: https://gist.github.com/mackstann/4229933
void listdir(const char *dirname) {
  int fd, nread;
  struct linux_dirent *d;
  int bpos;
  char d_type;
  char *buf = (char *)malloc(BUF_SIZE);

  fd = open(dirname, O_RDONLY | O_DIRECTORY);
  if (fd == -1) handle_error("open");

  for (;;) {
    nread = syscall(SYS_getdents, fd, buf, BUF_SIZE);
    if (nread == -1) handle_error("getdents");

    if (nread == 0) break;

    printf("--------------- nread=%d ---------------\n", nread);
    printf("i-node#  file type  d_reclen  d_off   d_name\n");
    for (bpos = 0; bpos < nread;) {
      d = (struct linux_dirent *)(buf + bpos);
      printf("%8ld  ", d->d_ino);
      d_type = *(buf + bpos + d->d_reclen - 1);
      bpos += d->d_reclen;
      if (d->d_ino && strcmp(d->d_name, ".") && strcmp(d->d_name, "..")) {
        printf("%-10s ", (d_type == DT_REG)    ? "regular"
                         : (d_type == DT_DIR)  ? "directory"
                         : (d_type == DT_FIFO) ? "FIFO"
                         : (d_type == DT_SOCK) ? "socket"
                         : (d_type == DT_LNK)  ? "symlink"
                         : (d_type == DT_BLK)  ? "block dev"
                         : (d_type == DT_CHR)  ? "char dev"
                                               : "???");
        printf("%4d %10lld  %s/%s\n", d->d_reclen, (long long)d->d_off, dirname,
               d->d_name);
        if (d_type == DT_DIR) {
          int dirname_len = strlen(dirname);
          char *subdir = (char *)calloc(1, PATH_MAX + 1);
          strcat(subdir, dirname);
          strcat(subdir + dirname_len, "/");
          strcat(subdir + dirname_len + 1, d->d_name);
          listdir(subdir);
          free(subdir);
        }
      }
    }
  }

  close(fd);
  free(buf);
}

int main(int argc, char *argv[]) {
  if (argc != 1) {
    printf("usage: ./create_files\n");
    return 1;
  }

  populate_memfs();
  listdir("/memfs");

  exit(EXIT_SUCCESS);
}
