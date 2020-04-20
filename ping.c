/*
  * Author: Rohan Kumar
  * Produced for the Cloudflare internship application for summer 2020
*/

#include <stdio.h>
#include <netdb.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include <fcntl.h>
#include <signal.h>
#include <time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <arpa/inet.h>

#define TIMEOUT 1
#define PING_PACKET_SIZE 64
#define SLEEP_RATE 1000000

int loop = 1;

struct icmphdr {
  u_int8_t type;		/* message type */
  u_int8_t code;		/* type sub-code */
  u_int16_t checksum;
  union {
    struct {
      u_int16_t	id;
      u_int16_t	sequence;
    } echo;			/* echo datagram */
    u_int32_t	gateway;	/* gateway address */
    struct {
      u_int16_t	__unused;
      u_int16_t	mtu;
    } frag;			/* path mtu discovery */
  } un;
};

struct ping_packet {
  struct icmphdr hdr;
  char message[PING_PACKET_SIZE - sizeof(struct icmphdr)];
};

u_short checksum(const u_short *addr, int len, u_short csum) {
  int nleft = len;
  const u_short *address = addr;
  u_short result;
  int sum = csum;

  while(nleft > 1) {
    sum += *address++;
    nleft -= 2;
  }

  if (nleft) {
    sum += htons(*(u_char *)address << 8);
  }

  sum = (sum >> 16) + (sum & 0xffff);
  sum += (sum >> 16);
  result = ~sum;
  return result;
}

//Method to catch user termination of program
void interrupt() {
  loop = 0;
}

//Method to perform a DNS lookup on user input
char *dns_lookup(char *address_host, struct sockaddr_in *address) {
  struct hostent *host_entity;
  char *IP = (char*) malloc(NI_MAXHOST * sizeof(char));

  if((host_entity = gethostbyname(address_host)) != NULL) {
    strcpy(IP, inet_ntoa(*(struct in_addr *)host_entity->h_addr));
    (*address).sin_family = host_entity->h_addrtype;
    (*address).sin_port = htons (0);
    (*address).sin_addr.s_addr  = *(long*)host_entity->h_addr;
    return IP;
  }

  return NULL;
}

//Method to resolve the reverse lookup of the user input
char *reverse_dns_lookup(char *ip_address) {
  struct sockaddr_in temp;
  socklen_t len;
  char buf[NI_MAXHOST], *return_buffer;
  int size = sizeof(struct sockaddr_in);

  temp.sin_family = AF_INET;
  temp.sin_addr.s_addr = inet_addr(ip_address);

  if(!getnameinfo((struct sockaddr *) &temp, size, buf, sizeof(buf), NULL, 0, NI_NAMEREQD)) {
    return_buffer = (char*)malloc((strlen(buf) +1)*sizeof(char) );
    strcpy(return_buffer, buf);
    return return_buffer;
  }
  printf("Could not resolve the reverse lookup of requested hostname");
  return NULL;
}

//Method to send a ping request for the hostname
void send_ping(int ping_sockfd, struct sockaddr_in *ping_address, char *ping_domain, char *ping_ip, char *hostname) {
  int ttl = 64, message_count = 0, flag = 1, message_received = 0, address_size, i;
  struct ping_packet packet;
  struct sockaddr_in ret_address;
  struct timespec time_start, time_end, tfs, tfe;
  long double rtt=0, total=0;
  struct timeval tv_out;
  tv_out.tv_sec = TIMEOUT;
  tv_out.tv_usec = 0;
  clock_gettime(CLOCK_MONOTONIC, &tfs);
  double packet_lossRate;

  //Setting socket for desired IP
  if(!setsockopt(ping_sockfd, IPPROTO_IP, IP_TTL, &ttl, sizeof(ttl)) != 0) {
    printf("\nSocket set!\n");
  }
  else {
    printf("\nSetting socket failed!\n");
    return;
  }

  setsockopt(ping_sockfd, SOL_SOCKET, SO_RCVTIMEO, (const char *)&tv_out, sizeof(tv_out));

  //Infinite loop of sending ICMP packet
  while(loop) {
    //Int representation of whether packet is successfully sent or not
    flag = 1;
    bzero(&packet, sizeof(packet));
    packet.hdr.type = ICMP_ECHO;
    packet.hdr.un.echo.id = getpid();

    for(i = 0; i < sizeof(packet.message) - 1; i++) {
      packet.message[i] = i + '0';
    }

    packet.message[i] = 0;
    packet.hdr.un.echo.sequence = message_count++;
    packet.hdr.checksum = checksum(&packet, sizeof(packet), 0);
    usleep(SLEEP_RATE);
    clock_gettime(CLOCK_MONOTONIC, &time_start);

    if (sendto(ping_sockfd, &packet, sizeof(packet), 0, (struct sockaddr*) ping_address, sizeof(*ping_address)) <= 0) {
        printf("\nPacket Sending Failed!\n");
        flag = 0;
    }

    address_size = sizeof(ret_address);

    if(recvfrom(ping_sockfd, &packet, sizeof(packet), 0, (struct sockaddr*)&ret_address, &address_size) <= 0 && message_count > 1) {
      printf("\nFailed to receive packet\n");
    }
    else {
      clock_gettime(CLOCK_MONOTONIC, &time_end);
      double timeElapsed = ((double)(time_end.tv_nsec -time_start.tv_nsec))/1000000.0;
      rtt = (time_end.tv_sec-time_start.tv_sec) * 1000.0+ timeElapsed;

      if(flag) {
          if(!(packet.hdr.type == 69 && packet.hdr.code == 0)) {
              printf("Error..Packet received with incorrect ICMP type\n");
          }
          else {
              printf("%d) %d bytes from %s (%s) rtt = %Lf ms.\n", message_count, PING_PACKET_SIZE, hostname, ping_ip, rtt);
              message_received++;
          }
      }
    }
  }
  clock_gettime(CLOCK_MONOTONIC, &tfe);
  double timeElapsed = ((double)(tfe.tv_nsec - tfs.tv_nsec)) / 1000000.0;
  total = (tfe.tv_sec - tfs.tv_sec) * 1000.0 + timeElapsed;
  packet_lossRate = ((message_count - message_received) / message_count) * 100.0;

  printf("\nStatistics:\n");
  printf("\n%f%% packet loss. RTT time: %Lf ms.\n\n", packet_lossRate, total);
}

int main(int argc, char *argv[]) {
  int sockfd;
  char *ip_address, *reverse_hostname;
  struct sockaddr_in address;
  int addr_size = sizeof(address);
  char buffer[NI_MAXHOST];

  if(argc == 2) {
    ip_address = dns_lookup(argv[1], &address);
    if(ip_address==NULL) {
        printf("\nDNS lookup failed!\n");
        return 0;
    }

    reverse_hostname = reverse_dns_lookup(ip_address);
    printf("\nTrying to connect to '%s' IP: %s\n", argv[1], ip_address);

    sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    if(sockfd < 0) {
        printf("\nSocket not received properly!\n");
        return 0;
    }
    else {
        printf("\nSocket received successfully!\n");
    }

    signal(SIGINT, interrupt);

    //sends a continuous ping
    send_ping(sockfd, &address, reverse_hostname, ip_address, argv[1]);
    return 0;
  }
}
