/* $Id$ */

/***
  This file is part of nss-mdns.
 
  nss-mdns is free software; you can redistribute it and/or modify it
  under the terms of the GNU Lesser General Public License as
  published by the Free Software Foundation; either version 2 of the
  License, or (at your option) any later version.
 
  nss-mdns is distributed in the hope that it will be useful, but
  WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
  General Public License for more details.
 
  You should have received a copy of the GNU Lesser General Public
  License along with nss-mdns; if not, write to the Free Software
  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307
  USA.
***/

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <inttypes.h>
#include <errno.h>
#include <string.h>
#include <stdio.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <fcntl.h>
#include <assert.h>
#include <sys/time.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <stdlib.h>
#include <ifaddrs.h>

#include "dns.h"
#include "util.h"
#include "query.h"

static const usec_t retry_ms[] = { 500000, 1000000, 0 };

static uint16_t get_random_id(void) {
    uint16_t id = 0;
    int ok = 0, fd;
    
    if ((fd = open("/dev/urandom", O_RDONLY)) >= 0) {
        ok = read(fd, &id, sizeof(id)) == 2;
        close(fd);
    }

    if (!ok)
        ok = random() & 0xFFFF;

    return id;
}

#ifndef NSS_IPV6_ONLY
static void mdns_mcast_group(struct sockaddr_in *ret_sa) {
    assert(ret_sa);

    memset(ret_sa, 0, sizeof(struct sockaddr_in));
    
    ret_sa->sin_family = AF_INET;
    ret_sa->sin_port = htons(5353);
#ifdef EXTENDED_MDNS
#error IANA has not assigned an IPv4 address for Extended MDNS!
#else
    ret_sa->sin_addr.s_addr = inet_addr("224.0.0.251");
#endif
}

int mdns_open_socket(void) {
    struct sockaddr_in sa;
    int fd = -1, ttl, yes;

    if ((fd = socket(AF_INET, SOCK_DGRAM, 0)) < 0)
        goto fail;

    ttl = 255;
    if (setsockopt(fd, IPPROTO_IP, IP_MULTICAST_TTL, &ttl, sizeof(ttl)) < 0)
        goto fail;

    sa.sin_family = AF_INET;
    sa.sin_port = 0;
    sa.sin_addr.s_addr = INADDR_ANY;
    
    if (bind(fd, (struct sockaddr*) &sa, sizeof(sa)) < 0)
        goto fail;
    
#ifdef IP_PKTINFO
    yes = 1;
    if (setsockopt(fd, IPPROTO_IP, IP_PKTINFO, &yes, sizeof(yes)) < 0)
        goto fail;
#else
    
#ifdef IP_RECVINTERFACE
    yes = 1;
    if (setsockopt (fd, IPPROTO_IP, IP_RECVINTERFACE, &yes, sizeof(yes)) < 0)
      goto fail;
#elif defined(IP_RECVIF)
    yes = 1;
    if (setsockopt (fd, IPPROTO_IP, IP_RECVIF, &yes, sizeof(yes)) < 0)
        goto fail;
#endif
    
#ifdef IP_RECVDSTADDR
    yes = 1;
    if (setsockopt (fd, IPPROTO_IP, IP_RECVDSTADDR, &yes, sizeof(yes)) < 0)
        goto fail;
#endif
    
#endif /* IP_PKTINFO */
    
#ifdef IP_RECVTTL
    yes = 1;
    if (setsockopt(fd, IPPROTO_IP, IP_RECVTTL, &yes, sizeof(yes)) < 0)
        goto fail;
#endif

    if (set_cloexec(fd) < 0)
        goto fail;
    
    if (set_nonblock(fd) < 0)
        goto fail;

    return fd;

fail:
    if (fd >= 0)
        close(fd);

    return -1;
}

static int send_dns_packet(int fd, struct dns_packet *p) {
    struct sockaddr_in sa;
    struct msghdr msg;
    struct iovec io;
#ifdef IP_PKTINFO
    struct cmsghdr *cmsg;
    uint8_t cmsg_data[CMSG_SPACE(sizeof(struct in_pktinfo))];
    struct in_pktinfo *pkti;
#elif defined(IP_SENDSRCADDR)
    struct cmsghdr *cmsg;
    uint8_t cmsg_data[CMSG_SPACE(sizeof(struct in_addr))];
    struct in_addr *addr;
#endif
    int i, n;
    struct ifreq ifreq[32];
    struct ifconf ifconf;
    int n_sent = 0;
    int last_index = -1;

    assert(fd >= 0 && p);
    assert(dns_packet_check_valid(p) >= 0);

    mdns_mcast_group(&sa);

    memset(&io, 0, sizeof(io));
    io.iov_base = p->data;
    io.iov_len = p->size;

    memset(&msg, 0, sizeof(msg));
    msg.msg_name = &sa;
    msg.msg_namelen = sizeof(sa);
    msg.msg_iov = &io;
    msg.msg_iovlen = 1;
    msg.msg_flags = 0;

#ifdef IP_PKTINFO
    memset(cmsg_data, 0, sizeof(cmsg_data));
    msg.msg_control = cmsg_data;
    msg.msg_controllen = sizeof(cmsg_data);
	
    cmsg = CMSG_FIRSTHDR(&msg);
    cmsg->cmsg_len = CMSG_LEN(sizeof(struct in_pktinfo));
    cmsg->cmsg_level = IPPROTO_IP;
    cmsg->cmsg_type = IP_PKTINFO;

    pkti = (struct in_pktinfo*) CMSG_DATA(cmsg);

    msg.msg_controllen = cmsg->cmsg_len;
#elif defined(IP_SENDSRCADDR)
    memset(cmsg_data, 0, sizeof(cmsg_data));
    msg.msg_control = cmsg_data;
    msg.msg_controllen = sizeof(cmsg_data);
        
    cmsg = CMSG_FIRSTHDR(&msg);
    cmsg->cmsg_len = CMSG_LEN(sizeof(struct in_addr));
    cmsg->cmsg_level = IPPROTO_IP;
    cmsg->cmsg_type = IP_SENDSRCADDR;
	
    addr = (struct in_addr *)CMSG_DATA(cmsg);

    msg.msg_controllen = cmsg->cmsg_len;
#elif defined(__GNUC__)
#warning "FIXME: We need some code to set the outgoing interface/local address here if IP_PKTINFO/IP_SENDSRCADDR is not available"
#endif
   
    ifconf.ifc_req = ifreq;
    ifconf.ifc_len = sizeof(ifreq);
    
    if (ioctl(fd, SIOCGIFCONF, &ifconf) < 0)
        return -1;

    for (i = 0, n = ifconf.ifc_len/sizeof(struct ifreq); i < n; i++) {
        struct sockaddr_in *ifsa;
        u_int32_t s_addr;

        /* Check if this is the loopback device or any other invalid interface */
        ifsa = (struct sockaddr_in*) &ifreq[i].ifr_addr;
        s_addr = htonl(ifsa->sin_addr.s_addr);
        if (ifsa->sin_family != AF_INET ||
            s_addr == INADDR_LOOPBACK ||
            s_addr == INADDR_ANY ||
            s_addr == INADDR_BROADCAST)
            continue;

        if (ioctl(fd, SIOCGIFFLAGS, &ifreq[i]) < 0) 
            continue;  /* Since SIOCGIFCONF and this call is not
                        * issued in a transaction, we ignore errors
                        * here, since the interface may have vanished
                        * since that call */

        /* Check whether this network interface supports multicasts and is up and running */
        if (!((ifreq[i].ifr_flags & IFF_MULTICAST) ||
                (ifreq[i].ifr_flags & IFF_BROADCAST)) ||
            !(ifreq[i].ifr_flags & IFF_UP) ||
            !(ifreq[i].ifr_flags & IFF_RUNNING))
            continue;

        if (ioctl(fd, SIOCGIFINDEX, &ifreq[i]) < 0) 
            continue; /* See above why we ignore this error */

#ifdef IP_PKTINFO
        /* Only send the the packet once per interface. We assume that
         * multiple addresses assigned to the same interface follow
         * immediately one after the other.*/
        if (last_index == ifreq[i].ifr_ifindex)
            continue;

        last_index = pkti->ipi_ifindex = ifreq[i].ifr_ifindex;
#elif defined(IP_SENDSRCADDR)
	addr->s_addr = ifsa->sin_addr.s_addr;
#elif defined(__GNUC__)
#warning "FIXME: We need some code to set the outgoing interface/local address here if IP_PKTINFO/IP_SENDSRCADDR is not available"
#endif
        
        for (;;) {
            
            if (sendmsg(fd, &msg, MSG_DONTROUTE) >= 0)
                break;

            if (errno != EAGAIN)
                return -1;
            
            if (wait_for_write(fd, NULL) < 0)
                return -1;
        }

        n_sent++;
    }

    return n_sent;
}
#endif

#ifndef NSS_IPV4_ONLY
static void mdns_mcast_group6(struct sockaddr_in6 *ret_sa) {
    assert(ret_sa);

    memset(ret_sa, 0, sizeof(struct sockaddr_in6));
    
    ret_sa->sin6_family = AF_INET6;
    ret_sa->sin6_port = htons(5353);
#ifdef EXTENDED_MDNS
    assert(inet_pton(AF_INET6, "ff05::fb", &ret_sa->sin6_addr) == 1);
#else
    assert(inet_pton(AF_INET6, "ff02::fb", &ret_sa->sin6_addr) == 1);
#endif
}

int mdns_open_socket6(void) {
    struct ipv6_mreq mreq;
    struct sockaddr_in6 sa;
    int fd = -1, ttl, yes;

    if ((fd = socket(AF_INET6, SOCK_DGRAM, 0)) < 0)
        goto fail;
    ttl = 255;
    if (setsockopt(fd, IPPROTO_IPV6, IPV6_MULTICAST_HOPS, &ttl, sizeof(ttl)) < 0)
        goto fail;

    yes = 1;
    if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes)) < 0) {
        fprintf(stderr, "SO_REUSEADDR failed: %s\n", strerror(errno));
        goto fail;
    }

    sa.sin6_family = AF_INET6;
    sa.sin6_addr = in6addr_any;
    sa.sin6_port = 0;
    
    if (bind(fd, (struct sockaddr*) &sa, sizeof(sa)) < 0)
        goto fail;

    mdns_mcast_group6(&sa);

    memset(&mreq, 0, sizeof(mreq));
    mreq.ipv6mr_multiaddr = sa.sin6_addr;

    if (setsockopt(fd, IPPROTO_IPV6, IPV6_ADD_MEMBERSHIP, &mreq, sizeof(mreq)) < 0) {
        fprintf(stderr, "IPV6_ADD_MEMBERSHIP failed: %s\n", strerror(errno));
        goto fail;
    }
    
#ifdef IPV6_PKTINFO
    yes = 1;
    if (setsockopt(fd, IPPROTO_IPV6, IPV6_RECVPKTINFO, &yes, sizeof(yes)) < 0)
        goto fail;
#else
    
#ifdef IPV6_RECVINTERFACE
    yes = 1;
    if (setsockopt (fd, IPPROTO_IPV6, IPV6_RECVINTERFACE, &yes, sizeof(yes)) < 0)
      goto fail;
#elif defined(IPV6_RECVIF)
    yes = 1;
    if (setsockopt (fd, IPPROTO_IPV6, IPV6_RECVIF, &yes, sizeof(yes)) < 0)
        goto fail;
#endif
    
#ifdef IPV6_RECVDSTADDR
    yes = 1;
    if (setsockopt (fd, IPPROTO_IPV6, IPV6_RECVDSTADDR, &yes, sizeof(yes)) < 0)
        goto fail;
#endif
    
#endif /* IPV6_PKTINFO */
    
#ifdef IPV6_RECVHOPLIMIT
    yes = 1;
    if (setsockopt(fd, IPPROTO_IPV6, IPV6_RECVHOPLIMIT, &yes, sizeof(yes)) < 0)
        goto fail;
#endif

    if (set_cloexec(fd) < 0)
        goto fail;
    
    if (set_nonblock(fd) < 0)
        goto fail;

    return fd;

fail:
    if (fd >= 0)
        close(fd);

    return -1;
}

static int send_dns_packet6(int fd, struct dns_packet *p) {
    struct sockaddr_in6 sa;
    struct msghdr msg;
    struct iovec io;
#ifdef IPV6_PKTINFO
    struct cmsghdr *cmsg;
    uint8_t cmsg_data[CMSG_SPACE(sizeof(struct in6_pktinfo))];
    struct in6_pktinfo *pkti;
#endif
    struct ifaddrs *ifaddr, *ifa;
    int n_sent = 0;
    int last_index = -1;

    assert(fd >= 0 && p);
    assert(dns_packet_check_valid(p) >= 0);

    mdns_mcast_group6(&sa);

    memset(&io, 0, sizeof(io));
    io.iov_base = p->data;
    io.iov_len = p->size;

    memset(&msg, 0, sizeof(msg));
    msg.msg_name = &sa;
    msg.msg_namelen = sizeof(sa);
    msg.msg_iov = &io;
    msg.msg_iovlen = 1;
    msg.msg_flags = 0;

#ifdef IPV6_PKTINFO
    memset(cmsg_data, 0, sizeof(cmsg_data));
    msg.msg_control = cmsg_data;
    msg.msg_controllen = sizeof(cmsg_data);

    cmsg = CMSG_FIRSTHDR(&msg);
    cmsg->cmsg_len = CMSG_LEN(sizeof(struct in6_pktinfo));
    cmsg->cmsg_level = IPPROTO_IPV6;
    cmsg->cmsg_type = IPV6_PKTINFO;

    pkti = (struct in6_pktinfo*) CMSG_DATA(cmsg);

    msg.msg_controllen = cmsg->cmsg_len;
#elif defined(__GNUC__)
#warning "FIXME: We need some code to set the outgoing interface/local address here if IPV6_PKTINFO is not available"
#endif

    if (getifaddrs(&ifaddr) == -1) {
        return -1;
    }

    for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
        struct sockaddr_in6 *ifsa6;
        int ifindex;

        /* Check if this is the loopback device or any other invalid interface */
        ifsa6 = (struct sockaddr_in6*) ifa->ifa_addr;
        if (ifsa6 == NULL ||
            ifsa6->sin6_family != AF_INET6 ||
            memcmp(&ifsa6->sin6_addr, &in6addr_loopback, sizeof(in6addr_loopback)) == 0 ||
            memcmp(&ifsa6->sin6_addr, &in6addr_loopback, sizeof(in6addr_any)) == 0)
            continue;

        /* Check whether this network interface supports multicasts and is up and running */
        if (!((ifa->ifa_flags & IFF_MULTICAST) ||
                (ifa->ifa_flags & IFF_BROADCAST)) ||
            !(ifa->ifa_flags & IFF_UP) ||
            !(ifa->ifa_flags & IFF_RUNNING))
            continue;

        ifindex = if_nametoindex(ifa->ifa_name);
        if (ifindex == 0)
            continue;

        /* Only send the the packet once per interface. We assume that
         * multiple addresses assigned to the same interface follow
         * immediately one after the other.*/
        if (last_index == ifindex)
            continue;

        last_index = ifindex;

#ifdef IP_PKTINFO
        pkti->ipi6_ifindex = ifindex;
#endif

        for (;;) {
            
            if (sendmsg(fd, &msg, MSG_DONTROUTE) >= 0)
                break;

            if (errno != EAGAIN) {
                freeifaddrs(ifaddr);
                return -1;
            }
            
            if (wait_for_write(fd, NULL) < 0) {
                freeifaddrs(ifaddr);
                return -1;
            }
        }

        n_sent++;
    }

    freeifaddrs(ifaddr);

    return n_sent;
}
#endif

static int recv_dns_packet(int *fd, int fdcount, struct dns_packet **ret_packet, uint8_t *ret_ttl, uint32_t *ret_ifindex, struct timeval *end) {
    struct dns_packet *p= NULL;
    struct msghdr msg;
    struct iovec io;
    int ret = -1;
    uint8_t aux[64];
    assert(fd && fdcount >= 1 && *fd >= 0);

    if (!(p = dns_packet_new()))
        return -1; /* OOM */

    io.iov_base = p->data;
    io.iov_len = sizeof(p->data);
    
    memset(&msg, 0, sizeof(msg));
    msg.msg_name = NULL;
    msg.msg_namelen = 0;
    msg.msg_iov = &io;
    msg.msg_iovlen = 1;
    msg.msg_control = aux;
    msg.msg_controllen = sizeof(aux);
    msg.msg_flags = 0;
    
    for (;;) {
        ssize_t l;
        int r;
        int i;
        
        for (i = 0; i < fdcount; i ++)
        if ((l = recvmsg(fd[i], &msg, 0)) >= 0) {
            struct cmsghdr *cmsg;
            *ret_ttl = 0;
            *ret_ifindex = 0;
            
            for (cmsg = CMSG_FIRSTHDR(&msg); cmsg != NULL; cmsg = CMSG_NXTHDR(&msg,cmsg)) {
                if (cmsg->cmsg_level == IPPROTO_IPV6 && cmsg->cmsg_type == IPV6_HOPLIMIT)
		{
                    *ret_ttl = (uint8_t) (*(uint32_t*) CMSG_DATA(cmsg));
                }
                else if (cmsg->cmsg_level == IPPROTO_IPV6 && cmsg->cmsg_type == IPV6_PKTINFO)
		{
                    struct in6_pktinfo *pkti = ((struct in6_pktinfo *) CMSG_DATA(cmsg));
                    *ret_ifindex = pkti->ipi6_ifindex;
                }
#ifdef SOL_IP
                else if (cmsg->cmsg_level == SOL_IP && cmsg->cmsg_type == IP_TTL)
#else
                else if (cmsg->cmsg_level == IPPROTO_IP && cmsg->cmsg_type == IP_TTL)
#endif
		{
                    *ret_ttl = (uint8_t) (*(uint32_t*) CMSG_DATA(cmsg));
                }
#ifdef SOL_IP
                else if (cmsg->cmsg_level == SOL_IP && cmsg->cmsg_type == IP_PKTINFO)
#else
                else if (cmsg->cmsg_level == IPPROTO_IP && cmsg->cmsg_type == IP_PKTINFO)
#endif
		{
                    struct in_pktinfo *pkti = ((struct in_pktinfo *) CMSG_DATA(cmsg));
                    *ret_ifindex = pkti->ipi_ifindex;
                }
            }
                     
            p->size = (size_t) l;

            *ret_packet = p;
            return 0;
        }

        if (errno != EAGAIN)
            goto fail;
        
        if ((r = wait_for_read(fd, fdcount, end)) < 0)
            goto fail;
        else if (r > 0) { /* timeout */
            ret = 1;
            goto fail;
        }
    }

fail:
    if (p)
        dns_packet_free(p);

    return ret;
}

static int send_name_query(int fd, int fdv6, const char *name, uint16_t id, int query_ipv4, int query_ipv6) {
    int ret = -1, ret1 = -1, ret2 = -1;
    struct dns_packet *p = NULL;
    uint8_t *prev_name = NULL;
    int qdcount = 0;

    assert((fd >= 0 || fdv6 >= 0) && name && (query_ipv4 || query_ipv6));

    if (!(p = dns_packet_new()))
        goto finish; /* OOM */

    dns_packet_set_field(p, DNS_FIELD_ID, id);
    dns_packet_set_field(p, DNS_FIELD_FLAGS, DNS_FLAGS(0, 0, 0, 0, 0, 0, 0, 0, 0, 0));

#ifndef NSS_IP6_ONLY
    if (query_ipv4) {
        if (!(prev_name = dns_packet_append_name(p, name)))
            goto finish; /* Bad name */

        dns_packet_append_uint16(p, DNS_TYPE_A);
        dns_packet_append_uint16(p, DNS_CLASS_IN);
        qdcount++;
    }
#endif
    
#ifndef NSS_IP4_ONLY
    if (query_ipv6) {
        if (!dns_packet_append_name_compressed(p, name, prev_name))
            goto finish; /* Bad name */
        
        dns_packet_append_uint16(p, DNS_TYPE_AAAA);
        dns_packet_append_uint16(p, DNS_CLASS_IN);
        qdcount++;
    }
#endif
    
    dns_packet_set_field(p, DNS_FIELD_QDCOUNT, qdcount);
    
#ifndef NSS_IPV4_ONLY
    if (fdv6 > 0)
        ret1 = send_dns_packet6(fdv6, p);
#endif
#ifndef NSS_IPV6_ONLY
    if (fd > 0)
        ret2 = send_dns_packet(fd, p);
#endif
    
finish:
    if (p)
        dns_packet_free(p);

    if (ret1 == -1 && ret2 == -1)
        ret = -1;
    else {
        if (ret1 == -1)
            ret1 = 0;
        if (ret2 == -1)
            ret2 = 0;
        ret = ret1 + ret2;
    }

    return ret;
}

static int domain_cmp(const char *a, const char *b) {
    size_t al, bl;

    al = strlen(a);
    bl = strlen(b);

    if (al > 0 && a[al-1] == '.')
        al --;

    if (bl > 0 && b[bl-1] == '.')
        bl --;

    if (al != bl)
        return al > bl ? 1 : (al < bl ? -1 : 0);

    return strncasecmp(a, b, al);
}

static int skip_questions(struct dns_packet *p) {
    unsigned i;
    assert(p);

    for (i = dns_packet_get_field(p, DNS_FIELD_QDCOUNT); i > 0; i--) {
        char pname[256];
        uint16_t type, class;
        
        if (dns_packet_consume_name(p, pname, sizeof(pname)) < 0 ||
            dns_packet_consume_uint16(p, &type) < 0 ||
            dns_packet_consume_uint16(p, &class) < 0)
            return -1;
    }

    return 0;
}

static int process_name_response(int fd, int fdv6, const char *name, usec_t timeout, uint16_t id, void (*ipv4_func)(const ipv4_address_t *ipv4, void *userdata), void (*ipv6_func)(const ipv6_address_t *ipv6, const uint32_t scopeid, void *userdata), void *userdata) {
    struct dns_packet *p = NULL;
    int done = 0;
    struct timeval end;
    
    assert((fd >= 0 || fdv6 >= 0) && name && (ipv4_func || ipv6_func));

    gettimeofday(&end, NULL);
    timeval_add(&end, timeout);

    while (!done) {
        uint8_t ttl;
        uint32_t ifindex;
        int r;
        int fds[2];
        int fdcount = 0;

        if (fdv6 >= 0)
            fds[fdcount++] = fdv6;
        if (fd >= 0)
            fds[fdcount++] = fd;

        if ((r = recv_dns_packet(fds, fdcount, &p, &ttl, &ifindex, &end)) < 0)
            return -1;
        else if (r > 0) /* timeout */
            return 1;

        /* Ignore packets with RFC != 255 */
        if (/* ttl == 255 && */  
            dns_packet_check_valid_response(p) >= 0 &&
            dns_packet_get_field(p, DNS_FIELD_ID) == id) {

            unsigned i;

            if (skip_questions(p) >= 0)
                
                for (i = dns_packet_get_field(p, DNS_FIELD_ANCOUNT); i > 0; i--) {
                    char pname[256];
                    uint16_t type, class;
                    uint32_t rr_ttl;
                    uint16_t rdlength;
                    
                    if (dns_packet_consume_name(p, pname, sizeof(pname)) < 0 ||
                        dns_packet_consume_uint16(p, &type) < 0 ||
                        dns_packet_consume_uint16(p, &class) < 0 ||
                        dns_packet_consume_uint32(p, &rr_ttl) < 0 ||
                        dns_packet_consume_uint16(p, &rdlength) < 0) {
                        break;
                    }
                    
                    /* Remove mDNS cache flush bit */
                    class &= ~0x8000;
                    
#ifndef NSS_IPV6_ONLY
                    if (ipv4_func &&
                        type == DNS_TYPE_A &&
                        class == DNS_CLASS_IN &&
                        !domain_cmp(name, pname) &&
                        rdlength == sizeof(ipv4_address_t)) {
                        
                        ipv4_address_t ipv4;
                        
                        if (dns_packet_consume_bytes(p, &ipv4, sizeof(ipv4)) < 0)
                            break;
                        
                        ipv4_func(&ipv4, userdata);
                        done = 1;
                        
                    }
#endif
#if ! defined(NSS_IPV6_ONLY) && ! defined(NSS_IPV4_ONLY)
/*                     else  */
#endif                        
#ifndef NSS_IPV4_ONLY
                    if (ipv6_func &&
                        type == DNS_TYPE_AAAA &&
                        class == DNS_CLASS_IN &&
                        !domain_cmp(name, pname) &&
                        rdlength == sizeof(ipv6_address_t)) {
                        
                        ipv6_address_t ipv6;
                        uint32_t scopeid = 0;
                        
                        if (dns_packet_consume_bytes(p, &ipv6, sizeof(ipv6_address_t)) < 0)
                            break;

                        /* Link Local addresses require scopeid */
                        if (ipv6.address[0] == 0xFE && ipv6.address[1] == 0x80)
                            scopeid = ifindex;
                        
                        ipv6_func(&ipv6, scopeid, userdata);
                        done = 1;
                    }
#endif
                    else {
                        
                        /* Step over */
                        
                        if (dns_packet_consume_seek(p, rdlength) < 0)
                            break;
                    }
                }
        }

        
        if (p)
            dns_packet_free(p);

    }
    
    return 0;
}

int mdns_query_name(int fd, int fdv6, const char *name, void (*ipv4_func)(const ipv4_address_t *ipv4, void *userdata), void (*ipv6_func)(const ipv6_address_t *ipv6, const uint32_t scopeid, void *userdata), void *userdata) {
    const usec_t *timeout = retry_ms;
    uint16_t id;
    
    assert((fd >= 0 || fdv6 >= 0) && name && (ipv4_func || ipv6_func));

    id = get_random_id();

    while (*timeout > 0) {
        int n;
        
        if (send_name_query(fd, fdv6, name, id, !!ipv4_func, !!ipv6_func) < 0)
            return -1;

        if ((n = process_name_response(fd, fdv6, name, *timeout, id, ipv4_func, ipv6_func, userdata)) < 0)
            return -1;

        if (n == 0)
            return 0;

        /* Timeout */

        timeout++;
    }

    return -1;
}

static int send_reverse_query(int fd, int af, const char *name, uint16_t id) {
    int ret = -1;
    struct dns_packet *p = NULL;

    assert(fd >= 0 && name);

    if (!(p = dns_packet_new()))
        goto finish;

    dns_packet_set_field(p, DNS_FIELD_ID, id);
    dns_packet_set_field(p, DNS_FIELD_FLAGS, DNS_FLAGS(0, 0, 0, 0, 0, 0, 0, 0, 0, 0));

    if (!dns_packet_append_name(p, name))
        goto finish;

    dns_packet_append_uint16(p, DNS_TYPE_PTR);
    dns_packet_append_uint16(p, DNS_CLASS_IN);

    dns_packet_set_field(p, DNS_FIELD_QDCOUNT, 1);
    
#ifndef NSS_IPV4_ONLY
    if (af == AF_INET6)
        ret = send_dns_packet6(fd, p);
#endif
#ifndef NSS_IPV6_ONLY
    if (af == AF_INET)
        ret = send_dns_packet(fd, p);
#endif
    
finish:
    if (p)
        dns_packet_free(p);

    return ret;
}

static int process_reverse_response(int fd, const char *name, usec_t timeout, uint16_t id, void (*name_func)(const char *name, void *userdata), void *userdata) {
    struct dns_packet *p = NULL;
    int done = 0;
    struct timeval end;

    assert(fd >= 0 && name && name_func);
    
    gettimeofday(&end, NULL);
    timeval_add(&end, timeout);

    while (!done) {
        uint8_t ttl;
        uint32_t ifindex;
        int r;

        if ((r = recv_dns_packet(&fd, 1, &p, &ttl, &ifindex, &end)) < 0)
            return -1;
        else if (r > 0) /* timeout */
            return 1;

        /* Ignore packets with RFC != 255 */
        if (/* ttl == 255 && */
            dns_packet_check_valid_response(p) >= 0 &&
            dns_packet_get_field(p, DNS_FIELD_ID) == id) {

            unsigned i;

            if (skip_questions(p) >= 0) {
            
                for (i = dns_packet_get_field(p, DNS_FIELD_ANCOUNT); i > 0; i--) {
                    char pname[256];
                    uint16_t type, class;
                    uint32_t rr_ttl;
                    uint16_t rdlength;
                    
                    if (dns_packet_consume_name(p, pname, sizeof(pname)) < 0 ||
                        dns_packet_consume_uint16(p, &type) < 0 ||
                        dns_packet_consume_uint16(p, &class) < 0 ||
                        dns_packet_consume_uint32(p, &rr_ttl) < 0 ||
                        dns_packet_consume_uint16(p, &rdlength) < 0) {
                        break;
                    }
                    
                    /* Remove mDNS cache flush bit */
                    class &= ~0x8000;
                    
                    if (type == DNS_TYPE_PTR &&
                        class == DNS_CLASS_IN &&
                        !domain_cmp(name, pname)) {
                        
                        char rname[256];
                        
                        if (dns_packet_consume_name(p, rname, sizeof(rname)) < 0)
                            break;
                        
                        name_func(rname, userdata);
                        done = 1;
                        
                    } else {
                        
                        /* Step over */
                        
                        if (dns_packet_consume_seek(p, rdlength) < 0)
                            break;
                    }
                }
            }
        }

        if (p)
            dns_packet_free(p);
    }

    return 0;
}

static int query_reverse(int fd, int af, const char *name, void (*name_func)(const char *name, void *userdata), void *userdata) {
    const usec_t *timeout = retry_ms;
    uint16_t id;
    
    assert(fd >= 0 && name && name_func);

    id = get_random_id();
    
    while (*timeout > 0) {
        int n;
        
        if (send_reverse_query(fd, af, name, id) <= 0) /* error or no interface to send data on */
            return -1;

        if ((n = process_reverse_response(fd, name, *timeout, id, name_func, userdata)) < 0)
            return -1;

        if (n == 0)
            return 0;

        /* Timeout */

        timeout++;
    }

    return -1;
}

#ifndef NSS_IPV6_ONLY
int mdns_query_ipv4(int fd, const ipv4_address_t *ipv4, void (*name_func)(const char *name, void *userdata), void *userdata) {
    char name[256];
    uint32_t a;
    assert(fd >= 0 && ipv4 && name_func);

    a = ntohl(ipv4->address);
    snprintf(name, sizeof(name), "%u.%u.%u.%u.in-addr.arpa", a & 0xFF, (a >> 8) & 0xFF, (a >> 16) & 0xFF, a >> 24);

    return query_reverse(fd, AF_INET, name, name_func, userdata);
}
#endif

#ifndef NSS_IPV4_ONLY
int mdns_query_ipv6(int fd, const ipv6_address_t *ipv6, void (*name_func)(const char *name, void *userdata), void *userdata) {
    char name[256];
    assert(fd >= 0 && ipv6 && name_func);

    snprintf(name, sizeof(name), "%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.ip6.arpa",
             ipv6->address[15] & 0xF, ipv6->address[15] >> 4,
             ipv6->address[14] & 0xF, ipv6->address[14] >> 4,
             ipv6->address[13] & 0xF, ipv6->address[13] >> 4,
             ipv6->address[12] & 0xF, ipv6->address[12] >> 4,
             ipv6->address[11] & 0xF, ipv6->address[11] >> 4,
             ipv6->address[10] & 0xF, ipv6->address[10] >> 4,
             ipv6->address[9] & 0xF, ipv6->address[9] >> 4,
             ipv6->address[8] & 0xF, ipv6->address[8] >> 4,
             ipv6->address[7] & 0xF, ipv6->address[7] >> 4,
             ipv6->address[6] & 0xF, ipv6->address[6] >> 4,
             ipv6->address[5] & 0xF, ipv6->address[5] >> 4,
             ipv6->address[4] & 0xF, ipv6->address[4] >> 4,
             ipv6->address[3] & 0xF, ipv6->address[3] >> 4,
             ipv6->address[2] & 0xF, ipv6->address[2] >> 4,
             ipv6->address[1] & 0xF, ipv6->address[1] >> 4,
             ipv6->address[0] & 0xF, ipv6->address[0] >> 4);
    
    return query_reverse(fd, AF_INET6, name, name_func, userdata);
}
#endif
