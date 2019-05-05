/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

#include <stdint.h>
#include <sys/socket.h>
#include <sys/eventfd.h>
#include <sys/epoll.h>
#include <fcntl.h>
#include <linux/ioctl.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <malloc.h>
#include <time.h>
#include <errno.h>

#include <proton/connection.h>
#include <proton/delivery.h>
#include <proton/event.h>
#include <proton/link.h>
#include <proton/message.h>
#include <proton/proactor.h>
#include <proton/session.h>
#include <proton/transport.h>
#include <proton/url.h>

#include "bridge.h"
#include "threading.h"
#include "netns.h"
#include "ctools.h"

#define MTU 1500
#define BUFSIZE 2048
#define MAX_EVENTS 64
#define MAX_TUNNELS 16
   
typedef struct ip_header_t {
    uint8_t  version;
    uint8_t  field1;
    uint16_t field2;
    uint32_t field3;
    union {
        struct {
            uint32_t field4;
            uint32_t v4_src_addr;
            uint32_t v4_dst_addr;
        } v4;
        struct {
            uint16_t v6_src_addr[8];
            uint16_t v6_dst_addr[8];
        } v6;
    };
} ip_header_t;

// Note that msg_data is encoded on
// outbound, decoded on inbound
typedef struct br_message_t {
    DEQ_LINKS(struct br_message_t);
    pn_bytes_t mbuf;
} br_message_t;

DEQ_DECLARE(br_message_t, br_message_list_t);


typedef struct tunnel_t {
    DEQ_LINKS(struct tunnel_t);
    const char        *name;
    const char        *ns_pid;
    const char        *vlan;
    const char        *ip_addr;
    const char        *ip6_addr;
    int                evt_fd;
    int                vlan_fd;
    pn_link_t         *ip_link;
    pn_link_t         *ip6_link; 
    br_message_list_t in_messages;
} tunnel_t;

DEQ_DECLARE(tunnel_t, tunnel_list_t);

typedef struct br_thread_t {
    int          thread_id;
    volatile int running;
    volatile int canceled;
    volatile int using_thread;
    sys_thread_t *thread;    
} br_thread_t;


// Bridge driver
pn_proactor_t     *proactor;
sys_mutex_t       *lock;
br_message_list_t out_messages;
uint64_t          br_tag = 1;
tunnel_list_t     tunnels;
br_thread_t       *br_thread;
int               tunnel_count;
bool              finished = false;

int exit_code = 0;

static void ip6_segment(char *out, const uint16_t *addr, int idx)
{
    uint16_t seg = ntohs(addr[idx]);

    *out = '\0';

    if (idx == 0) {
        if (seg == 0)
            strcpy(":", out);
        else
            sprintf(out, "%x:", seg);
    } else {
        if (seg == 0 && idx == 7)
            strcpy(":", out);
        else if (seg > 0) {
            uint16_t prev = ntohs(addr[idx - 1]);
            if (prev == 0)
                sprintf(out, ":%x%c", seg, idx < 7 ? ':' : '\0');
            else
                sprintf(out, "%x:", seg);
        }
    }
}

/**
 * get_dest_addr
 *
 * Given a buffer received from the tunnel interface, extract the destination
 * IP address and generate an AMQP address from the vlan name and the IP address.
 */
static void get_dest_addr(unsigned char *buffer, const char *vlan, char *addr, int len)
{
    const ip_header_t *hdr = (const ip_header_t*) buffer;

    if ((hdr->version & 0xf0) == 0x40) {
        uint32_t ip4_addr = ntohl(hdr->v4.v4_dst_addr);
        snprintf(addr, len, "u/%s/%d.%d.%d.%d", vlan,
                 (ip4_addr & 0xFF000000) >> 24,
                 (ip4_addr & 0x00FF0000) >> 16,
                 (ip4_addr & 0x0000FF00) >> 8,
                 (ip4_addr & 0x000000FF));
    } else {
        char seg[8][8];
        int  idx;

        for (idx = 0; idx < 8; idx++)
            ip6_segment(seg[idx], hdr->v6.v6_dst_addr, idx);

        snprintf(addr, len, "u/%s/%s%s%s%s%s%s%s%s", vlan,
                 seg[0], seg[1], seg[2], seg[3], seg[4], seg[5], seg[6], seg[7]);
    }
}


static const char *bridge_get_env(const char *suffix, int idx)
{
    char var[32];

    snprintf(var, 32, "LANQP_IF%d_%s", idx, suffix);
    return getenv(var);
}

tunnel_t *get_epoll_tunnel(int epoll_fd)
{
    tunnel_t *tunnel = DEQ_HEAD(tunnels);

    while (tunnel) {
        if (epoll_fd == tunnel->vlan_fd || epoll_fd == tunnel->evt_fd) {
            return tunnel;
        }
        tunnel = DEQ_NEXT(tunnel);
    }

    return tunnel;
}

static void br_message_free(br_message_t *brm)
{
    if (brm->mbuf.start) {
        free((void *)brm->mbuf.start);
    }
    free(brm);
}

/*
static void decode_amqp(br_message_t *brm)
{
    pn_message_t *msg;
    int err;
    pn_data_t* body;
    pn_bytes_t bytes;
    br_message_t *brmi;

    brmi = NEW(br_message_t);
    brmi->mbuf = pn_bytes(BUFSIZE, (char *)malloc(BUFSIZE));
    
    msg = pn_message();
    err = pn_message_decode(msg, brm->mbuf.start, brm->mbuf.size);
    if (err != 0) {
        printf("message decode error \n");
    }

    body = pn_message_body(msg);
    pn_data_next(body);
    bytes = pn_data_get_binary(body);

    memcpy((char *)brmi->mbuf.start,(char *)bytes.start, bytes.size);
    br_message_free(brmi);
}
*/

static void bridge_vlan_read(tunnel_t *tunnel)
{
    size_t          bufsize = BUFSIZE;
    pn_data_t       *body;
    br_message_t    *brm;
    pn_message_t    *message;
    char            addr_str[200];
    size_t          len;
    pn_session_t    *s = pn_link_session(tunnel->ip_link);
    pn_connection_t *c= pn_session_connection(s);

    while (1) {
        brm = NEW(br_message_t);
        DEQ_ITEM_INIT(brm);

        brm->mbuf = pn_bytes(bufsize, (char*)malloc(bufsize)); 
        len = read(tunnel->vlan_fd, (char *)brm->mbuf.start, brm->mbuf.size);
        if (len == -1) {
            br_message_free(brm);
            if (errno == EAGAIN || errno == EINTR) {
                // epoll vlan_fd is level so should
                // not need to re-activate
                return;
            }
        }
        
        if (len < 20) {
            br_message_free(brm);
            continue;
        } else {
            brm->mbuf.size = len;
        }
        
        message = pn_message();
        get_dest_addr((unsigned char *)brm->mbuf.start, tunnel->vlan, addr_str, 200);
        pn_message_set_address(message, addr_str);
        body = pn_message_body(message);
        pn_data_clear(body);
        pn_data_put_binary(body, brm->mbuf);
        pn_data_exit(body);

        // put_binary copies and stores so
        // ok to use pbuf
        brm->mbuf.size = bufsize;
        pn_message_encode(message, (char *)brm->mbuf.start, &brm->mbuf.size);
        //decode_amqp(brm);
        
        sys_mutex_lock(lock);
        DEQ_INSERT_TAIL(out_messages, brm);
        sys_mutex_unlock(lock);

        pn_message_free(message);

        // activate the amqp sender to call bridge_send_out_messages
        pn_connection_wake(c);
    }
    
    return;
}

static int bridge_deliver_in_messages(tunnel_t *tunnel)
{
    br_message_t *brm;
    int len;
    
    sys_mutex_lock(lock);
    brm = DEQ_HEAD(tunnel->in_messages);
    while (brm) {
        
        len = write(tunnel->vlan_fd, brm->mbuf.start, brm->mbuf.size);
        if (len == 0) {
            printf("wrote to tunnel \n");
        }
        if (len == -1) {
            if (errno == EAGAIN || errno == EINTR) {
                // fd socket is not accepting writes, come back
                // when it is writable.
                break;
            }
        }
            
        DEQ_REMOVE_HEAD(tunnel->in_messages);
        br_message_free(brm);
        brm = DEQ_HEAD(tunnel->in_messages);
    }
    sys_mutex_unlock(lock);

    return(0);
    
}

int bridge_activate_tunnel(tunnel_t *tunnel)
{
    static uint64_t evt_fd_delta = 1;

    write(tunnel->evt_fd, &evt_fd_delta, sizeof(uint64_t));
    return 0;
}


static int bridge_send_out_messages(pn_link_t *link)
{
    uint64_t          dtag;
    br_message_list_t to_send;
    br_message_t      *brm;
    int               link_credit = pn_link_credit(link);
    int               event_count = 0;

    DEQ_INIT(to_send);

    sys_mutex_lock(lock);
    if (link_credit > 0) {
        dtag = br_tag;
        brm = DEQ_HEAD(out_messages);
        while (brm) {
            DEQ_REMOVE_HEAD(out_messages);
            DEQ_INSERT_TAIL(to_send,brm);
            if (DEQ_SIZE(to_send) == link_credit)
                break;
            brm = DEQ_HEAD(out_messages);
        }
        br_tag += DEQ_SIZE(to_send);
    }

    sys_mutex_unlock(lock);

    // msg_data already encoded
    brm = DEQ_HEAD(to_send);
    while (brm) {
        DEQ_REMOVE_HEAD(to_send);
        dtag++;
        pn_delivery(link, pn_dtag((const char*)&dtag, sizeof(dtag)));
        pn_link_send(link, brm->mbuf.start, brm->mbuf.size);
        pn_link_advance(link);
        event_count++;
        br_message_free(brm);
        brm = DEQ_HEAD(to_send);
    }
   
    return event_count;
}


static br_thread_t *thread(int id)
{
    br_thread_t *thread = NEW(br_thread_t);
    if (!thread)
        return 0;

    thread->thread_id    = id;
    thread->running      = 0;
    thread->canceled     = 0;
    thread->using_thread = 0;
    

    return thread;
}


static void *thread_run(void *arg)
{
    br_thread_t         *thread = (br_thread_t*) arg;
    struct epoll_event  event;
    struct epoll_event  *events;
    int                 ret, nr_events, i, epoll_fd;
    
    if (!thread)
        return 0;
    thread->running = 1;

    epoll_fd = epoll_create1(0);
    if (epoll_fd < 0) {
        return 0;
    } 

    tunnel_t *tunnel = DEQ_HEAD (tunnels);
   
    while (tunnel) {
        // setup event and tunnel fd
        
        event.data.fd = tunnel->evt_fd;
        event.events = EPOLLIN | EPOLLET; 
        ret = epoll_ctl(epoll_fd, EPOLL_CTL_ADD, tunnel->evt_fd, &event);
        if (ret < 0) {
            return 0;
        }

        event.data.fd = tunnel->vlan_fd;
        //        event.events = EPOLLIN | EPOLLOUT;
        event.events = EPOLLIN;
        ret = epoll_ctl(epoll_fd, EPOLL_CTL_ADD, tunnel->vlan_fd, &event);
        if (ret < 0){
            return 0;
        }

        tunnel = DEQ_NEXT(tunnel);
    }
   
    events = malloc(sizeof (struct epoll_event) * MAX_EVENTS);

    while (thread->running) {
    
        nr_events = epoll_wait(epoll_fd, events, MAX_EVENTS, -1);

        if (nr_events < 0) {
            free(events);
            return 0;
        }
    
        for (i = 0; i < nr_events; i++){
            if (events[i].events & EPOLLERR) {
                printf("Epoll on on events failed\n");
                free(events);
                return 0;
            }
                
            if (events[i].events & EPOLLHUP) {
                printf("Epoll on fd %d hangup\n",
                       events[i].data.fd);
                free(events);
                return 0;
            }

            if (events[i].events & EPOLLOUT) {
                tunnel_t *tunnel = get_epoll_tunnel(events[i].data.fd);
                bridge_deliver_in_messages(tunnel);
            }
            
            if (events[i].events & EPOLLIN) {
                tunnel_t *tunnel = get_epoll_tunnel(events[i].data.fd);
                if (events[i].data.fd == tunnel->vlan_fd) {
                    bridge_vlan_read(tunnel);
                } else {
                    const size_t s = 32;
                    char buffer[s];
                    read(tunnel->evt_fd, buffer, s);
                    bridge_deliver_in_messages(tunnel);
                }
            }
            
        }
    }
    
    free (events);
    close (tunnel->vlan_fd);
    /*    if (thread->canceled)
          return 0; */

    return 0;
}


static void thread_start(br_thread_t *thread)
{
    if (!thread)
        return;

    thread->using_thread = 1;
    thread->thread = sys_thread(thread_run, (void*) thread);
}
/*
static void thread_cancel(br_thread_t *thread)
{
    if (!thread)
        return;

    thread->running  = 0;
    thread->canceled = 1;
}
*/

static void thread_join(br_thread_t *thread)
{
    if (!thread)
        return;

    if (thread->using_thread) {
        sys_thread_join(thread->thread);
        sys_thread_free(thread->thread);
    }
}

/*
static void thread_free(br_thread_t *thread)
{
    if (!thread)
        return;

    free(thread);
}
*/

static void check_condition(pn_event_t *e, pn_condition_t *cond) {
  if (pn_condition_is_set(cond)) {
    fprintf(stderr, "%s: %s: %s\n", pn_event_type_name(pn_event_type(e)),
            pn_condition_get_name(cond), pn_condition_get_description(cond));
    pn_connection_close(pn_event_connection(e));
    exit_code = 1;
  }
}

static void handle(pn_event_t* event) {

    switch (pn_event_type(event)) {

    case PN_CONNECTION_INIT: {
        pn_connection_t* c = pn_event_connection(event);
        pn_session_t* s = pn_session(pn_event_connection(event));
        pn_connection_open(c);
        pn_session_open(s);
        pn_link_t *sender = pn_sender(s, "vlan-sender");
        pn_link_set_snd_settle_mode(sender, PN_SND_SETTLED);
        pn_link_open(sender);

        // Setup receive link for each defined tunnel
        tunnel_t *tunnel = DEQ_HEAD(tunnels);
        pn_record_t *record;
        while (tunnel) {
            if (tunnel->ip_addr) {
                // What link attachment or context do we need to set e.g. record
                char a4[1000];
                tunnel->ip_link = pn_receiver(s, tunnel->name);
                record = pn_link_attachments(tunnel->ip_link);
                pn_record_set(record, PN_LEGCTX, tunnel);
                snprintf(a4, 1000, "u/%s/%s", tunnel->vlan, tunnel->ip_addr);
                pn_terminus_set_address(pn_link_source(tunnel->ip_link), a4);
                pn_terminus_set_address(pn_link_remote_target(tunnel->ip_link), a4);
                pn_link_open(tunnel->ip_link);
                pn_link_flow(tunnel->ip_link, 40);                
            }
            if (tunnel->ip6_addr) {
            }
            tunnel = DEQ_NEXT(tunnel);
        }
    } break;

    case PN_DELIVERY: {
        // This is for bridge receive as send is pre-settled
        pn_link_t     *link = NULL;
        pn_delivery_t *dlv = pn_event_delivery(event);
        pn_record_t   *record;
        tunnel_t      *tunnel;
        size_t        bufsize = BUFSIZE;
        ssize_t       len;
        br_message_t  *brm;
        pn_message_t  *msg;
        pn_data_t     *body;
        pn_bytes_t    data;

        if (pn_delivery_readable(dlv) && !pn_delivery_partial(dlv)) {
            brm = NEW(br_message_t);
            DEQ_ITEM_INIT(brm);

            brm->mbuf = pn_bytes(bufsize, (char *)malloc(bufsize));
            link = pn_delivery_link(dlv);
            
            len = pn_link_recv(link, (char *) brm->mbuf.start, brm->mbuf.size);

            msg = pn_message();

            pn_message_decode(msg, brm->mbuf.start, len);
            body = pn_message_body(msg);
            pn_data_next(body);
            data = pn_data_get_binary(body);

            memcpy((char *)brm->mbuf.start,(char *)data.start, data.size);
            brm->mbuf.size = data.size;
            
            record = pn_link_attachments(link);
            tunnel = (tunnel_t *)pn_record_get(record, PN_LEGCTX);
            
            // Accept the delivery and move to the next
            pn_link_advance(link);
            pn_link_flow(link, 1);
            
            sys_mutex_lock(lock);
            DEQ_INSERT_TAIL(tunnel->in_messages, brm);
            sys_mutex_unlock(lock);
            bridge_activate_tunnel(tunnel);

            // done with the delivery
            pn_delivery_settle(dlv);
            pn_message_free(msg);
        }
    } break;
        
    case PN_LINK_FLOW: {
        // The remote has given us credit to send a message
        pn_link_t *sender = pn_event_link(event);
        bridge_send_out_messages(sender);
    } break;

    case PN_PROACTOR_TIMEOUT: {
        pn_link_t *sender = pn_event_link(event);
        pn_connection_wake(pn_session_connection(pn_link_session(sender)));
    } break;

    case PN_CONNECTION_WAKE: {
        // There is tunnel data to send
        pn_link_t *sender = pn_event_link(event);
        bridge_send_out_messages(sender);
    } break;

    case PN_TRANSPORT_CLOSED:
        check_condition(event, pn_transport_condition(pn_event_transport(event)));
        break;

    case PN_CONNECTION_REMOTE_CLOSE:
         check_condition(event, pn_connection_remote_condition(pn_event_connection(event)));
         pn_connection_close(pn_event_connection(event));
         break;

    case PN_SESSION_REMOTE_CLOSE:
         check_condition(event, pn_session_remote_condition(pn_event_session(event)));
         pn_connection_close(pn_event_connection(event));
         break;

    case PN_LINK_REMOTE_CLOSE:
    case PN_LINK_REMOTE_DETACH:
        check_condition(event, pn_link_remote_condition(pn_event_link(event)));
        pn_connection_close(pn_event_connection(event));
        break;

    case PN_PROACTOR_INACTIVE:
        finished = true;
        break;
        
    default: break;
    }
}

static tunnel_t *bridge_add_tunnel(int idx)
{
    tunnel_t *tunnel = NEW(tunnel_t);
    memset (tunnel, 0, sizeof(tunnel_t));
    DEQ_ITEM_INIT(tunnel);
    DEQ_INIT(tunnel->in_messages);
       
    tunnel->name     = bridge_get_env("NAME", idx);
    tunnel->ns_pid   = bridge_get_env("PID",  idx);
    tunnel->vlan     = bridge_get_env("VLAN", idx);
    tunnel->ip_addr  = bridge_get_env("IP",   idx);
    tunnel->ip6_addr = bridge_get_env("IP6",  idx);

    if (!tunnel->name)
        tunnel->name = "lanq0";


    tunnel->vlan_fd = open_tunnel_in_ns(tunnel->name, tunnel->ns_pid);
    if (tunnel->vlan_fd == -1) {
        printf("Tunnel open failed on device %s", tunnel->name);
        exit(1);
    }
        
    int flags = fcntl(tunnel->vlan_fd, F_GETFL);
    flags |= O_NONBLOCK;

    if (fcntl(tunnel->vlan_fd, F_SETFL, flags) < 0) {
        printf("Tunnel failed to set to non-blocking: %s", strerror(errno));
        close(tunnel->vlan_fd);
        exit(1);
    }

    tunnel->evt_fd = eventfd(0, EFD_NONBLOCK);
    if (tunnel->evt_fd < 0) {
        exit(1);
    }

       
    return tunnel;
}
        
int bridge_setup (const char* address, const char *container, const char *ns_pid)
{
    const char *env = getenv("LANQP_IF_COUNT");
    const char* urlstr = NULL;
    
    DEQ_INIT(out_messages);
    DEQ_INIT(tunnels);
    lock = sys_mutex();
    
    if (!env){
        printf("Environment variable LANQP_IF_COUNT not set\n");
        exit(1);
    }  
    
    int idx;
    tunnel_count = atoi(env);   

    for (idx = 0; idx < tunnel_count; idx++){
        tunnel_t *tunnel = bridge_add_tunnel(idx);
        DEQ_INSERT_TAIL(tunnels, tunnel);
        printf("Tunnel name: %s and ip address %s\n", tunnel->name, tunnel->ip_addr);
    }

    /* Parse the URL or use default values */
    pn_url_t *url = urlstr ? pn_url_parse(urlstr) : NULL;
    //    const char *host = url ? pn_url_get_host(url) : NULL;
    //    const char *port = url ? pn_url_get_port(url) : "amqp";

    proactor = pn_proactor();
    pn_connection_t *conn = pn_connection();
    pn_proactor_connect(proactor, conn, address);

    if (url) pn_url_free(url);    
      
    return 0;

}

void bridge_exit()
{
    // close all tunnels and event fds
    //    close(evt_fd);
    sys_mutex_free(lock);
}


int bridge_run(int wait)
{

    br_thread = thread(1);
    
    thread_start(br_thread);

    do {
        pn_event_batch_t *events = pn_proactor_wait(proactor);
        pn_event_t *e;
        while ((e = pn_event_batch_next(events))) {
            handle(e);
        }
        pn_proactor_done(proactor, events);
    } while (!finished);
    
    thread_join(br_thread);

    br_thread->canceled = 0;

    bridge_exit();
          
    return 0;
}
   

