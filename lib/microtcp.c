/*
 * microtcp, a lightweight implementation of TCP for teaching,
 * and academic purposes.
 *
 * Copyright (C) 2015-2017  Manolis Surligas <surligas@gmail.com>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

 #include "microtcp.h"
 #include "../utils/crc32.h"
#include <ctime>
 #include <stdint.h>
 #include <string.h>
 #include <stdlib.h>
 #include <stdio.h>

 microtcp_sock_t microtcp_socket(int domain, int type, int protocol) {
     microtcp_sock_t sock;
     sock.sd = socket(domain, type, protocol);

     if (sock.sd < 0) {
         perror("[microtcp_socket] Invalid file descriptor");
         sock.state = INVALID;
         return sock;
     }

     sock.state = CLOSED;
     sock.init_win_size = MICROTCP_WIN_SIZE;
     sock.curr_win_size = MICROTCP_WIN_SIZE;
     sock.ssthresh = MICROTCP_INIT_SSTHRESH;
     sock.cwnd = MICROTCP_INIT_CWND;

     return sock;
 }

 int microtcp_bind(microtcp_sock_t *socket, const struct sockaddr *address,
                   socklen_t address_len) {
     int bind_result = bind(socket->sd, address, address_len);
     if (bind_result < 0) {
         perror("[microtcp_bind] bind failed");
         return bind_result;
     }

     return bind_result;
 }

 int microtcp_accept(microtcp_sock_t *socket, struct sockaddr *address,
                     socklen_t address_len) {
     ssize_t recv_status, send_status;
     microtcp_header_t *incoming_mtcp_header = (microtcp_header_t *)malloc(sizeof(microtcp_header_t));
     microtcp_header_t internal_mtcp_header, outgoing_mtcp_header;
     uint8_t checksum_byte_arr[MICROTCP_RECVBUF_LEN];
     uint32_t calculated_checksum;

     if (!incoming_mtcp_header) {
         perror("[microtcp_accept] malloc failed\n");
         return -1;
     }

     // Accept packet
     recv_status = recvfrom(socket->sd, incoming_mtcp_header,
                           sizeof(microtcp_header_t), 0, address, &address_len);
     if (recv_status < 0) {
         perror("[microtcp_accept - SYN] recvfrom failed\n");
         free(incoming_mtcp_header);
         return -1;
     }

     // Process packet after checking control = SYN
     if (htons(incoming_mtcp_header->control) != SYN) {
         perror("[microtcp_accept] expected SYN control flag\n");
         return -1;
     }

     // Populate private header. Needed for checksum calculation
     internal_mtcp_header.seq_number = ntohl(incoming_mtcp_header->seq_number);
     internal_mtcp_header.ack_number = 0;
     internal_mtcp_header.control = ntohs(incoming_mtcp_header->control);
     internal_mtcp_header.window = ntohs(incoming_mtcp_header->window);
     internal_mtcp_header.data_len = ntohl(incoming_mtcp_header->data_len);
     internal_mtcp_header.future_use0 = 0;
     internal_mtcp_header.future_use1 = 0;
     internal_mtcp_header.future_use2 = 0;
     internal_mtcp_header.checksum = 0;

     /**
      * Convert to byte array for checksum calculation.
      * By copying into a uint8_t array (bytes!), no conversion issues
      * arise from direct usage, since one uint8_t is one byte, unlike ints or longs
      * that would have required sth like sizeof(microtcp_header_t)/sizeof(int)
      */
     for (int i = 0; i < MICROTCP_RECVBUF_LEN; i++) {
         checksum_byte_arr[i] = 0;
     }
     memcpy(checksum_byte_arr, &internal_mtcp_header, sizeof(microtcp_header_t));

     calculated_checksum = crc32(checksum_byte_arr, sizeof(microtcp_header_t));

     if (calculated_checksum != ntohl(incoming_mtcp_header->checksum)) {
         perror("[microtcp_accept - SYN] checksum mismatch\n");
         free(incoming_mtcp_header);
         return -1;
     }

     // Construct SYN-ACK response
     outgoing_mtcp_header.seq_number = htonl(rand() % 100 + 1);
     outgoing_mtcp_header.ack_number = htonl(internal_mtcp_header.seq_number + 1);
     outgoing_mtcp_header.control = htons(SYN_ACK);
     outgoing_mtcp_header.window = htons(MICROTCP_WIN_SIZE);
     outgoing_mtcp_header.data_len = htonl(0);
     outgoing_mtcp_header.future_use0 = htonl(0);
     outgoing_mtcp_header.future_use1 = htonl(0);
     outgoing_mtcp_header.future_use2 = htonl(0);
     outgoing_mtcp_header.checksum = 0;

     // calculate checksum for SYN-ACK
     for (int i = 0; i < MICROTCP_RECVBUF_LEN; i++) {
         checksum_byte_arr[i] = 0;
     }
     memcpy(checksum_byte_arr, &outgoing_mtcp_header, sizeof(microtcp_header_t));
     calculated_checksum = crc32(checksum_byte_arr, sizeof(microtcp_header_t));
     outgoing_mtcp_header.checksum = ntohl(calculated_checksum);

     // send syn-ack, check for error
     send_status = sendto(socket->sd, &outgoing_mtcp_header,
                         sizeof(microtcp_header_t), 0, address, address_len);
     if (send_status < 0) {
         perror("[microtcp_accept - SYN-ACK] sendto failed\n");
         free(incoming_mtcp_header);
         return -1;
     }

     // wait for final ack
     recv_status = recvfrom(socket->sd, incoming_mtcp_header,
                           sizeof(microtcp_header_t), 0, address, &address_len);
     if (recv_status < 0) {
         perror("[microtcp_accept - ACK] recvfrom failed\n");
         free(incoming_mtcp_header);
         return -1;
     }

     // contruct internal header for checksum verification
     internal_mtcp_header.seq_number = ntohl(incoming_mtcp_header->seq_number);
     internal_mtcp_header.ack_number = ntohl(incoming_mtcp_header->ack_number);
     internal_mtcp_header.control = ntohs(incoming_mtcp_header->control);
     internal_mtcp_header.window = ntohs(incoming_mtcp_header->window);
     internal_mtcp_header.data_len = ntohl(incoming_mtcp_header->data_len);
     internal_mtcp_header.future_use0 = 0;
     internal_mtcp_header.future_use1 = 0;
     internal_mtcp_header.future_use2 = 0;
     internal_mtcp_header.checksum = 0;

     // check control = ACK
     if (htons(incoming_mtcp_header->control) != ACK) {
         perror("[microtcp_accept] expected ACK control flag\n");
         free(incoming_mtcp_header);
         return -1;
     }

     // calculate checksum
     for (int i = 0; i < MICROTCP_RECVBUF_LEN; i++) {
         checksum_byte_arr[i] = 0;
     }
     memcpy(checksum_byte_arr, &internal_mtcp_header, sizeof(microtcp_header_t));
     calculated_checksum = crc32(checksum_byte_arr, sizeof(microtcp_header_t));

     if (calculated_checksum != ntohl(incoming_mtcp_header->checksum)) {
         perror("[microtcp_accept - ACK] checksum mismatch\n");
         free(incoming_mtcp_header);
         return -1;
     }

     // check for correct ack number, seq
     if (ntohl(incoming_mtcp_header->seq_number) != outgoing_mtcp_header.ack_number) {
         perror("[microtcp_accept] incorrect seq number in ACK\n");
         free(incoming_mtcp_header);
         return -1;
     }
     if (ntohl(incoming_mtcp_header->ack_number) != outgoing_mtcp_header.seq_number + 1) {
         perror("[microtcp_accept] incorrect ack number in ACK\n");
         free(incoming_mtcp_header);
         return -1;
     }

     // connection established successfully. update socket state
     socket->state = ESTABLISHED;
     socket->seq_number = internal_mtcp_header.ack_number;
     socket->ack_number = internal_mtcp_header.seq_number + 1;

     return 0;
 }

 int microtcp_connect(microtcp_sock_t *socket, const struct sockaddr *address, socklen_t address_len) {
        uint32_t calculated_checksum;
        ssize_t send_status, recv_status;
        microtcp_header_t outgoing_mtcp_header, *incoming_mtcp_header = (microtcp_header_t *)malloc(sizeof(microtcp_header_t)), internal_mtcp_header;
        uint8_t checksum_byte_arr[MICROTCP_RECVBUF_LEN];

        if (!incoming_mtcp_header) {
            perror("[microtcp_connect] malloc failed\n");
            return -1;
        }

        // start SYN handshake - construct SYN packet
        outgoing_mtcp_header.seq_number = htonl(rand() % 100 + 1);
        outgoing_mtcp_header.ack_number = htonl(0);
        outgoing_mtcp_header.control = htons(SYN);
        outgoing_mtcp_header.window = htons(MICROTCP_WIN_SIZE);
        outgoing_mtcp_header.data_len = htonl(0);
        outgoing_mtcp_header.future_use0 = htonl(0);
        outgoing_mtcp_header.future_use1 = htonl(0);
        outgoing_mtcp_header.future_use2 = htonl(0);
        outgoing_mtcp_header.checksum = 0;

        // compute SYN checksum
        for (int i = 0; i < MICROTCP_RECVBUF_LEN; i++) {
            checksum_byte_arr[i] = 0;
        }
        memcpy(checksum_byte_arr, &outgoing_mtcp_header, sizeof(microtcp_header_t));
        calculated_checksum = crc32(checksum_byte_arr, sizeof(microtcp_header_t));
        outgoing_mtcp_header.checksum = ntohl(calculated_checksum);

        // send SYN packet
        send_status = sendto(socket->sd, &outgoing_mtcp_header,
                             sizeof(microtcp_header_t), 0, address, address_len);
        if (send_status < 0) {
            perror("[microtcp_connect - SYN] sendto failed\n");
            return -1;
        }

        // wait for SYN-ACK response
        recv_status = recvfrom(socket->sd, incoming_mtcp_header,
                               sizeof(microtcp_header_t), 0, address, &address_len);
        if (recv_status < 0) {
            perror("[microtcp_connect - SYN-ACK] recvfrom failed\n");
            free(incoming_mtcp_header);
            return -1;
        }

        // construct internal header for checksum verification
        internal_mtcp_header.seq_number = ntohl(incoming_mtcp_header->seq_number);
        internal_mtcp_header.ack_number = ntohl(incoming_mtcp_header->ack_number);
        internal_mtcp_header.control = ntohs(incoming_mtcp_header->control);
        internal_mtcp_header.window = ntohs(incoming_mtcp_header->window);
        internal_mtcp_header.data_len = ntohl(incoming_mtcp_header->data_len);
        internal_mtcp_header.future_use0 = 0;
        internal_mtcp_header.future_use1 = 0;
        internal_mtcp_header.future_use2 = 0;
        internal_mtcp_header.checksum = 0;

        // check control = SYN-ACK
        if (htons(incoming_mtcp_header->control) != SYN_ACK) {
            perror("[microtcp_connect] expected SYN-ACK control flag\n");
            free(incoming_mtcp_header);
            return -1;
        }

        // calculate checksum
        for (int i = 0; i < MICROTCP_RECVBUF_LEN; i++) {
            checksum_byte_arr[i] = 0;
        }
        memcpy(checksum_byte_arr, &internal_mtcp_header, sizeof(microtcp_header_t));
        calculated_checksum = crc32(checksum_byte_arr, sizeof(microtcp_header_t));

        if (calculated_checksum != ntohl(incoming_mtcp_header->checksum)) {
            perror("[microtcp_connect - SYN-ACK] checksum mismatch\n");
            free(incoming_mtcp_header);
            return -1;
        }

        // construct final ACK packet
        outgoing_mtcp_header.seq_number = outgoing_mtcp_header.seq_number;
        outgoing_mtcp_header.ack_number = htonl(internal_mtcp_header.seq_number + 1);
        outgoing_mtcp_header.control = htons(ACK);
        outgoing_mtcp_header.window = htons(MICROTCP_WIN_SIZE);
        outgoing_mtcp_header.data_len = htonl(0);
        outgoing_mtcp_header.future_use0 = htonl(0);
        outgoing_mtcp_header.future_use1 = htonl(0);
        outgoing_mtcp_header.future_use2 = htonl(0);
        outgoing_mtcp_header.checksum = 0;

        // calculate ACK checksum
        for (int i = 0; i < MICROTCP_RECVBUF_LEN; i++) {
            checksum_byte_arr[i] = 0;
        }
        memcpy(checksum_byte_arr, &outgoing_mtcp_header, sizeof(microtcp_header_t));
        calculated_checksum = crc32(checksum_byte_arr, sizeof(microtcp_header_t));
        outgoing_mtcp_header.checksum = ntohl(calculated_checksum);

        // send final ACK packet
        send_status = sendto(socket->sd, &outgoing_mtcp_header,
                             sizeof(microtcp_header_t), 0, address, address_len);
        if (send_status < 0) {
            perror("[microtcp_connect - ACK] sendto failed\n");
            free(incoming_mtcp_header);
            return -1;
        }

        // connection established successfully. update socket state
        socket->state = ESTABLISHED;
        socket->seq_number = ntohl(outgoing_mtcp_header.seq_number);
        socket->ack_number = internal_mtcp_header.seq_number + 1;
        free(incoming_mtcp_header);
        return 0;
 }

 int microtcp_shutdown(microtcp_sock_t *socket, int how) {
     /* Your code here */
 }

 ssize_t microtcp_send(microtcp_sock_t *socket, const void *buffer,
                       size_t length, int flags) {
     /* Your code here */
 }

 ssize_t microtcp_recv(microtcp_sock_t *socket, void *buffer, size_t length,
                       int flags) {
     /* Your code here */
 }
