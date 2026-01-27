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
 #include <stddef.h>
 #include <time.h>
 #include <stdint.h>
 #include <string.h>
 #include <stdlib.h>
 #include <stdio.h>
 #include <arpa/inet.h>

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
     uint32_t incoming_checksum;

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
     if (ntohs(incoming_mtcp_header->control) != SYN) {
        perror("[microtcp_accept] expected SYN control flag");
        free(incoming_mtcp_header);
        return -1;
     }

     incoming_checksum = ntohl(incoming_mtcp_header->checksum);
     incoming_mtcp_header->checksum = 0; // set to 0 for checksum calculation

     /**
      * Convert to byte array for checksum calculation.
      * By copying into a uint8_t array (bytes!), no conversion issues
      * arise from direct usage, since one uint8_t is one byte, unlike ints or longs
      * that would have required sth like sizeof(microtcp_header_t)/sizeof(int)
      */
     for (int i = 0; i < MICROTCP_RECVBUF_LEN; i++) {
         checksum_byte_arr[i] = 0;
     }
     memcpy(checksum_byte_arr, incoming_mtcp_header, sizeof(microtcp_header_t));

     calculated_checksum = crc32(checksum_byte_arr, sizeof(microtcp_header_t));

     if (calculated_checksum != incoming_checksum) {
         perror("[microtcp_accept - SYN] checksum mismatch\n");
         free(incoming_mtcp_header);
         return -1;
     }

     // Populate private header.
     internal_mtcp_header.seq_number = ntohl(incoming_mtcp_header->seq_number);
     internal_mtcp_header.ack_number = 0;
     internal_mtcp_header.control = ntohs(incoming_mtcp_header->control);
     internal_mtcp_header.window = ntohs(incoming_mtcp_header->window);
     internal_mtcp_header.data_len = ntohl(incoming_mtcp_header->data_len);
     internal_mtcp_header.future_use0 = 0;
     internal_mtcp_header.future_use1 = 0;
     internal_mtcp_header.future_use2 = 0;
     internal_mtcp_header.checksum = 0;

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
     outgoing_mtcp_header.checksum = htonl(calculated_checksum);

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

     incoming_checksum = ntohl(incoming_mtcp_header->checksum);
     incoming_mtcp_header->checksum = 0; // set to 0 for checksum calculation

     // check control = ACK
     if (ntohs(incoming_mtcp_header->control) != ACK) {
         perror("[microtcp_accept] expected ACK control flag\n");
         free(incoming_mtcp_header);
         return -1;
     }

     // calculate checksum
     for (int i = 0; i < MICROTCP_RECVBUF_LEN; i++) {
         checksum_byte_arr[i] = 0;
     }
     memcpy(checksum_byte_arr, incoming_mtcp_header, sizeof(microtcp_header_t));
     calculated_checksum = crc32(checksum_byte_arr, sizeof(microtcp_header_t));

     if (calculated_checksum != incoming_checksum) {
         perror("[microtcp_accept - ACK] checksum mismatch\n");
         free(incoming_mtcp_header);
         return -1;
     }

     // contruct internal header
     internal_mtcp_header.seq_number = ntohl(incoming_mtcp_header->seq_number);
     internal_mtcp_header.ack_number = ntohl(incoming_mtcp_header->ack_number);
     internal_mtcp_header.control = ntohs(incoming_mtcp_header->control);
     internal_mtcp_header.window = ntohs(incoming_mtcp_header->window);
     internal_mtcp_header.data_len = ntohl(incoming_mtcp_header->data_len);
     internal_mtcp_header.future_use0 = 0;
     internal_mtcp_header.future_use1 = 0;
     internal_mtcp_header.future_use2 = 0;
     internal_mtcp_header.checksum = 0;

     // check for correct ack number, seq
     if (ntohl(incoming_mtcp_header->seq_number) != ntohl(outgoing_mtcp_header.ack_number)) {
         perror("[microtcp_accept] incorrect seq number in ACK\n");
         free(incoming_mtcp_header);
         return -1;
     }
     if (ntohl(incoming_mtcp_header->ack_number) != ntohl(outgoing_mtcp_header.seq_number) + 1) {
         perror("[microtcp_accept] incorrect ack number in ACK\n");
         free(incoming_mtcp_header);
         return -1;
     }

     // connection established successfully. update socket state
     socket->state = ESTABLISHED;
     socket->seq_number = internal_mtcp_header.ack_number;
     socket->ack_number = internal_mtcp_header.seq_number;

     // Memory allocation for peer address
     socket->peer_address = (struct sockaddr *)malloc(address_len);
     if (socket->peer_address) {
         memcpy((void *)socket->peer_address, address, address_len);
         socket->peer_address_len = address_len;
     }

     socket->recvbuf = (uint8_t *)malloc(MICROTCP_RECVBUF_LEN);
     socket->buf_fill_level = 0;
     if (!socket->recvbuf) {
         perror("[microtcp_accept] recvbuf malloc failed\n");
         free(incoming_mtcp_header);
         return -1;
     }

     return 0;
 }

 int microtcp_connect(microtcp_sock_t *socket, const struct sockaddr *address, socklen_t address_len) {
        uint32_t calculated_checksum;
        ssize_t send_status, recv_status;
        microtcp_header_t outgoing_mtcp_header, *incoming_mtcp_header = (microtcp_header_t *)malloc(sizeof(microtcp_header_t)), internal_mtcp_header;
        uint8_t checksum_byte_arr[MICROTCP_RECVBUF_LEN];
        uint32_t incoming_checksum;

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
        outgoing_mtcp_header.checksum = htonl(calculated_checksum);

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

        incoming_checksum = ntohl(incoming_mtcp_header->checksum);
        incoming_mtcp_header->checksum = 0; // set to 0 for checksum calculation

        // check control = SYN-ACK
        if (ntohs(incoming_mtcp_header->control) != SYN_ACK) {
            perror("[microtcp_connect] expected SYN-ACK control flag\n");
            free(incoming_mtcp_header);
            return -1;
        }

        // calculate checksum
        for (int i = 0; i < MICROTCP_RECVBUF_LEN; i++) {
            checksum_byte_arr[i] = 0;
        }
        memcpy(checksum_byte_arr, incoming_mtcp_header, sizeof(microtcp_header_t));
        calculated_checksum = crc32(checksum_byte_arr, sizeof(microtcp_header_t));

        if (calculated_checksum != incoming_checksum) {
            perror("[microtcp_connect - SYN-ACK] checksum mismatch\n");
            free(incoming_mtcp_header);
            return -1;
        }

        // construct internal header
        internal_mtcp_header.seq_number = ntohl(incoming_mtcp_header->seq_number);
        internal_mtcp_header.ack_number = ntohl(incoming_mtcp_header->ack_number);
        internal_mtcp_header.control = ntohs(incoming_mtcp_header->control);
        internal_mtcp_header.window = ntohs(incoming_mtcp_header->window);
        internal_mtcp_header.data_len = ntohl(incoming_mtcp_header->data_len);
        internal_mtcp_header.future_use0 = 0;
        internal_mtcp_header.future_use1 = 0;
        internal_mtcp_header.future_use2 = 0;
        internal_mtcp_header.checksum = 0;

        // construct final ACK packet
        // keep same seq number as the one in SYN, just + 1. usage of outgoing_mtcp_header.seq_number is correct
        outgoing_mtcp_header.seq_number = htonl(ntohl(outgoing_mtcp_header.seq_number) + 1);
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
        outgoing_mtcp_header.checksum = htonl(calculated_checksum);

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

        // Memory allocation for peer address
        socket->peer_address = (struct sockaddr *)malloc(address_len);
        if (socket->peer_address) {
            memcpy((void *)socket->peer_address, address, address_len);
            socket->peer_address_len = address_len;
        }

        free(incoming_mtcp_header);
        return 0;
 }

int microtcp_shutdown(microtcp_sock_t *socket, int how) {
    uint32_t calculated_checksum;
    ssize_t send_status, recv_status;
    microtcp_header_t outgoing_mtcp_header, *incoming_mtcp_header = (microtcp_header_t *)malloc(sizeof(microtcp_header_t)), internal_mtcp_header;
    uint8_t checksum_byte_arr[MICROTCP_RECVBUF_LEN];
    uint32_t incoming_checksum;

    if (!incoming_mtcp_header) {
        perror("[microtcp_shutdown] malloc failed\n");
        return -1;
    }

    // start FIN handshake - construct FIN packet
    outgoing_mtcp_header.seq_number = htonl(socket->seq_number);
    outgoing_mtcp_header.ack_number = htonl(socket->ack_number);
    outgoing_mtcp_header.control = htons(FIN + ACK);
    outgoing_mtcp_header.window = htons(MICROTCP_WIN_SIZE);
    outgoing_mtcp_header.data_len = htonl(0);
    outgoing_mtcp_header.future_use0 = htonl(0);
    outgoing_mtcp_header.future_use1 = htonl(0);
    outgoing_mtcp_header.future_use2 = htonl(0);
    outgoing_mtcp_header.checksum = 0; // will be calculated next

    // compute FIN checksum
    for (int i = 0; i < MICROTCP_RECVBUF_LEN; i++) {
        checksum_byte_arr[i] = 0;
    }
    memcpy(checksum_byte_arr, &outgoing_mtcp_header, sizeof(microtcp_header_t));
    calculated_checksum = crc32(checksum_byte_arr, sizeof(microtcp_header_t));
    outgoing_mtcp_header.checksum = htonl(calculated_checksum);

    // send FIN packet
    send_status = sendto(socket->sd, &outgoing_mtcp_header,
                            sizeof(microtcp_header_t), 0, socket->peer_address, socket->peer_address_len);
    if (send_status < 0) {
        perror("[microtcp_shutdown - FIN] sendto failed\n");
        free(incoming_mtcp_header);
        return -1;
    }


    // wait for ACK response
    recv_status = recvfrom(socket->sd, incoming_mtcp_header, sizeof(microtcp_header_t), 0, socket->peer_address, &socket->peer_address_len);
    if (recv_status < 0) {
        perror("[microtcp_shutdown - ACK] recvfrom failed\n");
        free(incoming_mtcp_header);
        return -1;
    }

    incoming_checksum = ntohl(incoming_mtcp_header->checksum);
    incoming_mtcp_header->checksum = 0; // set to 0 for checksum calculation

    // check control = ACK
    if (ntohs(incoming_mtcp_header->control) != ACK) {
        perror("[microtcp_shutdown] expected ACK control flag\n");
        free(incoming_mtcp_header);
        return -1;
    }

    // check ack number = seq + 1
    if (ntohl(incoming_mtcp_header->ack_number) != socket->seq_number + 1) {
        perror("[microtcp_shutdown] incorrect ack number in ACK\n");
        free(incoming_mtcp_header);
        return -1;
    }

    // calculate checksum
    for (int i = 0; i < MICROTCP_RECVBUF_LEN; i++) {
        checksum_byte_arr[i] = 0;
    }
    memcpy(checksum_byte_arr, incoming_mtcp_header, sizeof(microtcp_header_t));
    calculated_checksum = crc32(checksum_byte_arr, sizeof(microtcp_header_t));

    // check checksum mismatch
    if (calculated_checksum != incoming_checksum) {
        perror("[microtcp_shutdown - ACK] checksum mismatch\n");
        free(incoming_mtcp_header);
        return -1;
    }

    // construct internal header
    internal_mtcp_header.seq_number = ntohl(incoming_mtcp_header->seq_number);
    internal_mtcp_header.ack_number = ntohl(incoming_mtcp_header->ack_number);
    internal_mtcp_header.control = ntohs(incoming_mtcp_header->control);
    internal_mtcp_header.window = ntohs(incoming_mtcp_header->window);
    internal_mtcp_header.data_len = ntohl(incoming_mtcp_header->data_len);
    internal_mtcp_header.future_use0 = 0;
    internal_mtcp_header.future_use1 = 0;
    internal_mtcp_header.future_use2 = 0;
    internal_mtcp_header.checksum = 0;

    // transition to CLOSING_BY_HOST state after successful FIN-ACK exchange
    socket->state = CLOSING_BY_HOST;

    // await FIN from peer - second part of shutdown
    recv_status = recvfrom(socket->sd, incoming_mtcp_header, sizeof(microtcp_header_t), 0, socket->peer_address, &socket->peer_address_len);
    if (recv_status < 0) {
        perror("[microtcp_shutdown - FIN] recvfrom failed\n");
        free(incoming_mtcp_header);
        return -1;
    }

    incoming_checksum = ntohl(incoming_mtcp_header->checksum);
    incoming_mtcp_header->checksum = 0; // set to 0 for checksum calculation

    // check control = FIN
    if (ntohs(incoming_mtcp_header->control) != FIN) {
        perror("[microtcp_shutdown] expected FIN control flag\n");
        free(incoming_mtcp_header);
        return -1;
    }

    // calculate checksum
    for (int i = 0; i < MICROTCP_RECVBUF_LEN; i++) {
        checksum_byte_arr[i] = 0;
    }
    memcpy(checksum_byte_arr, incoming_mtcp_header, sizeof(microtcp_header_t));
    calculated_checksum = crc32(checksum_byte_arr, sizeof(microtcp_header_t));

    // check checksum mismatch
    if (calculated_checksum != incoming_checksum) {
        perror("[microtcp_shutdown - FIN] checksum mismatch\n");
        free(incoming_mtcp_header);
        return -1;
    }

    // construct internal header
    internal_mtcp_header.seq_number = ntohl(incoming_mtcp_header->seq_number);
    internal_mtcp_header.ack_number = ntohl(incoming_mtcp_header->ack_number);
    internal_mtcp_header.control = ntohs(incoming_mtcp_header->control);
    internal_mtcp_header.window = ntohs(incoming_mtcp_header->window);
    internal_mtcp_header.data_len = ntohl(incoming_mtcp_header->data_len);
    internal_mtcp_header.future_use0 = 0;
    internal_mtcp_header.future_use1 = 0;
    internal_mtcp_header.future_use2 = 0;
    internal_mtcp_header.checksum = 0;

    // finalize shutdown: construct final ACK packet
    outgoing_mtcp_header.seq_number = htonl(socket->seq_number + 1);
    outgoing_mtcp_header.ack_number = htonl(internal_mtcp_header.seq_number + 1);
    outgoing_mtcp_header.control = htons(ACK);
    outgoing_mtcp_header.window = htons(MICROTCP_WIN_SIZE);
    outgoing_mtcp_header.data_len = htonl(0);
    outgoing_mtcp_header.future_use0 = htonl(0);
    outgoing_mtcp_header.future_use1 = htonl(0);
    outgoing_mtcp_header.future_use2 = htonl(0);
    outgoing_mtcp_header.checksum = 0; // will be calculated next

    // calculate ACK checksum
    for (int i = 0; i < MICROTCP_RECVBUF_LEN; i++) {
        checksum_byte_arr[i] = 0;
    }
    memcpy(checksum_byte_arr, &outgoing_mtcp_header, sizeof(microtcp_header_t));
    calculated_checksum = crc32(checksum_byte_arr, sizeof(microtcp_header_t));
    outgoing_mtcp_header.checksum = htonl(calculated_checksum);

    // send final ACK packet
    send_status = sendto(socket->sd, &outgoing_mtcp_header,
                         sizeof(microtcp_header_t), 0, socket->peer_address, socket->peer_address_len);
    if (send_status < 0) {
        perror("[microtcp_shutdown - final ACK] sendto failed\n");
        free(incoming_mtcp_header);
        return -1;
    }

    // connection terminated successfully. update socket state
    socket->state = CLOSED;
    socket->seq_number = socket->seq_number + 1;
    free(incoming_mtcp_header);
    shutdown(socket->sd, how);
    return 0;
}

ssize_t microtcp_send(microtcp_sock_t *socket, const void *buffer, size_t length, int flags) {
    size_t remaining; // remaining data to be sent
    size_t data_sent; // total data sent
    size_t bytes_to_send; // bytes to send in one window
    size_t chunks; // number of packet chunks we need to send
    uint32_t calculated_checksum;
    microtcp_header_t outgoing_mtcp_header, *incoming_mtcp_header = (microtcp_header_t *)malloc(sizeof(microtcp_header_t)), internal_mtcp_header;
    uint8_t checksum_byte_arr[MICROTCP_MSS];
    uint8_t *packet = (uint8_t *)malloc(MICROTCP_MSS); // buffer for the packet to be sent
    size_t seq; // sequence number
    size_t starting_seq = socket->seq_number; // starting sequence number
    int i;
    struct timeval timeout;
    size_t last_ack = socket->seq_number; // last ack received
    int dup_ack; // duplicate acks counter
    int retransmit; // retransmission flag
    uint32_t incoming_checksum;

    if (buffer == NULL || length == 0) {
        if (buffer == NULL) {
            perror("[microtcp_send] Empty buffer\n");
        } else {
            perror("[microtcp_send] Zero length\n");
        }
        return 0;
    }

    seq = socket->seq_number;
    // _mark: dont know wtf setsockopt is
    timeout.tv_sec = 0;
    timeout.tv_usec = MICROTCP_ACK_TIMEOUT_US;
    if (setsockopt(socket->sd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof (struct timeval))) {
        socket->state = INVALID;
        perror("[microtcp_send] setsockopt failed\n");
        return 0;
    }
    dup_ack = 0;
    retransmit = 0;
    data_sent = 0;
    remaining = length;

    while (data_sent < length) {

        // min(socket->curr_win_size, socket->cwnd, remaining);
        bytes_to_send = ((socket->curr_win_size < socket->cwnd) ? socket->curr_win_size : socket->cwnd) < remaining ? ((socket->curr_win_size < socket->cwnd) ? socket->curr_win_size : socket->cwnd) : remaining;
        chunks = bytes_to_send / (MICROTCP_MSS - sizeof(microtcp_header_t));

        // send full chunks
        for (i = 0; i < chunks; i++) {

            // Construct packet to calculate checksum
            outgoing_mtcp_header.seq_number = htonl(seq);
            outgoing_mtcp_header.ack_number = htonl(0);
            outgoing_mtcp_header.control = htons(0);
            outgoing_mtcp_header.window = htons(MICROTCP_WIN_SIZE);
            outgoing_mtcp_header.data_len = htonl(MICROTCP_MSS - sizeof(microtcp_header_t));
            outgoing_mtcp_header.future_use0 = htonl(0);
            outgoing_mtcp_header.future_use1 = htonl(0);
            outgoing_mtcp_header.future_use2 = htonl(0);
            outgoing_mtcp_header.checksum = 0; // will be calculated next

            // calculate checksum
            for (int j = 0; j < MICROTCP_MSS; j++) {
                checksum_byte_arr[j] = 0;
            }
            memcpy(checksum_byte_arr, &outgoing_mtcp_header, sizeof(microtcp_header_t));
            memcpy(checksum_byte_arr + sizeof(microtcp_header_t), buffer + data_sent, MICROTCP_MSS - sizeof(microtcp_header_t));
            calculated_checksum = crc32(checksum_byte_arr, MICROTCP_MSS);
            outgoing_mtcp_header.checksum = htonl(calculated_checksum);

            // prepare full packet
            memcpy(packet, &outgoing_mtcp_header, sizeof(microtcp_header_t));
            memcpy(packet + sizeof(microtcp_header_t), buffer + data_sent, MICROTCP_MSS - sizeof(microtcp_header_t));

            // send packet
            sendto(socket->sd, packet, MICROTCP_MSS, 0, socket->peer_address, socket->peer_address_len);

            socket->seq_number += (MICROTCP_MSS - sizeof(microtcp_header_t));
            data_sent += (MICROTCP_MSS - sizeof(microtcp_header_t));
            seq += (MICROTCP_MSS - sizeof(microtcp_header_t));
        }

        // check for a semi-filled chunk
        if (bytes_to_send % (MICROTCP_MSS - sizeof(microtcp_header_t)) != 0) {
            chunks++;

            // Construct packet
            outgoing_mtcp_header.seq_number = htonl(seq);
            outgoing_mtcp_header.ack_number = htonl(0);
            outgoing_mtcp_header.control = htons(0);
            outgoing_mtcp_header.window = htons(MICROTCP_WIN_SIZE);
            outgoing_mtcp_header.data_len = htonl(bytes_to_send % (MICROTCP_MSS - sizeof(microtcp_header_t)));
            outgoing_mtcp_header.future_use0 = htonl(0);
            outgoing_mtcp_header.future_use1 = htonl(0);
            outgoing_mtcp_header.future_use2 = htonl(0);
            outgoing_mtcp_header.checksum = 0; // will be calculated next

            // calculate checksum
            for (int j = 0; j < sizeof(microtcp_header_t) + bytes_to_send % (MICROTCP_MSS - sizeof(microtcp_header_t)); j++) {
                checksum_byte_arr[j] = 0;
            }
            memcpy(checksum_byte_arr, &outgoing_mtcp_header, sizeof(microtcp_header_t));
            memcpy(checksum_byte_arr + sizeof(microtcp_header_t), buffer + data_sent, bytes_to_send % (MICROTCP_MSS - sizeof(microtcp_header_t)));
            calculated_checksum = crc32(checksum_byte_arr, sizeof(microtcp_header_t) + bytes_to_send % (MICROTCP_MSS - sizeof(microtcp_header_t)));
            outgoing_mtcp_header.checksum = htonl(calculated_checksum);

            // prepare full packet
            memcpy(packet, &outgoing_mtcp_header, sizeof(microtcp_header_t));
            memcpy(packet + sizeof(microtcp_header_t), buffer + data_sent, bytes_to_send % (MICROTCP_MSS - sizeof(microtcp_header_t)));

            // send packet
            sendto(socket->sd, packet, sizeof(microtcp_header_t) + bytes_to_send % (MICROTCP_MSS - sizeof(microtcp_header_t)), 0, socket->peer_address, socket->peer_address_len);

            socket->seq_number += bytes_to_send % (MICROTCP_MSS - sizeof(microtcp_header_t));
            data_sent += bytes_to_send % (MICROTCP_MSS - sizeof(microtcp_header_t));
            seq += bytes_to_send % (MICROTCP_MSS - sizeof(microtcp_header_t));
        }

        // get the acks
        for (i = 0; i < chunks; i++) {
            if (recvfrom(socket->sd, incoming_mtcp_header, sizeof(microtcp_header_t), 0, socket->peer_address, &socket->peer_address_len) < 0) {
                // Retransmission needed
                retransmit = 1;
                break;
            }

            incoming_checksum = ntohl(incoming_mtcp_header->checksum);
            incoming_mtcp_header->checksum = 0; // set to 0 for checksum calculation
            for (int j = 0; j < MICROTCP_MSS; j++) {
                checksum_byte_arr[j] = 0;
            }
            memcpy(checksum_byte_arr, incoming_mtcp_header, sizeof(microtcp_header_t));
            calculated_checksum = crc32(checksum_byte_arr, sizeof(microtcp_header_t));
            if (calculated_checksum != incoming_checksum) {
                // checksum mismatch, ignore ack
                i--;
                continue;
            } else if (ntohs(incoming_mtcp_header->control) != ACK) {
                // not an ack, ignore
                i--;
                continue;
            }

            // construct internal header
            internal_mtcp_header.seq_number = ntohl(incoming_mtcp_header->seq_number);
            internal_mtcp_header.ack_number = ntohl(incoming_mtcp_header->ack_number);
            internal_mtcp_header.control = ntohs(incoming_mtcp_header->control);
            internal_mtcp_header.window = ntohs(incoming_mtcp_header->window);
            internal_mtcp_header.data_len = ntohl(incoming_mtcp_header->data_len);
            internal_mtcp_header.future_use0 = 0;
            internal_mtcp_header.future_use1 = 0;
            internal_mtcp_header.future_use2 = 0;
            internal_mtcp_header.checksum = 0;

            // ack received
            if (last_ack == internal_mtcp_header.ack_number) {
                dup_ack++;
                if (dup_ack == 3) { // 3 duplicate acks, fast retransmit
                    break;
                }
                i--;
            } else {
                socket->curr_win_size = internal_mtcp_header.window;
                last_ack = internal_mtcp_header.ack_number;
                dup_ack = 0;
                if (socket->cwnd < socket->ssthresh) {
                    // slow start
                    socket->cwnd += MICROTCP_MSS;
                } else {
                    // congestion avoidance
                    socket->cwnd += (MICROTCP_MSS * MICROTCP_MSS) / socket->cwnd;
                }
            }
        }

        // process ACKs
        if (retransmit == 1) { // timeout occurred, retransmit
            socket->ssthresh = socket->cwnd / 2;
            // min(MICROTCP_MSS, socket->ssthresh);
            socket->cwnd = (MICROTCP_MSS > socket->ssthresh) ? socket->ssthresh : MICROTCP_MSS;
            if (socket->cwnd == 0) {
                socket->cwnd = 1;
            }
            // retransmit missing packet
            retransmit = 0;
            socket->seq_number = last_ack;
            data_sent = last_ack - starting_seq;
        } else if (dup_ack == 3) { // 3 duplicate acks, fast retransmit
            socket->ssthresh = socket->cwnd / 2;
            socket->cwnd = socket->cwnd / 2 + 1;
            // retransmit missing packet
            socket->seq_number = last_ack;
            data_sent = last_ack - starting_seq;
        } else { // all acks received, continue
            remaining -= bytes_to_send;
        }
        dup_ack = 0;
    }

    free(incoming_mtcp_header);
    free(packet);
    return data_sent;
}

ssize_t microtcp_recv(microtcp_sock_t *socket, void *buffer, size_t length, int flags) {
    size_t expected_sequence_number = socket->ack_number,
           mtcp_header_size = sizeof(microtcp_header_t),
           incoming_data_segment_size;
    int bytes_accumulated = 0,
        bytes_copied = 0,
        is_out_of_order = 0;
    ssize_t received_bytes, sent_bytes;
    uint8_t incoming_packet_buffer[MICROTCP_MSS + mtcp_header_size],
            packet_buffer_data_segment[MICROTCP_MSS],
            checksum_byte_arr[MICROTCP_MSS + mtcp_header_size];
    microtcp_header_t incoming_mtcp_header,
                      internal_mtcp_header,
                      outgoing_mtcp_header;
    uint32_t calculated_checksum;
    uint32_t incoming_checksum;


    while (bytes_copied < length) {
        // receive data. return -1 on error as per spec
        received_bytes = recvfrom(socket->sd, incoming_packet_buffer, MICROTCP_MSS + mtcp_header_size, 0, socket->peer_address, &socket->peer_address_len);
        if (received_bytes < 0) return -1;

        incoming_data_segment_size = received_bytes - mtcp_header_size;

        // direct incoming data to respective structures
        memcpy(&incoming_mtcp_header, incoming_packet_buffer, mtcp_header_size);
        memcpy(packet_buffer_data_segment, incoming_packet_buffer + mtcp_header_size, incoming_data_segment_size);

        incoming_checksum = ntohl(incoming_mtcp_header.checksum);
        incoming_mtcp_header.checksum = 0; // set to 0 for checksum calculation

        // calculate checksum
        for (int i = 0; i < MICROTCP_MSS + mtcp_header_size; i++) {
            checksum_byte_arr[i] = 0;
        }

        memcpy(checksum_byte_arr, &incoming_mtcp_header, mtcp_header_size);
        memcpy(checksum_byte_arr + mtcp_header_size, packet_buffer_data_segment, incoming_data_segment_size);

        calculated_checksum = crc32(checksum_byte_arr, mtcp_header_size + incoming_data_segment_size);
        if (calculated_checksum != incoming_checksum) {
            // checksum mismatch, ignore packet
            continue;
        }

        // construct internal header for checksum verification
        internal_mtcp_header.seq_number = ntohl(incoming_mtcp_header.seq_number);
        internal_mtcp_header.ack_number = ntohl(incoming_mtcp_header.ack_number);
        internal_mtcp_header.control = ntohs(incoming_mtcp_header.control);
        internal_mtcp_header.window = ntohs(incoming_mtcp_header.window);
        internal_mtcp_header.data_len = ntohl(incoming_mtcp_header.data_len);
        internal_mtcp_header.future_use0 = 0;
        internal_mtcp_header.future_use1 = 0;
        internal_mtcp_header.future_use2 = 0;
        internal_mtcp_header.checksum = 0;

        // check termination by peer
        if (internal_mtcp_header.control == FIN + ACK) {
            socket->state = CLOSING_BY_PEER;
            return -1;
        }

        // check ooo
        if (internal_mtcp_header.seq_number != expected_sequence_number) {
            is_out_of_order = 1;
        } else {
            is_out_of_order = 0;
        }

        // buffer flush check
        if (bytes_accumulated + incoming_data_segment_size > MICROTCP_RECVBUF_LEN && !is_out_of_order) {
            // flush buffer
            size_t bytes_to_copy = bytes_accumulated;

            // Ensure we do not copy more than what fits in the user buffer
            if (bytes_copied + bytes_to_copy > length) {
               bytes_to_copy = length - bytes_copied;
            }

            memcpy(buffer + bytes_copied, socket->recvbuf, bytes_to_copy);
            bytes_copied += bytes_to_copy;
            bytes_accumulated = 0;
        }

        // if in order, copy to user buffer
        if (!is_out_of_order) {
            memcpy(socket->recvbuf + bytes_accumulated, packet_buffer_data_segment, incoming_data_segment_size);
            bytes_accumulated += incoming_data_segment_size;
            expected_sequence_number += incoming_data_segment_size;
            socket->ack_number = expected_sequence_number;
        }

        // send ack
        outgoing_mtcp_header.seq_number = htonl(socket->seq_number);
        outgoing_mtcp_header.ack_number = htonl(socket->ack_number);
        outgoing_mtcp_header.control = htons(ACK);
        outgoing_mtcp_header.window = htons(MICROTCP_WIN_SIZE - bytes_accumulated); // advertise remaining buffer space
        outgoing_mtcp_header.data_len = htonl(0);
        outgoing_mtcp_header.future_use0 = htonl(0);
        outgoing_mtcp_header.future_use1 = htonl(0);
        outgoing_mtcp_header.future_use2 = htonl(0);
        outgoing_mtcp_header.checksum = 0; // will be calculated next

        // calculate ACK checksum
        for (int i = 0; i < mtcp_header_size; i++) {
            checksum_byte_arr[i] = 0;
        }
        memcpy(checksum_byte_arr, &outgoing_mtcp_header, mtcp_header_size);
        calculated_checksum = crc32(checksum_byte_arr, mtcp_header_size);
        outgoing_mtcp_header.checksum = htonl(calculated_checksum);

        // send ACK packet
        sent_bytes = sendto(socket->sd, &outgoing_mtcp_header, mtcp_header_size, 0, socket->peer_address, socket->peer_address_len);
        if (sent_bytes < 0) {
            perror("[microtcp_recv] sendto failed\n");
            return -1;
        }
    }

    // when out of the loop, copy any remaining accumulated data
    if (bytes_accumulated > 0 && bytes_copied < length) {
        size_t remaining_space = length - bytes_copied;
        size_t bytes_to_copy = (bytes_accumulated < remaining_space) ? bytes_accumulated : remaining_space;

        memcpy(buffer + bytes_copied, socket->recvbuf, bytes_to_copy);
        bytes_copied += bytes_to_copy;
    }

    return bytes_copied;
}
