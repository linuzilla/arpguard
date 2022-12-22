//
// Created by saber on 8/16/21.
//

#ifndef __PACKET_H
#define __PACKET_H

struct linux_packet_t {
    int (*fileDescriptor) ();
    void (*receive) (char *packet_buffer, size_t buffer_size, void (*callback) (int, ssize_t) );
};

struct linux_packet_t *new_linux_packet (const char *device);

#endif //___PACKET_H
