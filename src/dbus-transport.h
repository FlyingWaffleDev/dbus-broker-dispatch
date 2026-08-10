#pragma once

#include "dbus-wire.h"

#include <sys/types.h>

typedef struct DBusTransport {
        int fd;
        uint32_t next_serial;
        StrBuf incoming;
        int received_fds[64];
        size_t n_received_fds;
} DBusTransport;

typedef struct DBusPacket {
        uint8_t *bytes;
        size_t length;
        DBusHeader header;
        DBusReader body;
        int fds[64];
        size_t n_fds;
} DBusPacket;

void dbus_transport_init(DBusTransport *transport, int fd);
void dbus_transport_clear(DBusTransport *transport);
bool dbus_transport_authenticate(DBusTransport *transport, uid_t uid, Error **error);
uint32_t dbus_transport_next_serial(DBusTransport *transport);
bool dbus_transport_send(DBusTransport *transport, const DBusWriter *message, const int *fds, size_t n_fds,
                         Error **error);
bool dbus_transport_receive(DBusTransport *transport, DBusPacket *packet, Error **error);
void dbus_packet_clear(DBusPacket *packet);
