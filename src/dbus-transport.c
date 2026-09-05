#define _GNU_SOURCE
#include "dbus-transport.h"

#include <errno.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <unistd.h>

enum { CONTROLLER_TIMEOUT_MS = 30000, MAX_AUTH_LINE = 4096 };

static void close_nointr(int fd)
{
        if (fd >= 0)
                while (close(fd) < 0 && errno == EINTR)
                        ;
}

void dbus_transport_init(DBusTransport *transport, int fd)
{
        *transport = (DBusTransport){.fd = fd, .next_serial = 1};
}

void dbus_transport_clear(DBusTransport *transport)
{
        for (size_t i = 0; i < transport->n_received_fds; ++i)
                close_nointr(transport->received_fds[i]);
        str_buf_clear(&transport->incoming);
        if (transport->fd >= 0)
                close_nointr(transport->fd);
        *transport = (DBusTransport){.fd = -1};
}

static bool wait_fd(int fd, short events, Error **error)
{
        struct pollfd pollfd = {.fd = fd, .events = events};
        int result;
        do
                result = poll(&pollfd, 1, CONTROLLER_TIMEOUT_MS);
        while (result < 0 && errno == EINTR);
        if (result < 0)
                return error_set_errno(error, errno, "Cannot poll D-Bus controller");
        if (!result)
                return error_set(error, ETIMEDOUT, "D-Bus controller timed out");
        if (pollfd.revents & (POLLERR | POLLNVAL))
                return error_set(error, EIO, "D-Bus controller socket failed");
        return true;
}

static bool write_all(int fd, const void *data, size_t length, Error **error)
{
        const uint8_t *bytes = data;
        while (length) {
                ssize_t n = send(fd, bytes, length, MSG_NOSIGNAL);
                if (n > 0) {
                        bytes += n;
                        length -= (size_t)n;
                } else if (n < 0 && errno == EINTR) {
                        continue;
                } else if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
                        if (!wait_fd(fd, POLLOUT, error))
                                return false;
                } else {
                        return error_set_errno(error, n < 0 ? errno : EPIPE, "Cannot write D-Bus controller");
                }
        }
        return true;
}

static bool read_auth_line(int fd, char line[MAX_AUTH_LINE], Error **error)
{
        size_t length = 0;
        while (length + 1 < MAX_AUTH_LINE) {
                char byte;
                ssize_t n = recv(fd, &byte, 1, 0);
                if (n == 1) {
                        line[length++] = byte;
                        if (length >= 2 && line[length - 2] == '\r' && line[length - 1] == '\n') {
                                line[length - 2] = 0;
                                return true;
                        }
                } else if (n < 0 && errno == EINTR) {
                        continue;
                } else if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
                        if (!wait_fd(fd, POLLIN, error))
                                return false;
                } else {
                        return error_set_errno(error, n < 0 ? errno : ECONNRESET,
                                               "Cannot read D-Bus authentication response");
                }
        }
        return error_set(error, EOVERFLOW, "D-Bus authentication response is too long");
}

bool dbus_transport_authenticate(DBusTransport *transport, uid_t uid, Error **error)
{
        char identity[32], encoded[64], request[128], line[MAX_AUTH_LINE];
        int identity_length = snprintf(identity, sizeof(identity), "%lu", (unsigned long)uid);
        static const char hex[] = "0123456789abcdef";

        if (identity_length < 0 || (size_t)identity_length >= sizeof(identity))
                return error_set(error, EOVERFLOW, "Cannot encode D-Bus authentication identity");
        for (int i = 0; i < identity_length; ++i) {
                unsigned char byte = (unsigned char)identity[i];
                encoded[i * 2] = hex[byte >> 4];
                encoded[i * 2 + 1] = hex[byte & 15];
        }
        encoded[identity_length * 2] = 0;
        int formatted = snprintf(request + 1, sizeof(request) - 1, "AUTH EXTERNAL %s\r\n", encoded);
        size_t request_length = formatted > 0 ? (size_t)formatted + 1 : 0;
        request[0] = 0;
        if (!request_length || request_length >= sizeof(request) ||
            !write_all(transport->fd, request, request_length, error) || !read_auth_line(transport->fd, line, error))
                return false;
        if (strncmp(line, "OK ", 3) != 0)
                return error_set(error, EACCES, "D-Bus authentication rejected: %s", line);
        if (!write_all(transport->fd, "NEGOTIATE_UNIX_FD\r\n", 19, error) ||
            !read_auth_line(transport->fd, line, error))
                return false;
        if (strcmp(line, "AGREE_UNIX_FD") != 0)
                return error_set(error, EPROTONOSUPPORT, "D-Bus peer refused Unix FD passing: %s", line);
        return write_all(transport->fd, "BEGIN\r\n", 7, error);
}

uint32_t dbus_transport_next_serial(DBusTransport *transport)
{
        uint32_t serial = transport->next_serial++;
        if (!transport->next_serial)
                transport->next_serial = 1;
        return serial;
}

bool dbus_transport_send(DBusTransport *transport, const DBusWriter *message, const int *fds, size_t n_fds,
                         Error **error)
{
        size_t offset = 0;

        if (!message || !message->bytes.len || n_fds > 64)
                return error_set(error, EINVAL, "Invalid D-Bus message or file descriptor list");
        if (n_fds) {
                char control[CMSG_SPACE(sizeof(int) * 64)] = {0};
                struct iovec iov = {.iov_base = message->bytes.data, .iov_len = message->bytes.len};
                struct msghdr msg = {
                        .msg_iov = &iov,
                        .msg_iovlen = 1,
                        .msg_control = control,
                        .msg_controllen = CMSG_SPACE(sizeof(int) * n_fds),
                };
                struct cmsghdr *cmsg = CMSG_FIRSTHDR(&msg);
                cmsg->cmsg_level = SOL_SOCKET;
                cmsg->cmsg_type = SCM_RIGHTS;
                cmsg->cmsg_len = CMSG_LEN(sizeof(int) * n_fds);
                memcpy(CMSG_DATA(cmsg), fds, sizeof(int) * n_fds);
                for (;;) {
                        ssize_t n = sendmsg(transport->fd, &msg, MSG_NOSIGNAL);
                        if (n > 0) {
                                offset = (size_t)n;
                                break;
                        }
                        if (n < 0 && errno == EINTR)
                                continue;
                        if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
                                if (!wait_fd(transport->fd, POLLOUT, error))
                                        return false;
                                continue;
                        }
                        return error_set_errno(error, n < 0 ? errno : EPIPE, "Cannot send D-Bus message");
                }
        }
        return write_all(transport->fd, message->bytes.data + offset, message->bytes.len - offset, error);
}

static bool receive_more(DBusTransport *transport, Error **error)
{
        uint8_t bytes[65536];
        /* Aligned for the control messages parsed out of it below. */
        union {
                struct cmsghdr header;
                char bytes[CMSG_SPACE(sizeof(int) * 64)];
        } control;
        struct iovec iov = {.iov_base = bytes, .iov_len = sizeof(bytes)};
        struct msghdr msg;

        for (;;) {
                ssize_t n;
                /* recvmsg() rewrites msg_controllen, so it must be restored
                 * before every attempt or a retry would silently drop file
                 * descriptors. */
                msg = (struct msghdr){
                        .msg_iov = &iov,
                        .msg_iovlen = 1,
                        .msg_control = control.bytes,
                        .msg_controllen = sizeof(control.bytes),
                };
                n = recvmsg(transport->fd, &msg, MSG_CMSG_CLOEXEC);
                if (n > 0) {
                        for (struct cmsghdr *cmsg = CMSG_FIRSTHDR(&msg); cmsg; cmsg = CMSG_NXTHDR(&msg, cmsg)) {
                                if (cmsg->cmsg_level != SOL_SOCKET || cmsg->cmsg_type != SCM_RIGHTS)
                                        continue;
                                size_t count = (cmsg->cmsg_len - CMSG_LEN(0)) / sizeof(int);
                                if (count > 64 - transport->n_received_fds) {
                                        int *received = (int *)CMSG_DATA(cmsg);
                                        for (size_t i = 0; i < count; ++i)
                                                close_nointr(received[i]);
                                        return error_set(error, EOVERFLOW, "Too many queued D-Bus file descriptors");
                                }
                                memcpy(transport->received_fds + transport->n_received_fds, CMSG_DATA(cmsg),
                                       count * sizeof(int));
                                transport->n_received_fds += count;
                        }
                        /* Checked after collecting, so the descriptors that did
                         * fit are owned by the transport and get closed with it
                         * rather than leaked. */
                        if (msg.msg_flags & MSG_CTRUNC)
                                return error_set(error, EOVERFLOW, "Too many file descriptors in D-Bus message");
                        if (!str_buf_append_n(&transport->incoming, (char *)bytes, (size_t)n))
                                return error_set(error, ENOMEM, "Cannot buffer D-Bus message");
                        return true;
                }
                if (n < 0 && errno == EINTR)
                        continue;
                if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
                        if (!wait_fd(transport->fd, POLLIN, error))
                                return false;
                        continue;
                }
                return error_set_errno(error, n < 0 ? errno : ECONNRESET, "D-Bus controller disconnected");
        }
}

void dbus_packet_clear(DBusPacket *packet)
{
        dbus_header_clear(&packet->header);
        for (size_t i = 0; i < packet->n_fds; ++i)
                close_nointr(packet->fds[i]);
        free(packet->bytes);
        *packet = (DBusPacket){0};
}

bool dbus_transport_receive(DBusTransport *transport, DBusPacket *packet, Error **error)
{
        DBusHeader temporary = {0};
        DBusReader body;
        size_t consumed;

        dbus_packet_clear(packet);
        for (;;) {
                Error *parse_error = NULL;
                if (transport->incoming.len >= 16 &&
                    dbus_message_parse((uint8_t *)transport->incoming.data, transport->incoming.len, &temporary, &body,
                                       &consumed, &parse_error)) {
                        if (temporary.unix_fds > transport->n_received_fds) {
                                dbus_header_clear(&temporary);
                                return error_set(error, EPROTO,
                                                 "D-Bus message references unavailable file descriptors");
                        }
                        packet->bytes = malloc(consumed);
                        if (!packet->bytes) {
                                dbus_header_clear(&temporary);
                                return error_set(error, ENOMEM, "Cannot allocate D-Bus packet");
                        }
                        memcpy(packet->bytes, transport->incoming.data, consumed);
                        memmove(transport->incoming.data, transport->incoming.data + consumed,
                                transport->incoming.len - consumed);
                        transport->incoming.len -= consumed;
                        transport->incoming.data[transport->incoming.len] = 0;
                        packet->length = consumed;
                        packet->header = temporary;
                        temporary = (DBusHeader){0};
                        size_t body_offset;
                        uint32_t fields_length;
                        memcpy(&fields_length, packet->bytes + 12, sizeof(fields_length));
                        if (packet->bytes[0] == 'B')
                                fields_length = __builtin_bswap32(fields_length);
                        body_offset = (16 + (size_t)fields_length + 7) & ~(size_t)7;
                        packet->body = (DBusReader){
                                .bytes = packet->bytes + body_offset,
                                .length = packet->length - body_offset,
                                .little_endian = packet->bytes[0] == 'l',
                        };
                        packet->n_fds = packet->header.unix_fds;
                        memcpy(packet->fds, transport->received_fds, packet->n_fds * sizeof(int));
                        memmove(transport->received_fds, transport->received_fds + packet->n_fds,
                                (transport->n_received_fds - packet->n_fds) * sizeof(int));
                        transport->n_received_fds -= packet->n_fds;
                        return true;
                }
                if (parse_error && parse_error->code != EAGAIN) {
                        if (error)
                                *error = parse_error;
                        else
                                error_free(parse_error);
                        dbus_header_clear(&temporary);
                        return false;
                }
                error_free(parse_error);
                dbus_header_clear(&temporary);
                if (!receive_more(transport, error))
                        return false;
        }
}
