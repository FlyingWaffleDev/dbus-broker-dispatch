#include "controller.h"

#include <errno.h>
#include <string.h>

void controller_init(Controller *controller, int fd, ControllerPacketFunc packet_func, void *data)
{
        *controller = (Controller){.packet_func = packet_func, .packet_data = data};
        dbus_transport_init(&controller->transport, fd);
}

void controller_clear(Controller *controller)
{
        dbus_transport_clear(&controller->transport);
        *controller = (Controller){.transport.fd = -1};
}

bool controller_authenticate(Controller *controller, uid_t uid, Error **error)
{
        return dbus_transport_authenticate(&controller->transport, uid, error);
}

int controller_fd(const Controller *controller)
{
        return controller->transport.fd;
}

static bool send_message(Controller *controller, uint8_t type, uint32_t serial, uint32_t reply_serial, const char *path,
                         const char *interface, const char *member, const char *error_name, const char *signature,
                         const DBusWriter *body, const int *fds, size_t n_fds, Error **error)
{
        DBusWriter message = {0};
        bool result;
        if (!dbus_message_build(&message, type, 0, serial, reply_serial, path, interface, member, NULL, error_name,
                                signature, (uint32_t)n_fds, body, error))
                return false;
        result = dbus_transport_send(&controller->transport, &message, fds, n_fds, error);
        dbus_writer_clear(&message);
        return result;
}

static bool dispatch_packet(Controller *controller, DBusPacket *packet, Error **error)
{
        if (!controller->packet_func)
                return true;
        return controller->packet_func(controller, packet, controller->packet_data, error);
}

bool controller_dispatch(Controller *controller, Error **error)
{
        DBusPacket packet = {0};
        bool result;
        if (!dbus_transport_receive(&controller->transport, &packet, error))
                return false;
        result = dispatch_packet(controller, &packet, error);
        dbus_packet_clear(&packet);
        return result;
}

static bool call(Controller *controller, const char *path, const char *interface, const char *member,
                 const char *signature, const DBusWriter *body, const int *fds, size_t n_fds, Error **error)
{
        uint32_t serial = dbus_transport_next_serial(&controller->transport);

        if (!send_message(controller, DBUS_MESSAGE_METHOD_CALL, serial, 0, path, interface, member, NULL, signature,
                          body, fds, n_fds, error))
                return false;
        for (;;) {
                DBusPacket packet = {0};
                bool result;
                if (!dbus_transport_receive(&controller->transport, &packet, error))
                        return false;
                if ((packet.header.type == DBUS_MESSAGE_METHOD_RETURN || packet.header.type == DBUS_MESSAGE_ERROR) &&
                    packet.header.reply_serial == serial) {
                        if (packet.header.type == DBUS_MESSAGE_ERROR) {
                                const char *message = "Controller method failed";
                                size_t length;
                                if (packet.header.signature && strcmp(packet.header.signature, "s") == 0)
                                        dbus_reader_string(&packet.body, &message, &length);
                                error_set(error, EPROTO, "%s: %s",
                                          packet.header.error_name ? packet.header.error_name : "D-Bus error", message);
                                dbus_packet_clear(&packet);
                                return false;
                        }
                        dbus_packet_clear(&packet);
                        return true;
                }
                result = dispatch_packet(controller, &packet, error);
                dbus_packet_clear(&packet);
                if (!result)
                        return false;
        }
}

bool controller_add_name(Controller *controller, const char *path, const char *name, uid_t uid, Error **error)
{
        DBusWriter body = {0};
        bool result;
        if (!dbus_writer_object_path(&body, path) || !dbus_writer_string(&body, name) ||
            !dbus_writer_u32(&body, (uint32_t)uid)) {
                dbus_writer_clear(&body);
                return error_set(error, ENOMEM, "Cannot encode AddName call");
        }
        result = call(controller, "/org/bus1/DBus/Broker", "org.bus1.DBus.Broker", "AddName", "osu", &body, NULL, 0,
                      error);
        dbus_writer_clear(&body);
        return result;
}

bool controller_release(Controller *controller, const char *path, Error **error)
{
        return call(controller, path, "org.bus1.DBus.Name", "Release", NULL, NULL, NULL, 0, error);
}

bool controller_reset(Controller *controller, const char *path, uint64_t serial, const char *reason, Error **error)
{
        DBusWriter body = {0};
        bool result;
        if (!dbus_writer_u64(&body, serial) || !dbus_writer_string(&body, reason)) {
                dbus_writer_clear(&body);
                return error_set(error, ENOMEM, "Cannot encode Reset call");
        }
        result = call(controller, path, "org.bus1.DBus.Name", "Reset", "ts", &body, NULL, 0, error);
        dbus_writer_clear(&body);
        return result;
}

bool controller_add_listener(Controller *controller, const char *path, int listener_fd, const char *policy_signature,
                             const DBusWriter *policy, Error **error)
{
        DBusWriter body = {0};
        bool result;
        if (!dbus_writer_object_path(&body, path) || !dbus_writer_u32(&body, 0) ||
            !dbus_writer_variant_begin(&body, policy_signature, 8) ||
            !str_buf_append_n(&body.bytes, policy->bytes.data, policy->bytes.len)) {
                dbus_writer_clear(&body);
                return error_set(error, ENOMEM, "Cannot encode AddListener call");
        }
        result = call(controller, "/org/bus1/DBus/Broker", "org.bus1.DBus.Broker", "AddListener", "ohv", &body,
                      &listener_fd, 1, error);
        dbus_writer_clear(&body);
        return result;
}

bool controller_set_policy(Controller *controller, const char *path, const char *policy_signature,
                           const DBusWriter *policy, Error **error)
{
        DBusWriter body = {0};
        bool result;
        if (!dbus_writer_variant_begin(&body, policy_signature, 8) ||
            !str_buf_append_n(&body.bytes, policy->bytes.data, policy->bytes.len)) {
                dbus_writer_clear(&body);
                return error_set(error, ENOMEM, "Cannot encode SetPolicy call");
        }
        result = call(controller, path, "org.bus1.DBus.Listener", "SetPolicy", "v", &body, NULL, 0, error);
        dbus_writer_clear(&body);
        return result;
}

bool controller_reply(Controller *controller, uint32_t reply_serial, Error **error)
{
        return send_message(controller, DBUS_MESSAGE_METHOD_RETURN, dbus_transport_next_serial(&controller->transport),
                            reply_serial, NULL, NULL, NULL, NULL, NULL, NULL, NULL, 0, error);
}

bool controller_reply_error(Controller *controller, uint32_t reply_serial, const char *name, const char *message,
                            Error **error)
{
        DBusWriter body = {0};
        bool result;
        if (!dbus_writer_string(&body, message))
                return error_set(error, ENOMEM, "Cannot encode controller error reply");
        result = send_message(controller, DBUS_MESSAGE_ERROR, dbus_transport_next_serial(&controller->transport),
                              reply_serial, NULL, NULL, NULL, name, "s", &body, NULL, 0, error);
        dbus_writer_clear(&body);
        return result;
}
