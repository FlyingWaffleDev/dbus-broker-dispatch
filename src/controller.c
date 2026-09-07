#include "controller.h"
#include "log.h"

#include <errno.h>
#include <stdlib.h>
#include <string.h>

/* Bounds the queue below. Only replies to in-flight calls are ever stored, so
 * the depth is the nesting depth of call(); anything beyond this is a broker
 * that is replying to serials we never sent. */
enum { MAX_PENDING_REPLIES = 64 };

void controller_reply_free(ControllerReply *reply)
{
        if (!reply)
                return;
        free(reply->error_name);
        free(reply->error_message);
        free(reply);
}

static void reply_destroy(void *data)
{
        controller_reply_free(data);
}

void controller_init(Controller *controller, int fd, ControllerPacketFunc packet_func, void *data)
{
        *controller = (Controller){.packet_func = packet_func, .packet_data = data};
        ptr_vec_init(&controller->pending_replies, reply_destroy);
        dbus_transport_init(&controller->transport, fd);
}

void controller_clear(Controller *controller)
{
        ptr_vec_clear(&controller->pending_replies);
        dbus_transport_clear(&controller->transport);
        *controller = (Controller){.transport.fd = -1};
}

/* Removes and returns the stored reply for serial, or NULL. */
ControllerReply *controller_take_reply(Controller *controller, uint32_t serial)
{
        for (size_t i = 0; i < controller->pending_replies.len; ++i) {
                ControllerReply *reply = controller->pending_replies.items[i];
                if (reply->serial == serial)
                        return ptr_vec_remove(&controller->pending_replies, i);
        }
        return NULL;
}

bool controller_store_reply(Controller *controller, const DBusPacket *packet, const char *message)
{
        ControllerReply *reply = calloc(1, sizeof(*reply));

        if (!reply)
                return false;
        reply->serial = packet->header.reply_serial;
        reply->is_error = packet->header.type == DBUS_MESSAGE_ERROR;
        if (reply->is_error) {
                reply->error_name = str_dup(packet->header.error_name ? packet->header.error_name : "D-Bus error");
                reply->error_message = str_dup(message);
                if (!reply->error_name || !reply->error_message) {
                        controller_reply_free(reply);
                        return false;
                }
        }
        while (controller->pending_replies.len >= MAX_PENDING_REPLIES) {
                ControllerReply *dropped = controller->pending_replies.items[0];
                log_warning("Discarding queued controller reply for serial %u; the call waiting for it will time out",
                            dropped->serial);
                ptr_vec_delete(&controller->pending_replies, 0);
        }
        if (!ptr_vec_push(&controller->pending_replies, reply)) {
                controller_reply_free(reply);
                return false;
        }
        return true;
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
        controller->dispatch_pending = false;
        /* Bound each pass so signals and timers remain responsive under load. */
        for (unsigned int i = 0; i < 32; ++i) {
                DBusPacket packet = {0};
                bool received, result;
                if (!dbus_transport_receive_ready(&controller->transport, &packet, &received, error))
                        return false;
                if (!received)
                        return true;
                result = dispatch_packet(controller, &packet, error);
                dbus_packet_clear(&packet);
                if (!result)
                        return false;
        }
        controller->dispatch_pending = true;
        return true;
}

/* Extracts an error message body, defaulting when the reply has no string. */
static const char *reply_error_message(DBusPacket *packet)
{
        const char *message = "Controller method failed";
        size_t length;

        if (packet->header.signature && strcmp(packet->header.signature, "s") == 0)
                dbus_reader_string(&packet->body, &message, &length);
        return message;
}

static bool call(Controller *controller, const char *path, const char *interface, const char *member,
                 const char *signature, const DBusWriter *body, const int *fds, size_t n_fds, Error **error)
{
        uint32_t serial = dbus_transport_next_serial(&controller->transport);

        /* A synchronous receive can also buffer packets after its reply.
         * Make the next event-loop wait nonblocking so those get dispatched. */
        controller->dispatch_pending = true;
        if (!send_message(controller, DBUS_MESSAGE_METHOD_CALL, serial, 0, path, interface, member, NULL, signature,
                          body, fds, n_fds, error))
                return false;
        for (;;) {
                DBusPacket packet = {0};
                ControllerReply *stored;
                bool result, is_reply;

                /* A nested call may already have read and parked our reply. */
                stored = controller_take_reply(controller, serial);
                if (stored) {
                        bool failed = stored->is_error;
                        if (failed)
                                error_set(error, EPROTO, "%s: %s", stored->error_name, stored->error_message);
                        controller_reply_free(stored);
                        return !failed;
                }
                if (!dbus_transport_receive(&controller->transport, &packet, error))
                        return false;
                is_reply = packet.header.type == DBUS_MESSAGE_METHOD_RETURN || packet.header.type == DBUS_MESSAGE_ERROR;
                if (is_reply && packet.header.reply_serial == serial) {
                        if (packet.header.type == DBUS_MESSAGE_ERROR) {
                                error_set(error, EPROTO, "%s: %s",
                                          packet.header.error_name ? packet.header.error_name : "D-Bus error",
                                          reply_error_message(&packet));
                                dbus_packet_clear(&packet);
                                return false;
                        }
                        dbus_packet_clear(&packet);
                        return true;
                }
                if (is_reply) {
                        /* Belongs to an outer call; park it instead of dropping it. */
                        if (!controller_store_reply(controller, &packet, reply_error_message(&packet))) {
                                dbus_packet_clear(&packet);
                                return error_set(error, ENOMEM, "Cannot queue controller reply");
                        }
                        dbus_packet_clear(&packet);
                        continue;
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
        if (!dbus_writer_string(&body, message)) {
                dbus_writer_clear(&body);
                return error_set(error, ENOMEM, "Cannot encode controller error reply");
        }
        result = send_message(controller, DBUS_MESSAGE_ERROR, dbus_transport_next_serial(&controller->transport),
                              reply_serial, NULL, NULL, NULL, name, "s", &body, NULL, 0, error);
        dbus_writer_clear(&body);
        return result;
}
