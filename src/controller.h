#pragma once

#include "dbus-transport.h"

typedef struct Controller Controller;
typedef bool (*ControllerPacketFunc)(Controller *controller, DBusPacket *packet, void *data, Error **error);

/* A reply that arrived while a different call was waiting for its own. Nested
 * calls happen whenever a dispatched packet issues one, so replies must be
 * matched by serial rather than assumed to arrive in call order. */
typedef struct ControllerReply {
        uint32_t serial;
        bool is_error;
        char *error_name;
        char *error_message;
} ControllerReply;

struct Controller {
        DBusTransport transport;
        ControllerPacketFunc packet_func;
        void *packet_data;
        PtrVec pending_replies;
};

/* Reply-queue operations, exposed for the reply-ordering test. */
void controller_reply_free(ControllerReply *reply);
bool controller_store_reply(Controller *controller, const DBusPacket *packet, const char *message);
ControllerReply *controller_take_reply(Controller *controller, uint32_t serial);

void controller_init(Controller *controller, int fd, ControllerPacketFunc packet_func, void *data);
void controller_clear(Controller *controller);
bool controller_authenticate(Controller *controller, uid_t uid, Error **error);
int controller_fd(const Controller *controller);
bool controller_dispatch(Controller *controller, Error **error);

bool controller_add_name(Controller *controller, const char *path, const char *name, uid_t uid, Error **error);
bool controller_release(Controller *controller, const char *path, Error **error);
bool controller_reset(Controller *controller, const char *path, uint64_t serial, const char *reason, Error **error);
bool controller_add_listener(Controller *controller, const char *path, int listener_fd, const char *policy_signature,
                             const DBusWriter *policy, Error **error);
bool controller_set_policy(Controller *controller, const char *path, const char *policy_signature,
                           const DBusWriter *policy, Error **error);
bool controller_reply(Controller *controller, uint32_t reply_serial, Error **error);
bool controller_reply_error(Controller *controller, uint32_t reply_serial, const char *name, const char *message,
                            Error **error);
