# shellcheck shell=sh
# Start and publish the standard per-user D-Bus bus for login shells.
#
# This is the fallback integration used when the package is built without PAM.
# OpenRC user services run in a separate process tree, so their environment
# cannot propagate back into the login session. Start the service first, then
# export its address only after the listener is ready.

if [ -z "${DBUS_SESSION_BUS_ADDRESS:-}" ] &&
	[ -n "${XDG_RUNTIME_DIR:-}" ] &&
	[ "${DBUS_BROKER_DISPATCH_INIT:-openrc}" = openrc ]; then
	dbus_socket="${XDG_RUNTIME_DIR}/bus"

	if [ ! -S "${dbus_socket}" ] && command -v rc-service >/dev/null 2>&1 &&
		rc-service --user dbus start >/dev/null 2>&1; then
		dbus_wait=0
		while [ ! -S "${dbus_socket}" ] && [ "${dbus_wait}" -lt 50 ]; do
			sleep 0.1
			dbus_wait=$((dbus_wait + 1))
		done
	fi

	if [ -S "${dbus_socket}" ]; then
		export DBUS_SESSION_BUS_ADDRESS="unix:path=${dbus_socket}"
	fi

	unset dbus_socket dbus_wait
fi
