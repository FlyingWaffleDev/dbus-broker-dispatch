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
	_dbd_openrc_address() (
		# Keep temporary variables and external commands out of the login shell.
		case ${XDG_RUNTIME_DIR} in /*) ;; *) return 1 ;; esac
		[ -d "${XDG_RUNTIME_DIR}" ] || return 1
		dbd_socket=${XDG_RUNTIME_DIR}/bus
		if [ ! -S "${dbd_socket}" ]; then
			command -v rc-service >/dev/null 2>&1 || return 1
			command -v timeout >/dev/null 2>&1 || return 1
			timeout 5 rc-service --user dbus start >/dev/null 2>&1 || return 1
			dbd_wait=0
			while [ ! -S "${dbd_socket}" ] && [ "${dbd_wait}" -lt 50 ]; do
				sleep 0.1
				dbd_wait=$((dbd_wait + 1))
			done
		fi
		[ -S "${dbd_socket}" ] || return 1
		# Percent-encode every byte so unusual runtime paths remain valid addresses.
		dbd_path=$(printf '%s' "${dbd_socket}" | LC_ALL=C od -An -v -tx1 |
			LC_ALL=C awk '{ for (i = 1; i <= NF; i++) printf "%%%s", $i }')
		[ -n "${dbd_path}" ] || return 1
		printf 'unix:path=%s' "${dbd_path}"
	)
	if dbd_address=$(_dbd_openrc_address); then
		export DBUS_SESSION_BUS_ADDRESS="${dbd_address}"
	fi
	unset dbd_address
	unset -f _dbd_openrc_address
fi
