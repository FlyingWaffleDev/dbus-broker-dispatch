# shellcheck shell=sh
# Login-shell fallback for dinit user services when PAM integration is disabled.
# Requires an existing user supervisor with the dbus service registered and
# XDG_RUNTIME_DIR in its environment. See init/README.md for setup and paths.

if [ -z "${DBUS_SESSION_BUS_ADDRESS:-}" ] &&
	[ -n "${XDG_RUNTIME_DIR:-}" ] &&
	[ "${DBUS_BROKER_DISPATCH_INIT:-dinit}" = dinit ]; then
	_dbd_dinit_address() (
		# Keep temporary variables and external commands out of the login shell.
		case ${XDG_RUNTIME_DIR} in /*) ;; *) return 1 ;; esac
		[ -d "${XDG_RUNTIME_DIR}" ] || return 1
		dbd_socket=${XDG_RUNTIME_DIR}/bus
		if [ ! -S "${dbd_socket}" ]; then
			dbd_control=${DBUS_BROKER_DISPATCH_DINIT_SOCKET:-${XDG_RUNTIME_DIR}/dinitctl}
			case ${dbd_control} in /*) ;; *) return 1 ;; esac
			[ -S "${dbd_control}" ] || return 1
			command -v dinitctl >/dev/null 2>&1 || return 1
			command -v timeout >/dev/null 2>&1 || return 1
			# Force a user socket, even if DINIT_SOCKET_PATH names the system manager.
			# Bound an unresponsive control connection as well as service startup.
			timeout 5 dinitctl --user --socket-path "${dbd_control}" \
				start --no-wait dbus >/dev/null 2>&1 || return 1
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
	if dbd_address=$(_dbd_dinit_address); then
		export DBUS_SESSION_BUS_ADDRESS="${dbd_address}"
	fi
	unset dbd_address
	unset -f _dbd_dinit_address
fi
