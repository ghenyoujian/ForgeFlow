#!/usr/bin/env bash
set -euo pipefail
# User-owned PostgreSQL installation and cluster; never alters system services.
cache=${FORGEFLOW_PG_CACHE:-"${XDG_CACHE_HOME:-$HOME/.cache}/forgeflow-postgres"}
state=${FORGEFLOW_PG_STATE:-"${XDG_STATE_HOME:-$HOME/.local/state}/forgeflow/postgres"}
port=${FORGEFLOW_PG_PORT:-55432}
mkdir -p "$cache/packages" "$state"
chmod 700 "$state"
if [[ ! -x "$cache/root/usr/lib/postgresql/16/bin/postgres" ]]; then
  (cd "$cache/packages" && apt download postgresql-16 postgresql-client-16 libpq5)
  for package in "$cache"/packages/*.deb; do dpkg-deb -x "$package" "$cache/root"; done
fi
export PATH="$cache/root/usr/lib/postgresql/16/bin:$PATH"
export LD_LIBRARY_PATH="$cache/root/usr/lib/x86_64-linux-gnu:${LD_LIBRARY_PATH:-}"
command=${1:-start}
case "$command" in
  start)
    if [[ ! -s "$state/cluster/PG_VERSION" ]]; then
      initdb -D "$state/cluster" --auth-local=trust --auth-host=scram-sha-256 --username=forgeflow --no-locale --encoding=UTF8
      printf '\nlisten_addresses = '\''127.0.0.1'\''\nport = %s\nunix_socket_directories = '\''%s'\''\n' "$port" "$state" >> "$state/cluster/postgresql.conf"
    fi
    # pg_ctl -l is only a startup log; the server collector owns operational
    # logs so logrotate can reopen them without copying/truncating a live file.
    cat > "$state/cluster/forgeflow-logging.conf" <<'CONFIG'
logging_collector = on
log_destination = 'stderr'
log_directory = 'log'
log_filename = 'postgres.log'
log_rotation_age = 0
log_rotation_size = 0
CONFIG
    if ! rg -q "^include_if_exists = 'forgeflow-logging.conf'$" "$state/cluster/postgresql.conf"; then
      printf "\ninclude_if_exists = 'forgeflow-logging.conf'\n" >> "$state/cluster/postgresql.conf"
    fi
    chmod 600 "$state/cluster/forgeflow-logging.conf"
    pg_ctl -D "$state/cluster" status >/dev/null 2>&1 || pg_ctl -D "$state/cluster" -l "$state/postgres.log" -w start
    psql -h "$state" -p "$port" -U forgeflow -d postgres -tAc "SELECT 1 FROM pg_database WHERE datname='forgeflow'" | rg -q '^1$' || createdb -h "$state" -p "$port" -U forgeflow forgeflow
    printf 'DATABASE_URL=postgresql://forgeflow@localhost:%s/forgeflow?host=%s\n' "$port" "$state"
    ;;
  stop) pg_ctl -D "$state/cluster" -m fast -w stop ;;
  status) pg_ctl -D "$state/cluster" status ;;
  install-log-rotation)
    command -v logrotate >/dev/null
    # Seven rotated operational logs; original historical logs and canonical
    # execution evidence are archived separately before first enabling this.
    config="$state/logrotate.conf"
    cat > "$config" <<CONFIG
"$state/cluster/log/postgres.log" {
    daily
    maxsize 16M
    rotate 7
    compress
    delaycompress
    missingok
    notifempty
    create 0600
    postrotate
        LD_LIBRARY_PATH="$cache/root/usr/lib/x86_64-linux-gnu" "$cache/root/usr/lib/postgresql/16/bin/psql" -X -h "$state" -p "$port" -U forgeflow -d postgres -v ON_ERROR_STOP=1 -Atc 'SELECT pg_rotate_logfile()' >/dev/null
    endscript
}
CONFIG
    chmod 600 "$config"
    units="${XDG_CONFIG_HOME:-$HOME/.config}/systemd/user"
    mkdir -p "$units"
    cat > "$units/forgeflow-postgres-logrotate.service" <<CONFIG
[Unit]
Description=Rotate bounded ForgeFlow PostgreSQL operational logs
After=forgeflow-postgres.service
[Service]
Type=oneshot
ExecStart=/usr/sbin/logrotate --state "$state/logrotate.state" "$config"
UMask=0077
CONFIG
    cat > "$units/forgeflow-postgres-logrotate.timer" <<'CONFIG'
[Unit]
Description=Hourly ForgeFlow PostgreSQL log size and retention check
[Timer]
OnCalendar=hourly
Persistent=true
RandomizedDelaySec=60
[Install]
WantedBy=timers.target
CONFIG
    systemctl --user daemon-reload
    systemctl --user enable --now forgeflow-postgres-logrotate.timer
    ;;
  *) printf 'Usage: %s [start|stop|status|install-log-rotation]\n' "$0" >&2; exit 2 ;;
esac
