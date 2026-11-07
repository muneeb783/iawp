#!/usr/bin/env bash
# One-time setup of the benchmark tools on the lab VM (Ubuntu, run with sudo).
#
# Installs nginx and stress-ng from the distribution, builds wrk2 from source
# (installed as /usr/local/bin/wrk2), and unpacks a pinned Lua release that
# the compile-noise loop builds over and over. Safe to run again.
set -euo pipefail

[[ $EUID -eq 0 ]] || { echo "run with sudo" >&2; exit 1; }
WORK=/var/tmp/iawp-bench
LUA=lua-5.4.7
LUA_SHA256=9fbf5e28ef86c69858f6d3d34eccc32e911c1a28b4120ff3e84aaa70cfbf1e30  # from https://www.lua.org/ftp/
mkdir -p "$WORK"

# No questions and no pseudo-terminal for dpkg: piped into `tail` or run from
# tmux, apt otherwise touches the terminal and the shell stops it (SIGTTOU).
export DEBIAN_FRONTEND=noninteractive
APT=(apt-get -y -qq -o Dpkg::Use-Pty=0 -o Dpkg::Options::=--force-confold)
"${APT[@]}" update
"${APT[@]}" install nginx stress-ng build-essential libssl-dev zlib1g-dev git curl luajit libluajit-5.1-dev
systemctl enable --now nginx

# wrk2 bundles LuaJIT 2.0, which crashes at start on current kernels ("PANIC:
# unprotected error in call to Lua API"). Build it against the distribution's
# LuaJIT 2.1 instead: its Makefile has no option for that, so point LDIR at a
# directory laid out like the bundled copy. -lluajit then links the shared library.
if [[ ! -f $WORK/wrk2.ok ]]; then
	rm -rf "$WORK/wrk2-src"
	git clone -q --depth 1 https://github.com/giltene/wrk2 "$WORK/wrk2-src"
	# OpenResty's LuaJIT 2.1 (Ubuntu's) dropped the old luaL_reg alias of luaL_Reg.
	sed -i 's/struct luaL_reg/struct luaL_Reg/' "$WORK/wrk2-src/src/script.c"
	LJ="$WORK/luajit-sys"
	LIBDIR="/usr/lib/$(gcc -print-multiarch)"
	rm -rf "$LJ" && mkdir -p "$LJ"
	ln -s /usr/include/luajit-2.1/*.h "$LJ"/
	ln -s "$(command -v luajit)" "$LJ/luajit"
	ln -s "$LIBDIR/libluajit-5.1.so" "$LJ/libluajit.so"
	ln -s "$LIBDIR/libluajit-5.1.a" "$LJ/libluajit.a"  # only to satisfy the Makefile's dependency
	make -C "$WORK/wrk2-src" -j"$(nproc)" LDIR="$LJ" >"$WORK/wrk2-build.log" 2>&1 ||
		{ echo "wrk2 build failed; see $WORK/wrk2-build.log" >&2; exit 1; }
	"$WORK/wrk2-src/wrk" -t1 -c1 -d3s -R10 http://127.0.0.1/ >"$WORK/wrk2-test.log" 2>&1 ||
		{ echo "wrk2 built but does not run; see $WORK/wrk2-test.log" >&2; exit 1; }
	install -m 755 "$WORK/wrk2-src/wrk" /usr/local/bin/wrk2
	touch "$WORK/wrk2.ok"
	echo "wrk2 built from commit $(git -C "$WORK/wrk2-src" rev-parse --short HEAD) with LuaJIT $(luajit -v | cut -d' ' -f2)"
fi

if [[ ! -d $WORK/lua/src ]]; then
	curl -fsSLo "$WORK/$LUA.tar.gz" "https://www.lua.org/ftp/$LUA.tar.gz"
	echo "$LUA_SHA256  $WORK/$LUA.tar.gz" | sha256sum --check --quiet
	tar -xzf "$WORK/$LUA.tar.gz" -C "$WORK"
	rm -rf "$WORK/lua" && mv "$WORK/$LUA" "$WORK/lua"
fi
make -s -C "$WORK/lua/src" -j"$(nproc)" linux >/dev/null && make -s -C "$WORK/lua/src" clean >/dev/null

curl -fsS -o /dev/null http://127.0.0.1/ && echo "nginx answers on http://127.0.0.1/"

# S2: PostgreSQL with a lab-only login role over TCP (127.0.0.1 uses password
# auth on Ubuntu), so the bench runs pgbench, pg_dump and psql as root without
# peer-auth trouble. Databases: bench (pgbench's tables plus the bulk-load
# target) and archive (what the backup loop dumps).
BENCH_SCALE=50     # ~750 MB, fits in memory: the scheduler, not the disk, shapes latency
ARCHIVE_SCALE=20   # ~300 MB: one compressed dump should take seconds, not the whole window
"${APT[@]}" install postgresql postgresql-contrib
systemctl enable --now postgresql
if ! command -v pgbench >/dev/null; then  # older postgresql-client-common has no wrapper for it
	ln -sf "$(ls -d /usr/lib/postgresql/*/bin/pgbench | sort -V | tail -1)" /usr/local/bin/pgbench
fi
PSQL=(sudo -u postgres psql -qXtA -v ON_ERROR_STOP=1)
[[ $("${PSQL[@]}" -c "select 1 from pg_roles where rolname = 'bench'") == 1 ]] ||
	"${PSQL[@]}" -c "create role bench login password 'bench'"
for db in bench archive; do
	[[ $("${PSQL[@]}" -c "select 1 from pg_database where datname = '$db'") == 1 ]] ||
		"${PSQL[@]}" -c "create database $db owner bench"
done
# Commits would otherwise wait for a flush to the VM's network disk, and that
# wait, not CPU scheduling, would dominate the tail.
"${PSQL[@]}" -c "alter database bench set synchronous_commit = off"
"${PSQL[@]}" -c "alter system set shared_buffers = '2GB'"
systemctl restart postgresql
for _ in $(seq 30); do pg_isready -q -h 127.0.0.1 && break; sleep 1; done
export PGHOST=127.0.0.1 PGUSER=bench PGPASSWORD=bench
if [[ ! -f $WORK/pg.ok ]]; then
	pgbench -i -q -s "$BENCH_SCALE" bench
	pgbench -i -q -s "$ARCHIVE_SCALE" archive
	psql -qX -v ON_ERROR_STOP=1 bench -c "\copy (select g, md5(g::text) || md5((g + 1)::text), now() from generate_series(1, 2000000) g) to '$WORK/bulk.csv' csv"
	touch "$WORK/pg.ok"
fi
# One table per parallel bulk load (run.py runs half the CPUs' worth). Unlogged:
# each load would otherwise write ~200 MB of WAL and compete with pgbench for
# the disk; S2 is about CPU scheduling.
for i in $(seq "$(nproc)"); do
	psql -qX -v ON_ERROR_STOP=1 bench -c "create unlogged table if not exists bulk_$i (id bigint, payload text, at timestamptz)"
done
SECONDS=0; pg_dump --no-sync -Fc -Z6 -f /dev/null archive; dump=$SECONDS
SECONDS=0; psql -qX -v ON_ERROR_STOP=1 -c 'TRUNCATE bulk_1' -c "\copy bulk_1 from '$WORK/bulk.csv' csv" bench; copy=$SECONDS
echo "postgres $(psql -XtAc 'show server_version' bench) answers; one backup takes ${dump} s, one bulk load ${copy} s (alone)"

echo "setup done: wrk2, stress-ng, nginx, $LUA in $WORK/lua, postgres with bench and archive databases"
