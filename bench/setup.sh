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

apt-get update -qq
apt-get install -y -qq nginx stress-ng build-essential libssl-dev zlib1g-dev git curl luajit libluajit-5.1-dev
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
echo "setup done: wrk2, stress-ng, nginx, $LUA in $WORK/lua"
