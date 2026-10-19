"""Build eval/processes.jsonl, the labelled process set every classifier is scored on.

Each record is the redacted state a model sees, plus the correct label.
Edit labels here and rerun (`python3 eval/build.py`), so the reasoning stays
next to the data. `judgment=True` marks labels reasonable people could argue.

Label `unknown` means nobody could tell from outside: the right answer is
"not enough information", and a confident guess counts as wrong.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from iawp.redact import redact_args  # noqa: E402

SESSION = "user.slice/user-1000.slice/session-4.scope"
DOCKER = "system.slice/docker-3f9c2a7be1d04c6a9f2b8e5d7c1a0b4e6f8d2c9a1b3e5f7d9c2a4b6e8f0a1c3d.scope"
K8S = ("kubepods.slice/kubepods-burstable.slice/kubepods-burstable-pod7c1e2f3a_4b5d_6e7f_8a9b_0c1d2e3f4a5b.slice/"
       "cri-containerd-9a8b7c6d5e4f3a2b1c0d9e8f7a6b5c4d3e2f1a0b9c8d7e6f5a4b3c2d1e0f9a8b.scope")

RECORDS: list[dict] = []


def rec(label, comm, cmd, *, exe=None, parent="systemd", cgroup="", user="root", judgment=False, note=""):
    argv = cmd if isinstance(cmd, list) else cmd.split(" ")
    if exe is None:
        first = argv[0]
        exe = first if first.startswith("/") else f"/usr/bin/{first.rsplit('/', 1)[-1]}"
    RECORDS.append({
        "id": f"p{len(RECORDS) + 1:03d}",
        "label": label,
        "judgment": judgment,
        "note": note,
        "state": {
            "process_name": comm[:15],  # the kernel truncates comm to 15 characters
            "executable": exe,
            "command_line": " ".join(redact_args(argv)),
            "parent_process": parent,
            "cgroup": cgroup,
            "user": user,
        },
    })


def svc(label, comm, cmd, unit=None, **kw):
    """A systemd service in its own cgroup."""
    kw.setdefault("cgroup", f"system.slice/{unit or comm}.service")
    rec(label, comm, cmd, **kw)


def shell(label, comm, cmd, **kw):
    """Something a person started from a login shell."""
    kw.setdefault("cgroup", SESSION)
    kw.setdefault("parent", "bash")
    kw.setdefault("user", "dev")
    rec(label, comm, cmd, **kw)


def docker(label, comm, cmd, **kw):
    kw.setdefault("cgroup", DOCKER)
    kw.setdefault("parent", "containerd-shim")
    rec(label, comm, cmd, **kw)


def pod(label, comm, cmd, **kw):
    kw.setdefault("cgroup", K8S)
    kw.setdefault("parent", "containerd-shim")
    rec(label, comm, cmd, **kw)


def cron(label, comm, cmd, **kw):
    kw.setdefault("cgroup", "system.slice/cron.service")
    kw.setdefault("parent", "cron")
    rec(label, comm, cmd, **kw)


LC, IA, BC, IO, BG, UNK = "latency-critical", "interactive", "batch-compute", "io-data", "background", "unknown"

# ---------------------------------------------------------------- latency-critical
svc(LC, "nginx", "nginx: master process /usr/sbin/nginx -g daemon on; master_process on;", exe="/usr/sbin/nginx")
svc(LC, "nginx", ["nginx: worker process"], exe="/usr/sbin/nginx", parent="nginx", user="www-data")
svc(LC, "haproxy", "/usr/sbin/haproxy -Ws -f /etc/haproxy/haproxy.cfg -p /run/haproxy.pid -S /run/haproxy-master.sock")
svc(LC, "caddy", "/usr/bin/caddy run --environ --config /etc/caddy/Caddyfile", user="caddy")
svc(LC, "apache2", "/usr/sbin/apache2 -k start", user="www-data", parent="apache2")
svc(LC, "postgres", "/usr/lib/postgresql/16/bin/postgres -D /var/lib/postgresql/16/main -c config_file=/etc/postgresql/16/main/postgresql.conf",
    unit="postgresql@16-main", user="postgres")
svc(LC, "postgres", ["postgres: 16/main: app appdb 10.0.4.17(51522) idle"], exe="/usr/lib/postgresql/16/bin/postgres",
    unit="postgresql@16-main", user="postgres", parent="postgres", note="a client connection's backend")
svc(LC, "mysqld", "/usr/sbin/mysqld", unit="mysql", user="mysql")
svc(LC, "mariadbd", "/usr/sbin/mariadbd", unit="mariadb", user="mysql")
svc(LC, "redis-server", "/usr/bin/redis-server 127.0.0.1:6379", user="redis")
svc(LC, "memcached", "/usr/bin/memcached -m 64 -p 11211 -u memcache -l 127.0.0.1 -P /var/run/memcached/memcached.pid", user="memcache")
svc(LC, "mongod", "/usr/bin/mongod --config /etc/mongod.conf", user="mongodb")
svc(LC, "pgbouncer", "/usr/sbin/pgbouncer /etc/pgbouncer/pgbouncer.ini", user="postgres")
svc(LC, "named", "/usr/sbin/named -f -u bind", unit="named", user="bind")
svc(LC, "unbound", "/usr/sbin/unbound -d -p", user="unbound")
svc(LC, "dnsmasq", "/usr/sbin/dnsmasq -k --conf-file=/etc/dnsmasq.conf", user="dnsmasq")
svc(LC, "php-fpm8.3", "php-fpm: master process (/etc/php/8.3/fpm/php-fpm.conf)", exe="/usr/sbin/php-fpm8.3", unit="php8.3-fpm")
svc(LC, "php-fpm8.3", ["php-fpm: pool www"], exe="/usr/sbin/php-fpm8.3", unit="php8.3-fpm", user="www-data", parent="php-fpm8.3")
svc(LC, "gunicorn", "/srv/shop/venv/bin/python3 /srv/shop/venv/bin/gunicorn --workers 4 --bind unix:/run/shop.sock shop.wsgi:application",
    exe="/usr/bin/python3.12", unit="shop", user="shop")
svc(LC, "gunicorn", ["gunicorn: worker [shop.wsgi:application]"], exe="/usr/bin/python3.12", unit="shop", user="shop", parent="gunicorn")
docker(LC, "uvicorn", "/usr/local/bin/python /usr/local/bin/uvicorn app.main:app --host 0.0.0.0 --port 8000", exe="/usr/local/bin/python3.12")
docker(LC, "puma 6.4.2 (tc", ["puma 6.4.2 (tcp://0.0.0.0:3000) [app]"], exe="/usr/local/bin/ruby")
docker(LC, "node", "node /app/dist/server.js", exe="/usr/local/bin/node", user="node")
docker(LC, "java", "java -Xms512m -Xmx2g -jar /app/orders-api.jar --server.port=8080", exe="/opt/java/openjdk/bin/java")
docker(LC, "envoy", "envoy -c /etc/envoy/envoy.yaml --service-cluster front-proxy", exe="/usr/local/bin/envoy", user="envoy")
docker(LC, "traefik", "traefik --providers.docker=true --entrypoints.web.address=:80", exe="/usr/local/bin/traefik")
pod(LC, "kube-apiserver", "kube-apiserver --advertise-address=10.0.0.10 --etcd-servers=https://127.0.0.1:2379 --secure-port=6443",
    exe="/usr/local/bin/kube-apiserver")
pod(LC, "etcd", "etcd --data-dir=/var/lib/etcd --listen-client-urls=https://127.0.0.1:2379", exe="/usr/local/bin/etcd")
pod(LC, "coredns", "/coredns -conf /etc/coredns/Corefile", exe="/coredns")
pod(LC, "payments-grpc", "/app/payments-grpc --port 50051 --db-dsn postgres://pay:hunter2@db:5432/pay", exe="/app/payments-grpc")
pod(LC, "checkout", "/usr/local/bin/checkout serve --listen :8080", exe="/usr/local/bin/checkout", note="Go service, 'serve' subcommand")
docker(LC, "nats-server", "nats-server --jetstream -m 8222", exe="/nats-server")
svc(LC, "ollama", "/usr/local/bin/ollama serve", user="ollama")
docker(LC, "python3", "python3 -m vllm.entrypoints.openai.api_server --model meta-llama/Llama-3.1-8B-Instruct --port 8000",
       exe="/usr/bin/python3.11")
docker(LC, "beam.smp", "/usr/lib/erlang/erts-14.2/bin/beam.smp -W w -MBas ageffcbf -- -root /usr/lib/erlang -progname erl -- -home /var/lib/rabbitmq",
       user="rabbitmq", judgment=True, note="RabbitMQ broker: clients wait on publish/consume")
svc(LC, "java", "/usr/bin/java -Xmx4G -Xms4G -server -XX:+UseG1GC -cp /opt/kafka/libs/* kafka.Kafka /opt/kafka/config/server.properties",
    unit="kafka", user="kafka", judgment=True, note="Kafka broker: producers block on acks")
svc(LC, "java", "/usr/share/elasticsearch/jdk/bin/java -Xms8g -Xmx8g -XX:+UseG1GC -cp /usr/share/elasticsearch/lib/* org.elasticsearch.bootstrap.Elasticsearch",
    unit="elasticsearch", user="elasticsearch", judgment=True, note="search queries; also bulk indexing")
svc(LC, "clickhouse-serv", "/usr/bin/clickhouse-server --config=/etc/clickhouse-server/config.xml", unit="clickhouse-server",
    user="clickhouse", judgment=True, note="analytics DB: queries are interactive but heavy")
svc(LC, "grafana", "/usr/share/grafana/bin/grafana server --config=/etc/grafana/grafana.ini", unit="grafana-server",
    user="grafana", judgment=True, note="people wait on dashboards")
svc(LC, "keepalived", "/usr/sbin/keepalived --dont-fork", judgment=True, note="failover heartbeats are timing sensitive")
svc(LC, "slapd", "/usr/sbin/slapd -h ldap:/// ldapi:/// -g openldap -u openldap -F /etc/ldap/slapd.d", user="openldap")
svc(LC, "squid", "/usr/sbin/squid --foreground -sYC", user="proxy")
svc(LC, "dovecot", "/usr/sbin/dovecot -F")
svc(LC, "minio", "/usr/local/bin/minio server /mnt/data --console-address :9001", user="minio-user", judgment=True,
    note="object store answering client requests; could be read as io-data")

# ---------------------------------------------------------------- interactive
shell(IA, "bash", ["-bash"], exe="/usr/bin/bash", parent="sshd-session")
shell(IA, "zsh", ["-zsh"], exe="/usr/bin/zsh", parent="sshd-session")
shell(IA, "fish", "/usr/bin/fish", parent="sshd-session")
shell(IA, "tmux: server", "tmux new -s work", exe="/usr/bin/tmux", parent="systemd", cgroup="user.slice/user-1000.slice/user@1000.service/tmux-spawn-1.scope")
shell(IA, "tmux: client", "tmux attach -t work", exe="/usr/bin/tmux")
shell(IA, "screen", "SCREEN -S deploy", exe="/usr/bin/screen")
shell(IA, "sshd-session", ["sshd-session: dev@pts/0"], exe="/usr/lib/openssh/sshd-session", parent="sshd-session", user="dev")
svc(IA, "sshd", ["sshd: /usr/sbin/sshd -D [listener] 0 of 10-100 startups"], exe="/usr/sbin/sshd", unit="ssh",
    judgment=True, note="waits for people to log in")
shell(IA, "vim", "vim src/main.rs")
shell(IA, "nvim", "nvim .")
shell(IA, "emacs", "emacs -nw notes.org")
shell(IA, "less", "less /var/log/syslog")
shell(IA, "htop", "htop")
shell(IA, "top", "top")
shell(IA, "man", "man 7 sched")
shell(IA, "ssh", "ssh -J bastion dev@db-1.internal")
shell(IA, "mosh-server", "mosh-server new -s -c 256 -l LANG=en_US.UTF-8", parent="systemd")
shell(IA, "psql", "psql -h db-1 -U app appdb")
shell(IA, "mysql", "mysql -u root -p --password=s3cretpass shop")
shell(IA, "ipython", "/home/dev/.venv/bin/python3 /home/dev/.venv/bin/ipython", exe="/usr/bin/python3.12")
shell(IA, "python3", "python3", exe="/usr/bin/python3.12", judgment=True, note="bare python3 from a shell: a REPL")
shell(IA, "watch", "watch -n 1 kubectl get pods -A")
shell(IA, "git", "git log --oneline --graph")
shell(IA, "fzf", "fzf --height 40%")
shell(IA, "gnome-shell", "/usr/bin/gnome-shell", parent="systemd", cgroup="user.slice/user-1000.slice/user@1000.service/session.slice/org.gnome.Shell@wayland.service")
shell(IA, "Xwayland", "/usr/bin/Xwayland :0 -rootless -noreset", parent="gnome-shell",
      cgroup="user.slice/user-1000.slice/user@1000.service/session.slice/org.gnome.Shell@wayland.service")
shell(IA, "alacritty", "alacritty", parent="gnome-shell", cgroup="user.slice/user-1000.slice/user@1000.service/app.slice/app-alacritty.scope")
shell(IA, "firefox", "/usr/lib/firefox/firefox", parent="gnome-shell", cgroup="user.slice/user-1000.slice/user@1000.service/app.slice/app-firefox.scope")
shell(IA, "code", "/usr/share/code/code --type=renderer --enable-crash-reporter", parent="code",
      cgroup="user.slice/user-1000.slice/user@1000.service/app.slice/app-code.scope")
shell(IA, "jupyter-lab", "/home/dev/.venv/bin/python3 /home/dev/.venv/bin/jupyter-lab --no-browser --port 8888", exe="/usr/bin/python3.12",
      judgment=True, note="serves one person's browser")
svc(IA, "agetty", "/sbin/agetty -o -p -- \\u --noclear - linux", exe="/usr/sbin/agetty", unit="getty@tty1",
    judgment=True, note="console login prompt")

# ---------------------------------------------------------------- batch-compute
shell(BC, "make", "make -j16")
shell(BC, "cc1", "/usr/libexec/gcc/x86_64-linux-gnu/14/cc1 -quiet -I include src/sched.c -O2 -o /tmp/ccXq2.s", parent="gcc")
shell(BC, "cc1plus", "/usr/libexec/gcc/x86_64-linux-gnu/14/cc1plus -quiet -D NDEBUG src/engine.cpp -O3", parent="g++")
shell(BC, "clang-18", "/usr/lib/llvm-18/bin/clang -cc1 -triple x86_64-pc-linux-gnu -emit-obj -O2 lib/Support/APInt.cpp", parent="ninja")
shell(BC, "ld.lld", "/usr/bin/ld.lld -o bin/clang --gc-sections lib/libLLVMSupport.a", parent="clang")
shell(BC, "ninja", "ninja -C build -j 16")
shell(BC, "cargo", "cargo build --release")
shell(BC, "rustc", "/home/dev/.rustup/toolchains/stable-x86_64-unknown-linux-gnu/bin/rustc --crate-name tokio --edition=2021 -C opt-level=3",
      parent="cargo")
shell(BC, "go", "go build ./...")
shell(BC, "compile", "/usr/local/go/pkg/tool/linux_amd64/compile -o /tmp/go-build123/b001/_pkg_.a -p main -complete ./main.go", parent="go")
shell(BC, "javac", "javac -d out src/main/java/com/acme/App.java")
shell(BC, "java", "/usr/lib/jvm/java-21-openjdk-amd64/bin/java -Xmx2g -cp /home/dev/.gradle/wrapper/dists/gradle-8.7/lib/* org.gradle.launcher.daemon.bootstrap.GradleDaemon 8.7",
      parent="systemd", judgment=True, note="Gradle daemon: idles between builds, builds when asked")
shell(BC, "bazel", "bazel(monorepo) -server --output_base=/home/dev/.cache/bazel/_bazel_dev/9f1e", exe="/home/dev/.cache/bazel/_bazel_dev/install/bazel",
      parent="systemd")
shell(BC, "node", "node node_modules/.bin/webpack --mode production", exe="/usr/bin/node", parent="npm run build")
shell(BC, "tsc", "node /app/node_modules/.bin/tsc -p tsconfig.json", exe="/usr/bin/node")
shell(BC, "ffmpeg", "ffmpeg -i input.mov -c:v libx264 -preset slow -crf 20 output.mp4")
shell(BC, "x265", "x265 --preset veryslow --crf 18 in.y4m -o out.hevc")
shell(BC, "HandBrakeCLI", "HandBrakeCLI -i movie.mkv -o movie.mp4 --preset Fast 1080p30")
shell(BC, "blender", "blender -b scene.blend -o //render/frame_#### -a")
shell(BC, "python3", "python3 train.py --epochs 50 --batch-size 256", exe="/usr/bin/python3.12")
shell(BC, "torchrun", "/home/dev/.venv/bin/python3 /home/dev/.venv/bin/torchrun --nproc_per_node 8 finetune.py --config cfg.yaml",
      exe="/usr/bin/python3.12")
shell(BC, "pt_main_thread", "/home/dev/.venv/bin/python3 -u finetune.py --local-rank=3 --config cfg.yaml", exe="/usr/bin/python3.12",
      parent="torchrun", note="PyTorch renames its main thread")
shell(BC, "stress-ng", "stress-ng --cpu 8 --timeout 60s")
shell(BC, "stress-ng-cpu", ["stress-ng-cpu"], exe="/usr/bin/stress-ng", parent="stress-ng")
shell(BC, "sysbench", "sysbench cpu --threads=8 --time=300 run")
shell(BC, "redis-benchmark", "redis-benchmark -h 10.0.0.5 -n 1000000 -c 50", note="load generator, not a server")
shell(BC, "pgbench", "pgbench -c 32 -j 8 -T 600 appdb", note="load generator")
shell(BC, "wrk", "wrk -t8 -c400 -d60s http://10.0.0.5/")
shell(BC, "xz", "xz -9 -T0 dataset.tar", judgment=True, note="compression is CPU-bound at -9")
shell(BC, "zstd", "zstd -19 --long=27 -T0 db.dump", judgment=True, note="CPU-bound at -19")
shell(BC, "Rscript", "/usr/lib/R/bin/exec/R --no-echo --no-restore --file=simulate.R", exe="/usr/lib/R/bin/exec/R")
shell(BC, "julia", "julia --threads=auto sim.jl")
shell(BC, "gmx", "gmx mdrun -deffnm md_0_1 -nt 16")
shell(BC, "lmp", "lmp -in in.lj -sf omp -pk omp 16")
shell(BC, "simpleFoam", "simpleFoam -parallel", exe="/opt/openfoam11/platforms/linux64GccDPInt32Opt/bin/simpleFoam", parent="mpirun")
pod(BC, "java", "/opt/java/openjdk/bin/java -cp /opt/spark/jars/* org.apache.spark.executor.CoarseGrainedExecutorBackend --driver-url spark://driver:7078 --cores 4",
    exe="/opt/java/openjdk/bin/java")
docker(BC, "buildkitd", "buildkitd --addr fd:// --oci-worker-gc", exe="/usr/bin/buildkitd", judgment=True, note="container image builds")
docker(BC, "celery", "/usr/local/bin/python /usr/local/bin/celery -A proj worker --concurrency 8 -Q reports", exe="/usr/local/bin/python3.12",
       judgment=True, note="async job worker; jobs could be anything")
docker(BC, "sidekiq 7.2.4 a", ["sidekiq 7.2.4 app [3 of 10 busy]"], exe="/usr/local/bin/ruby", judgment=True, note="async job worker")
shell(BC, "pytest", "/home/dev/.venv/bin/python3 /home/dev/.venv/bin/pytest -n 16 tests/", exe="/usr/bin/python3.12",
      judgment=True, note="test suite: throughput, but someone may be waiting")

# ---------------------------------------------------------------- io-data
shell(IO, "rsync", "rsync -aHAX --delete /srv/data/ backup-1:/backups/data/")
svc(IO, "rsync", "rsync --server -logDtpre.iLsfxCIvu . /backups/data/", unit="ssh", parent="sshd-session", user="backup",
    note="receiving end of an rsync over ssh")
cron(IO, "tar", "tar -czf /backups/www-2026-10-19.tgz /var/www")
cron(IO, "pg_dump", "/usr/lib/postgresql/16/bin/pg_dump -Fc appdb -f /backups/appdb.dump", user="postgres")
svc(IO, "pg_basebackup", "/usr/lib/postgresql/16/bin/pg_basebackup -D /backups/base -X stream -P", unit="pg-basebackup", user="postgres")
cron(IO, "mysqldump", "mysqldump --single-transaction --all-databases --password=hunter2")
shell(IO, "dd", "dd if=/dev/nvme0n1 of=/mnt/backup/disk.img bs=4M status=progress", user="root")
svc(IO, "rclone", "/usr/bin/rclone sync /srv/media remote:media --transfers 16", unit="rclone-sync")
svc(IO, "restic", "/usr/bin/restic backup /home /etc --repo s3:s3.amazonaws.com/acme-backups", unit="restic-backup")
cron(IO, "borg", "borg create --stats ssh://backup@nas/./repo::{hostname}-{now} /home")
cron(IO, "aws", "/usr/bin/python3 /usr/local/bin/aws s3 sync /var/log/archive s3://acme-logs/archive", exe="/usr/bin/python3.12")
shell(IO, "gsutil", "/usr/bin/python3 /usr/lib/google-cloud-sdk/platform/gsutil/gsutil -m cp -r gs://acme-data/raw /mnt/raw",
      exe="/usr/bin/python3.12")
shell(IO, "scp", "scp -t /home/dev/uploads", parent="sshd-session")
shell(IO, "cp", "cp -a /mnt/old /mnt/new")
cron(IO, "mongodump", "mongodump --uri mongodb://backup:s3cret@localhost:27017 --out /backups/mongo")
shell(IO, "pg_restore", "/usr/lib/postgresql/16/bin/pg_restore -d appdb_staging -j 4 /backups/appdb.dump", user="postgres")
shell(IO, "psql", "psql -h db-1 appdb -f bulk_load_2026_10.sql", judgment=True, note="psql client, but doing a bulk load")
docker(IO, "python3", "python3 etl_orders.py --since 2026-10-01 --sink warehouse", exe="/usr/bin/python3.11")
pod(IO, "python", "python -m airflow tasks run ingest_clickstream load_s3 scheduled__2026-10-19", exe="/usr/local/bin/python3.11")
shell(IO, "curl", "curl -L -o ubuntu-26.04-server.iso https://releases.ubuntu.com/26.04/ubuntu-26.04-server.iso")
shell(IO, "wget", "wget -c https://data.acme.io/exports/2026-10.parquet")
shell(IO, "aria2c", "aria2c -x 16 https://mirror.example.org/dataset.tar")
svc(IO, "zfs", "zfs send -I tank/data@mon tank/data@tue", unit="zfs-replicate", parent="bash")
svc(IO, "btrfs", "btrfs scrub start -B /mnt/pool", unit="btrfs-scrub", judgment=True, note="checks disks; could be called background")
cron(IO, "gzip", "gzip -c /var/log/nginx/access.log.1", judgment=True, note="default level: I/O-bound")
docker(IO, "kafka-mirror", "/opt/kafka/bin/kafka-mirror-maker.sh --consumer.config c.properties --producer.config p.properties",
       exe="/usr/bin/bash", judgment=True, note="copies topics between clusters")
svc(IO, "rsnapshot", "/usr/bin/perl -w /usr/bin/rsnapshot daily", exe="/usr/bin/perl", unit="rsnapshot-daily")
docker(IO, "mc", "mc mirror --overwrite local/bucket s3/bucket")
svc(IO, "duplicity", "/usr/bin/python3 /usr/bin/duplicity incremental /srv b2://acme-backup", exe="/usr/bin/python3.12", unit="duplicity")
shell(IO, "unzip", "unzip -q corpus.zip -d /data/corpus")

# ---------------------------------------------------------------- background
svc(BG, "cron", "/usr/sbin/cron -f -P")
svc(BG, "systemd-journal", "/usr/lib/systemd/systemd-journald", unit="systemd-journald")
svc(BG, "rsyslogd", "/usr/sbin/rsyslogd -n -iNONE", unit="rsyslog", user="syslog")
svc(BG, "node_exporter", "/usr/bin/prometheus-node-exporter", exe="/usr/bin/prometheus-node-exporter",
    unit="prometheus-node-exporter", user="prometheus")
docker(BG, "nginx-prometheus", "/usr/bin/nginx-prometheus-exporter --nginx.scrape-uri=http://nginx:8080/stub_status",
       note="trap: name starts with nginx")
docker(BG, "postgres_export", "/bin/postgres_exporter --web.listen-address=:9187", user="nobody", note="trap: name starts with postgres")
docker(BG, "redis_exporter", "/redis_exporter -redis.addr redis://redis:6379")
pod(BG, "fluent-bit", "/fluent-bit/bin/fluent-bit -c /fluent-bit/etc/fluent-bit.conf")
svc(BG, "ruby", "/opt/td-agent/bin/ruby -Eascii-8bit:ascii-8bit /opt/td-agent/bin/fluentd --log /var/log/td-agent/td-agent.log",
    unit="td-agent", user="td-agent", note="fluentd under its ruby comm")
svc(BG, "telegraf", "/usr/bin/telegraf -config /etc/telegraf/telegraf.conf", user="telegraf")
svc(BG, "agent", "/opt/datadog-agent/bin/agent/agent run -p /opt/datadog-agent/run/agent.pid", unit="datadog-agent", user="dd-agent")
pod(BG, "otelcol-contrib", "/otelcol-contrib --config=/conf/relay.yaml")
svc(BG, "filebeat", "/usr/share/filebeat/bin/filebeat --environment systemd -c /etc/filebeat/filebeat.yml")
pod(BG, "promtail", "/usr/bin/promtail -config.file=/etc/promtail/promtail.yaml")
svc(BG, "unattended-upgr", "/usr/bin/python3 /usr/share/unattended-upgrades/unattended-upgrade-shutdown --wait-for-signal",
    exe="/usr/bin/python3.12", unit="unattended-upgrades")
svc(BG, "packagekitd", "/usr/libexec/packagekitd", unit="packagekit")
svc(BG, "snapd", "/snap/snapd/current/usr/lib/snapd/snapd", exe="/snap/snapd/23258/usr/lib/snapd/snapd")
svc(BG, "chronyd", "/usr/sbin/chronyd -n -F 1", unit="chrony", user="_chrony")
svc(BG, "systemd-timesyn", "/usr/lib/systemd/systemd-timesyncd", unit="systemd-timesyncd", user="systemd-timesync")
svc(BG, "google_guest_ag", "/usr/bin/google_guest_agent", unit="google-guest-agent")
svc(BG, "google_osconfig", "/usr/bin/google_osconfig_agent", unit="google-osconfig-agent")
svc(BG, "amazon-ssm-agen", "/snap/amazon-ssm-agent/9881/amazon-ssm-agent", unit="snap.amazon-ssm-agent.amazon-ssm-agent")
svc(BG, "irqbalance", "/usr/sbin/irqbalance")
svc(BG, "multipathd", "/usr/sbin/multipathd -d -s", judgment=True, note="storage path failover daemon")
svc(BG, "udisksd", "/usr/libexec/udisks2/udisksd", unit="udisks2")
svc(BG, "networkd-dispat", "/usr/bin/python3 /usr/bin/networkd-dispatcher --run-startup-triggers", exe="/usr/bin/python3.12",
    unit="networkd-dispatcher")
svc(BG, "logrotate", "/usr/sbin/logrotate /etc/logrotate.conf")
svc(BG, "updatedb.plocat", "/usr/sbin/updatedb.plocate", unit="plocate-updatedb")
svc(BG, "apt-get", "/usr/bin/apt-get -qq update", unit="apt-daily", parent="apt.systemd.dai")
svc(BG, "fwupd", "/usr/libexec/fwupd/fwupd")
svc(BG, "smartd", "/usr/sbin/smartd -n", unit="smartmontools")
svc(BG, "atd", "/usr/sbin/atd -f")
svc(BG, "certbot", "/usr/bin/python3 /usr/bin/certbot -q renew", exe="/usr/bin/python3.12")
svc(BG, "auditd", "/sbin/auditd", exe="/usr/sbin/auditd")
svc(BG, "osqueryd", "/opt/osquery/bin/osqueryd --flagfile /etc/osquery/osquery.flags")
svc(BG, "freshclam", "/usr/bin/freshclam -d --foreground=true", unit="clamav-freshclam", user="clamav")
svc(BG, "postgres", ["postgres: 16/main: autovacuum launcher"], exe="/usr/lib/postgresql/16/bin/postgres",
    unit="postgresql@16-main", user="postgres", parent="postgres", note="trap: housekeeping inside a critical database")
svc(BG, "postgres", ["postgres: 16/main: checkpointer"], exe="/usr/lib/postgresql/16/bin/postgres",
    unit="postgresql@16-main", user="postgres", parent="postgres", judgment=True,
    note="background flush, but stalls can show up in query latency")
pod(BG, "cadvisor", "/usr/bin/cadvisor -logtostderr --housekeeping_interval=10s")
svc(BG, "containerd", "/usr/bin/containerd", judgment=True, note="container runtime; only busy when containers start")
svc(BG, "dockerd", "/usr/bin/dockerd -H fd:// --containerd=/run/containerd/containerd.sock", unit="docker", judgment=True)
svc(BG, "kubelet", "/usr/bin/kubelet --config=/var/lib/kubelet/config.yaml --kubeconfig=/etc/kubernetes/kubelet.conf",
    judgment=True, note="node agent; slow kubelet delays pod starts, not requests")
pod(BG, "kube-proxy", "/usr/local/bin/kube-proxy --config=/var/lib/kube-proxy/config.conf", judgment=True,
    note="programs iptables rules; not in the packet path itself")
svc(BG, "systemd-resolve", "/usr/lib/systemd/systemd-resolved", unit="systemd-resolved", user="systemd-resolve", judgment=True,
    note="local DNS stub: answers lookups, but is not the workload")
svc(BG, "dbus-daemon", ["@dbus-daemon --system --address=systemd: --nofork --nopidfile --systemd-activation --syslog-only"],
    exe="/usr/bin/dbus-daemon", unit="dbus", user="messagebus", judgment=True)
svc(BG, "polkitd", "/usr/lib/polkit-1/polkitd --no-debug --log-level=notice", unit="polkit", user="polkitd", judgment=True)
svc(BG, "systemd-logind", "/usr/lib/systemd/systemd-logind", judgment=True)

# ---------------------------------------------------------------- unknown: nobody could tell from outside
shell(UNK, "python3", "python3 main.py", exe="/usr/bin/python3.12")
shell(UNK, "python3", "python3 app.py --config prod.yaml", exe="/usr/bin/python3.12", note="'app' hints at a server but proves nothing")
shell(UNK, "python3", "python3 -m acme_tool", exe="/usr/bin/python3.12")
shell(UNK, "run.sh", "/bin/bash ./run.sh", exe="/usr/bin/bash")
docker(UNK, "java", "java -jar /app/app.jar", exe="/opt/java/openjdk/bin/java")
docker(UNK, "node", "node index.js", exe="/usr/local/bin/node")
docker(UNK, "dotnet", "dotnet Acme.Core.dll", exe="/usr/share/dotnet/dotnet")
docker(UNK, "deno", "deno run --allow-net main.ts", exe="/usr/local/bin/deno")
svc(UNK, "acmed", "/opt/acme/bin/acmed --config /etc/acme/acmed.yaml", unit="acmed")
svc(UNK, "zxqd", "/opt/zxq/bin/zxqd --db-password=hunter2 --token abc123", unit="zxq")
shell(UNK, "a.out", "./a.out", exe="/home/dev/scratch/a.out")
pod(UNK, "worker", "/app/worker", exe="/app/worker", note="could be a queue consumer, a batch job, anything")
shell(UNK, "ruby", "ruby script.rb", exe="/usr/bin/ruby3.3")
shell(UNK, "perl", "perl process.pl", exe="/usr/bin/perl")
svc(UNK, "agent", "/usr/local/bin/agent --config /etc/agent.toml", unit="agent")
shell(UNK, "sleep", "sleep 3600")
docker(UNK, "sh", "/bin/sh -c /entrypoint.sh", exe="/usr/bin/dash")
docker(UNK, "tini", "/usr/bin/tini -- /docker-entrypoint.sh", parent="containerd-shim")
docker(UNK, "bash", "bash -c while true; do ./step; sleep 5; done", exe="/usr/bin/bash")
svc(UNK, "svc", "/srv/bin/svc", unit="svc")


if __name__ == "__main__":
    ids = [r["id"] for r in RECORDS]
    assert len(ids) == len(set(ids))
    out = Path(__file__).with_name("processes.jsonl")
    out.write_text("".join(json.dumps(r) + "\n" for r in RECORDS))
    counts: dict[str, int] = {}
    for r in RECORDS:
        counts[r["label"]] = counts.get(r["label"], 0) + 1
    judged = sum(r["judgment"] for r in RECORDS)
    print(f"wrote {len(RECORDS)} records to {out}: " + ", ".join(f"{n} {k}" for k, n in counts.items())
          + f"; {judged} marked judgment")
