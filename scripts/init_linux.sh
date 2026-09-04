#!/usr/bin/env bash
set -euo pipefail

APP_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
INSTALL_SYSTEMD=1
START_SERVICE=1

usage() {
  cat <<'EOF'
NetHub Accounts Linux 初始化脚本

用法：
  ./scripts/init_linux.sh [--no-systemd] [--no-start]

脚本将创建/复用 Conda 环境、安装依赖、生成安全密钥、升级数据库，
并默认安装 systemd 用户服务。重复执行不会覆盖已有密钥或 .env。
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --no-systemd) INSTALL_SYSTEMD=0 ;;
    --no-start) START_SERVICE=0 ;;
    -h|--help) usage; exit 0 ;;
    *) echo "未知参数: $1" >&2; usage >&2; exit 2 ;;
  esac
  shift
done

log() { printf '[nethub-accounts] %s\n' "$*"; }
die() { echo "$*" >&2; exit 1; }
command -v conda >/dev/null 2>&1 || die "未找到 Conda，请先安装 Miniconda 或 Anaconda。"

cd "$APP_DIR"
[[ -f requirements.txt && -f alembic.ini && -f .env.example ]] || die "项目文件不完整。"

if [[ ! -f .env ]]; then
  cp .env.example .env
  log "已从 .env.example 创建 .env"
fi
chmod 600 .env

set -a
# shellcheck disable=SC1091
source ./.env
set +a

CONDA_ENV_NAME="${CONDA_ENV_NAME:-nethub-accounts}"
PYTHON_VERSION="${PYTHON_VERSION:-3.12}"
SERVICE_NAME="${SYSTEMD_SERVICE_NAME:-nethub-accounts}"

if ! conda run -n "$CONDA_ENV_NAME" python -c 'import sys' >/dev/null 2>&1; then
  log "创建 Conda 环境 $CONDA_ENV_NAME (Python $PYTHON_VERSION)"
  conda create --yes --name "$CONDA_ENV_NAME" "python=$PYTHON_VERSION" pip
fi

PYTHON_BIN="$(conda run -n "$CONDA_ENV_NAME" python -c 'import sys; print(sys.executable)')"
PYTHON_BIN="${PYTHON_BIN//$'\r'/}"
[[ -x "$PYTHON_BIN" ]] || die "无法确定 Conda Python 路径。"

log "安装 Python 依赖"
"$PYTHON_BIN" -m pip install --upgrade pip
"$PYTHON_BIN" -m pip install --upgrade -r requirements.txt

mkdir -p data migration-output
chmod 700 data migration-output

ACCOUNTS_ENV_PATH="$APP_DIR/.env" "$PYTHON_BIN" - <<'PY'
import os
import re
import secrets
from pathlib import Path

path = Path(os.environ["ACCOUNTS_ENV_PATH"])
lines = path.read_text(encoding="utf-8").splitlines()
name = "ACCOUNTS_SECRET_KEY"
pattern = re.compile(rf"^\s*{name}\s*=")
indexes = [i for i, line in enumerate(lines) if pattern.match(line)]
value = lines[indexes[0]].split("=", 1)[1].strip() if indexes else ""
if len(value.encode("utf-8")) < 32:
    assignment = f"{name}={secrets.token_urlsafe(48)}"
    if indexes:
        lines[indexes[0]] = assignment
    else:
        lines.append(assignment)
    temporary = path.with_name(f"{path.name}.tmp.{os.getpid()}")
    temporary.write_text("\n".join(lines) + "\n", encoding="utf-8")
    os.chmod(temporary, 0o600)
    os.replace(temporary, path)
    print("generated ACCOUNTS_SECRET_KEY")
else:
    print("kept ACCOUNTS_SECRET_KEY")
PY

set -a
# shellcheck disable=SC1091
source ./.env
set +a

OIDC_SIGNING_KEY_PATH="${OIDC_SIGNING_KEY_PATH:-data/oidc-rs256.pem}"
if [[ "$OIDC_SIGNING_KEY_PATH" != /* ]]; then
  OIDC_SIGNING_KEY_PATH="$APP_DIR/$OIDC_SIGNING_KEY_PATH"
fi
if [[ ! -f "$OIDC_SIGNING_KEY_PATH" ]]; then
  log "生成 OIDC RS256 私钥"
  OIDC_OUTPUT_PATH="$OIDC_SIGNING_KEY_PATH" "$PYTHON_BIN" - <<'PY'
import os
from pathlib import Path
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

path = Path(os.environ["OIDC_OUTPUT_PATH"])
path.parent.mkdir(parents=True, exist_ok=True)
key = rsa.generate_private_key(public_exponent=65537, key_size=3072)
temporary = path.with_name(f"{path.name}.tmp.{os.getpid()}")
temporary.write_bytes(key.private_bytes(
    serialization.Encoding.PEM,
    serialization.PrivateFormat.PKCS8,
    serialization.NoEncryption(),
))
os.chmod(temporary, 0o600)
os.replace(temporary, path)
PY
fi
chmod 600 "$OIDC_SIGNING_KEY_PATH"

log "升级数据库"
"$PYTHON_BIN" -m app.cli db-upgrade

if [[ "$INSTALL_SYSTEMD" == "1" ]]; then
  command -v systemctl >/dev/null 2>&1 || die "未找到 systemctl；可用 --no-systemd 完成其余初始化。"
  command -v systemd-analyze >/dev/null 2>&1 || die "未找到 systemd-analyze。"
  SERVICE_DIR="${XDG_CONFIG_HOME:-$HOME/.config}/systemd/user"
  SERVICE_FILE="$SERVICE_DIR/$SERVICE_NAME.service"
  mkdir -p "$SERVICE_DIR"
  "$PYTHON_BIN" scripts/render_systemd_unit.py \
    --app-dir "$APP_DIR" \
    --python-bin "$PYTHON_BIN" \
    --host "${ACCOUNTS_HOST:-127.0.0.1}" \
    --port "${ACCOUNTS_PORT:-3400}" \
    --output "$SERVICE_FILE"
  systemd-analyze --user verify "$SERVICE_FILE"
  systemctl --user daemon-reload
  systemctl --user enable "$SERVICE_NAME.service"
  if [[ "$START_SERVICE" == "1" ]]; then
    systemctl --user restart "$SERVICE_NAME.service"
    log "服务状态: $(systemctl --user is-active "$SERVICE_NAME.service")"
  fi
fi

log "初始化完成。首次部署请执行：$PYTHON_BIN -m app.cli bootstrap-admin"
