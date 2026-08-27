#!/usr/bin/env bash
# human-gate 站点自动接入脚本（在“装了节点的服务器”上运行）
# 功能：给指定站点的 nginx 配置注入闸门（include human-gate.inc + location / 加 auth_request）
#       自动处理反代站点(location / 在 proxy/*.conf 里)，自动备份 + nginx -t 校验 + 失败回滚 + 幂等。
#
# 用法：
#   bash attach-gate.sh list                    # 列出所有站点及接入状态
#   bash attach-gate.sh apply <域名或conf名>...  # 接入指定站点(可多个)
#   bash attach-gate.sh apply all               # 接入全部(会先列计划并要求确认)
#   预览不写盘：  DRYRUN=1 bash attach-gate.sh apply all
# 注意：本脚本大量用 grep 作条件判断，故不启用 set -e（避免条件为假时误退出）。
# 写操作处均显式判断返回值并在 nginx -t 失败时回滚。
set -uo pipefail

# ---- 定位 nginx ----
VHOST=""
for d in /www/server/panel/vhost/nginx /etc/nginx/sites-enabled /etc/nginx/conf.d /usr/local/nginx/conf/vhost; do
  [ -d "$d" ] && VHOST="$d" && break
done
[ -z "$VHOST" ] && { echo "!! 找不到 nginx vhost 目录"; exit 1; }

NGINX_BIN="$(command -v nginx || echo /www/server/nginx/sbin/nginx)"
INC_SRC_CANDIDATES=("$VHOST/human-gate.inc" "$(cd "$(dirname "$0")" && pwd)/human-gate.inc" "$HOME/human-gate-node/human-gate.inc")
INC_DST="$VHOST/human-gate.inc"
INC_LINE="    include $INC_DST;"
AUTH_LINE="        auth_request /__gate/check;"
STAMP=$(date +%Y%m%d%H%M%S)
DRYRUN="${DRYRUN:-0}"

# 确保 human-gate.inc 就位
ensure_inc() {
  [ -f "$INC_DST" ] && return 0
  for c in "${INC_SRC_CANDIDATES[@]}"; do
    if [ -f "$c" ] && [ "$c" != "$INC_DST" ]; then cp "$c" "$INC_DST"; echo "  已放置 human-gate.inc -> $INC_DST"; return 0; fi
  done
  echo "!! 未找到 human-gate.inc（请把它放到 $VHOST/ 或脚本同目录）"; exit 1
}

# 站点主配置：VHOST 下含 server_name 的 .conf（排除片段文件）
site_confs() {
  for f in "$VHOST"/*.conf; do
    [ -f "$f" ] || continue
    case "$(basename "$f")" in
      human-gate.inc|*realip*|cloudflare*|proxy-realip*|ingest-endpoint*) continue;;
    esac
    if grep -q 'server_name' "$f" && grep -q 'server' "$f"; then
      echo "$f"
    fi
  done
}

# 展开主 conf 里 include 的所有文件（含 proxy/*.conf），找含根 location / 的文件
# 匹配根 location（路径恰为 /），支持修饰符 ^~ = ~ 及 { 换行：
#   location / {   |   location ^~ /   |   location = / {
root_loc_regex='^[[:space:]]*location[[:space:]]+([\^~=*]+[[:space:]]+)?/[[:space:]]*(\{[[:space:]]*)?$'
find_loc_file() {
  local main="$1"
  grep -qE "$root_loc_regex" "$main" && { echo "$main"; return; }
  # 解析 include 指令并通配展开
  grep -oE 'include[[:space:]]+[^;]+;' "$main" | sed -E 's/include[[:space:]]+//; s/;$//' | while read -r pat; do
    case "$pat" in /*) : ;; *) pat="$VHOST/$pat";; esac
    for f in $pat; do
      [ -f "$f" ] || continue
      grep -qE "$root_loc_regex" "$f" && { echo "$f"; return; }
    done
  done | head -1
}

is_attached() { grep -q 'human-gate.inc' "$1" 2>/dev/null; }

declare -a BAKED
backup() { [ "$DRYRUN" = 1 ] && return 0; cp -a "$1" "$1.gatebak.$STAMP"; BAKED+=("$1"); }
rollback() { for f in "${BAKED[@]:-}"; do [ -f "$f.gatebak.$STAMP" ] && cp -a "$f.gatebak.$STAMP" "$f"; done; }

inject_include() {
  local f="$1"
  grep -q 'human-gate.inc' "$f" && return 0
  backup "$f"
  [ "$DRYRUN" = 1 ] && { echo "  [dry] $f 注入 include human-gate.inc"; return 0; }
  if grep -q '#SSL-END' "$f"; then
    sed -i "/#SSL-END/a\\$INC_LINE" "$f"
  else
    sed -i "0,/server_name/{/server_name/a\\$INC_LINE
}" "$f"
  fi
  echo "  ✓ $f 已注入 include"
}

inject_auth() {
  local f="$1"
  grep -q 'auth_request /__gate/check' "$f" && { echo "  = $f 已有 auth_request，跳过"; return 0; }
  grep -qE "$root_loc_regex" "$f" || { echo "  !! $f 未找到根 location /（可能是特殊结构，需手动加）"; return 1; }
  backup "$f"
  [ "$DRYRUN" = 1 ] && { echo "  [dry] $f 在 location / 注入 auth_request"; return 0; }
  # 找到根 location 行后，在其块的第一个 '{' 之后插入（兼容 { 同行或换行）
  # 用 awk 原生正则（避免 shell 正则里的 POSIX 类/转义在 awk 中失效）：
  #   ^location ([~=*^]+ )?/( ?{)?$   —— 归一化空白后的根 location 形态
  awk -v ins="$AUTH_LINE" '
    function emit(){ print ins; inserted=1 }
    {
      print
      if (!inserted) {
        t=$0; gsub(/[ \t]+/," ",t); sub(/^ /,"",t); sub(/ $/,"",t)
        if (armed) {
          if ($0 ~ /[{]/) { emit(); armed=0 }
        } else if (t ~ /^location ([~=*^]+ )?[/]( ?[{])?$/) {
          armed=1
          if ($0 ~ /[{]/) { emit(); armed=0 }
        }
      }
    }
  ' "$f" > "$f.gatetmp" && mv "$f.gatetmp" "$f"
  echo "  ✓ $f 已在 location / 注入 auth_request"
}

attach_one() {
  local main="$1" name; name="$(basename "$main")"
  echo "== 接入 $name =="
  local locf; locf="$(find_loc_file "$main")"
  if [ -z "$locf" ]; then
    echo "  !! 未定位到根 location /，跳过（该站可能无 location / 或结构特殊）"; return 1
  fi
  inject_include "$main"
  inject_auth "$locf"
}

cmd_list() {
  echo "nginx 目录: $VHOST"
  printf "%-40s %-10s %s\n" "站点配置" "已接入" "根location所在"
  printf -- "------------------------------------------------------------------------\n"
  while read -r f; do
    [ -z "$f" ] && continue
    local locf; locf="$(find_loc_file "$f")"
    printf "%-40s %-10s %s\n" "$(basename "$f")" "$(is_attached "$f" && echo yes || echo no)" "${locf:-未找到}"
  done < <(site_confs)
}

cmd_apply() {
  ensure_inc
  local targets=("$@") confs=()
  if [ "${targets[0]:-}" = "all" ]; then
    while read -r f; do [ -n "$f" ] && confs+=("$f"); done < <(site_confs)
    echo "将接入以下 ${#confs[@]} 个站点："
    for c in "${confs[@]}"; do echo "  - $(basename "$c")"; done
    if [ "$DRYRUN" != 1 ] && [ "${YES:-0}" != 1 ]; then
      read -r -p "确认接入全部？(输入 yes 继续) " ans; [ "$ans" = yes ] || { echo "已取消"; exit 0; }
    fi
  else
    for t in "${targets[@]}"; do
      local hit=""
      while read -r f; do
        [ "$(basename "$f")" = "$t" ] || [ "$(basename "$f")" = "$t.conf" ] && hit="$f"
        grep -q "server_name.*$t" "$f" 2>/dev/null && hit="$f"
      done < <(site_confs)
      [ -n "$hit" ] && confs+=("$hit") || echo "!! 未匹配到站点: $t"
    done
  fi
  [ "${#confs[@]}" -eq 0 ] && { echo "没有可接入的站点"; exit 1; }

  # 预检：nginx 必须带 http_auth_request_module，否则 auth_request 指令无法使用
  if [ "$DRYRUN" != 1 ] && ! "$NGINX_BIN" -V 2>&1 | grep -q 'http_auth_request_module'; then
    echo "!! 本机 nginx 未编译 http_auth_request_module，无法使用 auth_request。"
    echo "   该节点的闸门需改用其它方式（如在上游应用或另一层带该模块的 nginx 上接入）。"
    echo "   已中止，未做任何修改。"
    exit 2
  fi

  for c in "${confs[@]}"; do attach_one "$c" || true; done

  if [ "$DRYRUN" = 1 ]; then echo "== DRYRUN 结束，未写盘 =="; return 0; fi
  echo "== 校验 nginx 配置 =="
  # 注意：不要用 `if nginx -t | tail` —— pipefail 下管道返回码会取 nginx 的非零，
  # 导致校验失败时反而跳过回滚。这里单独取 nginx -t 的退出码。
  local tout
  tout="$("$NGINX_BIN" -t 2>&1)"; local trc=$?
  echo "$tout" | tail -2
  if [ "$trc" -eq 0 ]; then
    "$NGINX_BIN" -s reload && echo "== ✓ 已重载，接入完成 =="
    echo "备份后缀: .gatebak.$STAMP （确认无误后可删）"
  else
    echo "== ✗ 配置校验失败，自动回滚 =="
    rollback
    local rout; rout="$("$NGINX_BIN" -t 2>&1)"; local rrc=$?
    if [ "$rrc" -eq 0 ]; then
      echo "== ✓ 已回滚到接入前状态（nginx 配置校验通过）=="
    else
      echo "== !! 回滚后仍校验失败，请人工检查："; echo "$rout" | tail -3
    fi
    exit 1
  fi
}

case "${1:-list}" in
  list) cmd_list ;;
  apply) shift; [ "$#" -ge 1 ] || { echo "用法: bash attach-gate.sh apply <域名|conf名|all>"; exit 1; }; cmd_apply "$@" ;;
  *) echo "用法: bash attach-gate.sh {list|apply <目标>}"; exit 1 ;;
esac
