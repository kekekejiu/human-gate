# ============================================================
# 人机验证闸门 (human-gate) 公共片段
# 用法：在某个 server{} 里 include 本文件，然后在需要保护的
#       location 里加一行： auth_request /__gate/check;
# 注意：API / 支付回调 / 静态资源等 location 不要加 auth_request，即自动放行。
# ============================================================

# 闸门校验端点：由 auth_request 内部调用，不对外暴露
location = /__gate/check {
    internal;
    proxy_pass http://127.0.0.1:9200/__gate/check;
    proxy_pass_request_body off;
    proxy_set_header Content-Length "";
    proxy_set_header X-Original-URI $request_uri;
    proxy_set_header X-Forwarded-Host $host;
    proxy_set_header X-Real-IP $remote_addr;
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    proxy_set_header User-Agent $http_user_agent;
    proxy_set_header Cookie $http_cookie;
}

# 闸门页面与接口(验证页 / 生成滑块 / 校验)：直接转发，不参与鉴权
location /__gate/ {
    proxy_pass http://127.0.0.1:9200;
    proxy_set_header Host $host;
    proxy_set_header User-Agent $http_user_agent;
    proxy_set_header X-Real-IP $remote_addr;
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    proxy_set_header X-Forwarded-Proto $scheme;
    access_log off;
}

# 未通过验证(auth_request 返回 401)时跳转到闸门页，并带上原始地址
error_page 401 = @gate_redirect;
location @gate_redirect {
    # 关键：保持相对跳转，不让 nginx 补全成源站绝对地址(否则前置反代会被击穿、暴露源站IP)
    absolute_redirect off;
    return 302 /__gate/?next=$request_uri;
}
