-- ============================================================
-- registry_proxy.lua
-- 容器镜像仓库反向代理
--
-- 鉴权模型：透明式（credential-transparent）
--   上游要鉴权 -> 我们回自己的 401，realm 指向本站 /v2/auth
--   客户端来 /v2/auth 换 token -> 我们中转到真实 token 端点，把 token 交回客户端
--   之后客户端自带 token -> 我们原样转发，绝不碰 Authorization
--   => 服务端不持有、不缓存任何 bearer token
--   => 客户端可以 docker login，用自己的账号配额，不挤代理出口 IP
--
-- 对外暴露：
--   init_worker()    init_worker_by_lua_block         http
--   root_redirect()  access_by_lua_block              = /
--   route()          access_by_lua_block              = /v2/ , ^~ /v2/
--   fix_response()   header_filter_by_lua_block       = /v2/ , ^~ /v2/
--   auth()           content_by_lua_block             = /v2/auth
--   prepare_follow() rewrite_by_lua_block             @follow
-- ============================================================

local http  = require("resty.http")
local cjson = require("cjson.safe")

local _M = {}

-- 我们在 WWW-Authenticate 里回给客户端的 service 名。
-- 客户端只是原样带回 /v2/auth，值本身不参与上游校验。
local SERVICE = "docker-proxy"

-- ------------------------------------------------------------
-- 1) 仓库路由表：subdomain -> 上游仓库
--    对应 server_name 正则 ~^(?<subdomain>.+)\.example\.com$ 捕获出来的 $subdomain
--    default_prefix：仓库名不含 "/" 时自动补的前缀（仅 Docker Hub 有此隐式规则）
--    新增仓库只需要在这里加一行，鉴权方式运行时自动探测，无需额外配置
-- ------------------------------------------------------------
local REGISTRIES = {
    ["docker"] = {
        upstream       = "registry-1.docker.io",
        default_prefix = "library/",
    },
    ["ghcr"] = {
        upstream = "ghcr.io",
    },
    ["quay"] = {
        upstream = "quay.io",
    },
    ["k8s"] = {
        upstream = "registry.k8s.io",
    },
    ["mcr"] = {
        upstream = "mcr.microsoft.com",
    },
    ["elastic"] = {
        upstream = "docker.elastic.co",
    },
    ["nvcr"] = {
        upstream = "nvcr.io",
    },
    ["cr"] = {
        upstream       = "registry-1.docker.io",
        default_prefix = "library/",
    },
    -- 按需继续添加：
    -- ["gcr"] = { upstream = "gcr.io" },
}

-- `cr.example.com/<registry>/...` 的路径选择器。只接受明确列出的上游，
-- 未命中时保持 Docker Hub 默认路由，不把任意路径第一段当作目标主机
-- （否则代理会退化成任意主机的 SSRF 中继）。
local CR_SELECTORS = {
    ["ghcr.io"]           = { upstream = "ghcr.io" },
    ["quay.io"]           = { upstream = "quay.io" },
    ["registry.k8s.io"]   = { upstream = "registry.k8s.io" },
    ["mcr.microsoft.com"] = { upstream = "mcr.microsoft.com" },
    ["docker.elastic.co"] = { upstream = "docker.elastic.co" },
    ["nvcr.io"]           = { upstream = "nvcr.io" },
}

-- 未知 subdomain 时回给客户端的路由表，同时描述 cr 统一入口的选择器。
local routes_json_cache
local function routes_json()
    if not routes_json_cache then
        local routes = {}
        for sub, conf in pairs(REGISTRIES) do
            routes[sub] = "https://" .. conf.upstream
        end
        local selectors = {}
        for selector, conf in pairs(CR_SELECTORS) do
            selectors[selector] = "https://" .. conf.upstream
        end
        routes_json_cache = cjson.encode({
            routes = routes,
            unified = {
                subdomain = "cr",
                default = "https://" .. REGISTRIES.cr.upstream,
                selectors = selectors,
            },
        })
    end
    return routes_json_cache
end

-- 直接把响应写完并结束请求。
-- 关键：用 ngx.exit(ngx.HTTP_OK) 而不是 ngx.exit(status)。
-- headers 已发出后 nginx 不会再走 special response handler，
-- 因此不受 error_page（含我们自己装的 error_page 302/307/308 = @follow）摆布。
local function respond(status, content_type, body)
    ngx.status = status
    ngx.header["Content-Type"]  = content_type
    ngx.header["Content-Length"] = #body
    ngx.print(body)
    ngx.send_headers()
    return ngx.exit(ngx.HTTP_OK)
end

local function respond_json(status, body)
    return respond(status, "application/json", body)
end

-- registry 风格的错误体
local function respond_registry_error(status, code, message)
    return respond_json(status, cjson.encode({
        errors = { { code = code, message = message, detail = message } },
    }))
end

-- ------------------------------------------------------------
-- 2) 上游鉴权探测（realm / service）
--    token 不再由我们持有，但 /v2/auth 仍需知道往哪个 realm 转发
-- ------------------------------------------------------------
local DISCOVERY_TTL      = 3600
local DISCOVERY_FAIL_TTL = 30    -- 负缓存，避免上游抖动时每请求都发起 5s 探测

local function discover(upstream_host)
    local dict = ngx.shared.auth_discovery

    local cached = dict:get(upstream_host)
    if cached then
        if cached == "NOAUTH" then
            return { no_auth = true }
        end
        if cached:sub(1, 5) == "FAIL:" then
            return nil, cached:sub(6)
        end
        local data = cjson.decode(cached)
        if data then
            return data
        end
    end

    local function fail(msg)
        dict:set(upstream_host, "FAIL:" .. msg, DISCOVERY_FAIL_TTL)
        return nil, msg
    end

    local httpc = http.new()
    httpc:set_timeout(5000)

    local ok, err = httpc:connect(upstream_host, 443)
    if not ok then
        return fail("connect " .. upstream_host .. " failed: " .. tostring(err))
    end

    local sok, serr = httpc:ssl_handshake(nil, upstream_host, true)
    if not sok then
        httpc:close()
        return fail("tls handshake to " .. upstream_host .. " failed: " .. tostring(serr))
    end

    local res, rerr = httpc:request({
        method  = "GET",
        path    = "/v2/",
        headers = { ["Host"] = upstream_host },
    })
    if not res then
        httpc:close()
        return fail("probe /v2/ failed: " .. tostring(rerr))
    end
    res:read_body()
    httpc:set_keepalive(10000, 50)

    if res.status == 200 then
        dict:set(upstream_host, "NOAUTH", DISCOVERY_TTL)
        return { no_auth = true }
    end

    local challenge = res.headers["Www-Authenticate"] or res.headers["www-authenticate"]
    if not challenge then
        return fail("no WWW-Authenticate header, status=" .. tostring(res.status))
    end

    local realm   = challenge:match('realm="([^"]+)"')
    local service = challenge:match('service="([^"]+)"')
    if not realm then
        return fail("cannot parse realm from challenge: " .. challenge)
    end

    local data = { realm = realm, service = service }
    dict:set(upstream_host, cjson.encode(data), DISCOVERY_TTL)
    return data
end

-- ------------------------------------------------------------
-- 3) URI 处理
-- ------------------------------------------------------------
-- Docker Hub 隐式 library/ 前缀。
-- 在【原始】path 字符串上做，不用 ngx.req.set_uri()：
--   ngx.req.set_uri() 会清掉 r->valid_unparsed_uri，使 proxy_pass 落到
--   会重新转义的分支（%2F -> %252F）。构造完整 URL 交给 proxy_pass $var
--   则走逐字节复制分支，预签名查询串得以原样保留。
-- 关键字数组顺序很重要：/blobs/uploads/ 必须在 /blobs/ 之前匹配。
local REPO_KEYWORDS = { "/manifests/", "/blobs/uploads/", "/blobs/", "/tags/list", "/referrers/" }

local function split_repo(path)
    local rest = path:match("^/v2/(.+)$")
    if not rest then return nil end
    for _, kw in ipairs(REPO_KEYWORDS) do
        local idx = rest:find(kw, 1, true)
        if idx then
            return rest:sub(1, idx - 1)
        end
    end
    return nil
end

local function apply_library_prefix(path, conf)
    if not conf.default_prefix then return path end
    local repo = split_repo(path)
    if not repo or repo == "" or repo:find("/", 1, true) then
        return path
    end
    -- /v2/nginx/manifests/latest -> /v2/library/nginx/manifests/latest
    return "/v2/" .. conf.default_prefix .. path:sub(5)
end

-- cr 统一入口的路径选择器解析。repo 是 /v2/ 之后的仓库名，
-- 例如 "ghcr.io/owner/image" 或 "library/nginx"。
-- 命中时返回（目标配置, 选择器字符串）；未命中返回 nil，
-- 调用方沿用该 subdomain 自身的默认配置（即 Docker Hub）。
-- route() 从 URL path 取 repo，auth() 从 token scope 取 repo，
-- 两边必须调用同一个函数，否则 token 会由错误的 realm/service 签发。
local function cr_select(sub, repo)
    if sub ~= "cr" or type(repo) ~= "string" then return nil end
    local seg = repo:match("^([^/]+)/")
    if not seg then return nil end
    local target = CR_SELECTORS[seg]
    if not target then return nil end
    return target, seg
end

-- ------------------------------------------------------------
-- 4) 对外接口
-- ------------------------------------------------------------

function _M.init_worker()
    ngx.log(ngx.NOTICE, "[init] registry proxy worker initialized")
end

-- location = /
-- registry subdomain -> 301 /v2/ ；其他 subdomain 直接返回，
-- 让 phase 继续走到 index 模块，回落静态站点（不影响 /api/* 等）
function _M.root_redirect()
    if REGISTRIES[ngx.var.subdomain] then
        return ngx.redirect("https://" .. ngx.var.host .. "/v2/", 301)
    end
end

-- location = /v2/ 与 ^~ /v2/ 的 access 阶段
function _M.route()
    local sub  = ngx.var.subdomain
    local conf = REGISTRIES[sub]
    if not conf then
        ngx.log(ngx.WARN, "[route] unknown registry subdomain: ", tostring(sub))
        return respond_json(404, routes_json())
    end

    -- 用原始 request_uri，不用已解码的 ngx.var.uri
    local raw = ngx.var.request_uri or "/"
    local path, qs = raw:match("^([^?]*)%?(.*)$")
    if not path then
        path, qs = raw, nil
    end

    -- cr 统一入口：按仓库名第一段选择真实上游，并把选择器从 path 里剥掉。
    -- 未命中选择器则沿用默认（Docker Hub），不会把任意第一段当上游主机。
    if sub == "cr" then
        local target, seg = cr_select(sub, split_repo(path))
        if target then
            conf = target
            -- "/v2/ghcr.io/owner/img/manifests/tag" -> "/v2/owner/img/manifests/tag"
            -- 必须在 apply_library_prefix 之前剥离，避免 library/ 插到选择器上。
            path = "/v2/" .. path:sub(5 + #seg + 1)
        end
    end

    path = apply_library_prefix(path, conf)

    ngx.var.upstream_url = "https://" .. conf.upstream .. path
                           .. ((qs and qs ~= "") and ("?" .. qs) or "")
    -- 供 fix_response() 判断 Location 是否指向我们刚路由的上游
    ngx.var.reg_upstream = conf.upstream

    -- 注意：这里【完全不碰】Authorization，也不设 Host。
    -- Host 由 proxy_pass 完整 URL 求值出的 $proxy_host 决定。
end

-- location = /v2/ 与 ^~ /v2/ 的 header filter 阶段
-- 把上游的 401 challenge 换成指向本站 /v2/auth 的 challenge。
-- 用 header_filter 而不是 error_page 拦截 401：nginx 拦截 401 时会把上游的
-- WWW-Authenticate 一并复制过来，客户端会看到两个 challenge，第一个指向
-- auth.docker.io，docker 会直接去 Docker Hub 从而绕过本代理。
-- 对 ngx.header 赋值是【替换】语义，天然免疫该问题。
function _M.fix_response()
    if ngx.status == 401 then
        ngx.header["WWW-Authenticate"] = string.format(
            'Bearer realm="https://%s/v2/auth",service="%s"', ngx.var.host, SERVICE)
        if not ngx.header["Docker-Distribution-Api-Version"] then
            ngx.header["Docker-Distribution-Api-Version"] = "registry/2.0"
        end
    end
end

-- location = /v2/auth —— token 中转
function _M.auth()
    local sub        = ngx.var.subdomain
    local entry_conf = REGISTRIES[sub]
    local conf       = entry_conf
    if not conf then
        return respond_json(404, routes_json())
    end

    -- scope 必须用 get_uri_args() 取【已解码】的值。
    -- $arg_scope 是未解码的原始串，而 docker 客户端（Go url.Values.Encode）
    -- 会把 : 编码成 %3A、/ 编码成 %2F。原样透传会让上游返回无 scope 的 token，
    -- 导致每次 pull 都 401 死循环。
    local args = ngx.req.get_uri_args(50)
    local query = {}

    -- 透传客户端其余参数（offline_token / client_id 等）
    for k, v in pairs(args) do
        if k ~= "scope" and k ~= "service" then
            query[k] = v
        end
    end

    -- scope 可以出现多次（跨仓库 blob mount），get_uri_args 对重复 key 返回 table。
    -- cr 入口必须从每个 repository scope 选上游并剥离 selector；若一个请求横跨
    -- 不同 Registry，则没有单一 token endpoint 可正确处理，直接返回明确错误。
    local scope = args.scope
    if scope ~= nil then
        local list = (type(scope) == "table") and scope or { scope }
        local out = {}
        local selected_upstream

        for _, s in ipairs(list) do
            if type(s) == "string" then
                local name, action = s:match("^repository:(.+):([^:]+)$")
                if name and action then
                    local scope_conf = entry_conf
                    local target, seg = cr_select(sub, name)
                    if target then
                        scope_conf = target
                        name = name:sub(#seg + 2)
                    end

                    if selected_upstream and selected_upstream ~= scope_conf.upstream then
                        return respond_registry_error(400, "UNSUPPORTED",
                            "token request contains scopes for multiple registries")
                    end
                    selected_upstream = scope_conf.upstream
                    conf = scope_conf

                    -- repository:nginx:pull -> repository:library/nginx:pull
                    -- action 部分泛化匹配，不写死 pull（还有 pull,push / delete）。
                    if conf.default_prefix and not name:find("/", 1, true) then
                        name = conf.default_prefix .. name
                    end
                    s = "repository:" .. name .. ":" .. action
                end
                out[#out + 1] = s
            end
        end

        if #out > 0 then
            query.scope = (#out == 1) and out[1] or out
        end
        -- scope 解析不出来就【省略】该参数，不发 scope=null
    end

    -- scope-less 请求使用 subdomain 的默认上游；带 scope 的 cr 请求使用上面解析出的上游。
    local info, derr = discover(conf.upstream)
    if not info then
        ngx.log(ngx.ERR, "[auth] discover failed upstream=", conf.upstream, " err=", derr)
        -- 绝不在这里回 401：客户端会带着我们的 realm 再来 /v2/auth，形成死循环
        return respond_registry_error(502, "UNAVAILABLE",
            "upstream auth discovery failed: " .. tostring(derr))
    end
    if info.no_auth then
        -- 上游是公开仓库，不需要 token。给个空 token 让客户端继续。
        return respond_json(200, cjson.encode({ token = "", access_token = "" }))
    end

    -- service 用探测到的值覆盖客户端传来的
    if info.service and info.service ~= "" then
        query.service = info.service
    end

    local realm_host, realm_path = info.realm:match("^https?://([^/]+)(/.*)$")
    if not realm_host then
        realm_host = info.realm:match("^https?://([^/]+)$")
        realm_path = "/"
    end
    if not realm_host then
        ngx.log(ngx.ERR, "[auth] bad realm url: ", tostring(info.realm))
        return respond_registry_error(502, "UNAVAILABLE", "bad realm url")
    end

    local httpc = http.new()
    httpc:set_timeout(5000)

    local ok, cerr = httpc:connect(realm_host, 443)
    if not ok then
        ngx.log(ngx.ERR, "[auth] connect realm ", realm_host, " failed: ", tostring(cerr))
        return respond_registry_error(502, "UNAVAILABLE", "connect token endpoint failed")
    end
    local sok, serr = httpc:ssl_handshake(nil, realm_host, true)
    if not sok then
        httpc:close()
        ngx.log(ngx.ERR, "[auth] tls to realm ", realm_host, " failed: ", tostring(serr))
        return respond_registry_error(502, "UNAVAILABLE", "tls to token endpoint failed")
    end

    -- 原样转发客户端的 Authorization —— docker login 靠这个把 Basic 凭据送到上游，
    -- 从而按用户账号计配额，而不是所有人共享代理出口 IP 的匿名配额。
    local fwd = {
        ["Host"]       = realm_host,
        ["Accept"]     = ngx.var.http_accept or "*/*",
        ["User-Agent"] = ngx.var.http_user_agent or "registry-proxy",
    }
    local client_auth = ngx.var.http_authorization
    if client_auth then
        fwd["Authorization"] = client_auth
    end

    local res, rerr = httpc:request({
        method  = "GET",
        path    = realm_path .. "?" .. ngx.encode_args(query),
        headers = fwd,
    })
    if not res then
        httpc:close()
        ngx.log(ngx.ERR, "[auth] token request failed: ", tostring(rerr))
        return respond_registry_error(502, "UNAVAILABLE", "token request failed")
    end

    local body = res:read_body()
    httpc:set_keepalive(10000, 50)

    -- 上游怎么答就怎么回，包括 401（凭据错误）。
    -- 这里绝不能把 401 改写成指向本站 realm 的 challenge，否则 docker login 死循环。
    ngx.status = res.status
    ngx.header["Content-Type"] = res.headers["Content-Type"] or "application/json"
    if body and #body > 0 then
        ngx.header["Content-Length"] = #body
        ngx.print(body)
    end
    ngx.send_headers()
    return ngx.exit(ngx.HTTP_OK)
end

-- location @follow —— 服务端跟随 blob 重定向
-- 必须在 rewrite 阶段读 $upstream_http_location：
-- content 阶段时 ngx_http_upstream_create() 已把 r->upstream 清零，读出来是空串。
local MAX_FOLLOW_HOPS = 4

local function is_private_host(host)
    -- 只挡明文 IP 字面量；域名解析后的私网地址不在此拦截范围（成本过高）
    local a, b = host:match("^(%d+)%.(%d+)%.[%d]+%.[%d]+$")
    if not a then
        return host == "localhost" or host == "[::1]"
    end
    a, b = tonumber(a), tonumber(b)
    if a == 127 or a == 10 or a == 0 then return true end
    if a == 169 and b == 254 then return true end          -- 含 169.254.169.254 元数据端点
    if a == 172 and b >= 16 and b <= 31 then return true end
    if a == 192 and b == 168 then return true end
    return false
end

function _M.prepare_follow()
    local loc = ngx.var.upstream_http_location

    if not loc or loc == "" then
        ngx.log(ngx.ERR, "[follow] empty Location header")
        return ngx.exit(502)
    end

    -- 相对 Location：按上一跳的 base 解析成绝对 URL
    if not loc:match("^https?://") then
        local base = ngx.var.follow_url
        if base == nil or base == "" then
            base = ngx.var.upstream_url or ""
        end
        local scheme, host, path = base:match("^(https?)://([^/]+)(/?[^?]*)")
        if not scheme then
            ngx.log(ngx.ERR, "[follow] relative Location but no usable base: ", loc)
            return ngx.exit(502)
        end
        if loc:sub(1, 1) == "/" then
            loc = scheme .. "://" .. host .. loc
        else
            local dir = path:match("^(.*/)") or "/"
            loc = scheme .. "://" .. host .. dir .. loc
        end
    end

    local host = loc:match("^https?://([^/:]+)")
    if not host then
        ngx.log(ngx.ERR, "[follow] cannot parse host from Location: ", loc)
        return ngx.exit(502)
    end

    -- 自环保护：上游把我们指回自己
    if host == ngx.var.host then
        ngx.log(ngx.ERR, "[follow] self-referential Location: ", loc)
        return ngx.exit(502)
    end

    -- SSRF 加固：@follow 的目标由第三方响应头决定
    if is_private_host(host) then
        ngx.log(ngx.ERR, "[follow] refusing private/loopback target: ", host)
        return ngx.exit(502)
    end

    -- 非 GET/HEAD 不能跟随：proxy_request_buffering off 下请求体已流走，无法重放。
    -- 把 307 交回客户端。用 send_headers + exit(OK)，
    -- 直接 ngx.exit(307) 会再次触发 error_page 307 = @follow 自环。
    local method = ngx.req.get_method()
    if method ~= "GET" and method ~= "HEAD" then
        ngx.status = 307
        ngx.header["Location"] = loc
        ngx.header["Content-Length"] = 0
        ngx.send_headers()
        return ngx.exit(ngx.HTTP_OK)
    end

    -- hop 计数必须用 nginx 变量：ngx_http_named_location() 会 memzero r->ctx，
    -- ngx.ctx 每跳都会被清空，计数器永远读到 0。
    local hops = (tonumber(ngx.var.follow_hops) or 0) + 1
    if hops > MAX_FOLLOW_HOPS then
        ngx.log(ngx.ERR, "[follow] hop limit exceeded (", MAX_FOLLOW_HOPS, "), last=", loc)
        return ngx.exit(502)
    end
    ngx.var.follow_hops = tostring(hops)

    ngx.var.follow_url = loc
end

return _M
