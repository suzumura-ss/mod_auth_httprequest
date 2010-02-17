#include "httpd.h"
#include "http_config.h"
#include "http_protocol.h"
#include "http_request.h"
#include "ap_config.h"
#include "http_log.h"
#include "apr_lib.h"
#include "apr_strings.h"
#include "ap_mpm.h"
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <error.h>
#include <curl/curl.h>

#define UNSET     (-1)
#define DISABLED  (0)
#define ENABLED   (1)

static const char VERSION[] = "mod_auth_httprequest/0.1";
static const char X_AUTH_HTTPREQUEST_URI[] = "X-Auth-HttpRequest-URI";
static const char DUMP_AUTH_RESULT[]       = "X-Auth-HttpRequest-URI_DumpResult";

module AP_MODULE_DECLARE_DATA auth_httprequest_module;

#define AP_LOG_DEBUG(rec, fmt, ...) ap_log_rerror(APLOG_MARK, APLOG_DEBUG,  0, rec, fmt, ##__VA_ARGS__)
#define AP_LOG_INFO(rec, fmt, ...)  ap_log_rerror(APLOG_MARK, APLOG_INFO,   0, rec, "[HttpRequestAuth] " fmt, ##__VA_ARGS__)
#define AP_LOG_WARN(rec, fmt, ...)  ap_log_rerror(APLOG_MARK, APLOG_WARNING,0, rec, "[HttpRequestAuth] " fmt, ##__VA_ARGS__)
#define AP_LOG_ERR(rec, fmt, ...)   ap_log_rerror(APLOG_MARK, APLOG_ERR,    0, rec, "[HttpRequestAuth] " fmt, ##__VA_ARGS__)

// Config store.
typedef struct {
  apr_pool_t*  pool;
  short enabled;
  short dump;
  int   port;
  char* uri;
} auth_conf;


// Callbacks context.
typedef struct {
  request_rec*  rec;
  CURL* curl;
  struct curl_slist* headers;
  int   status;
  apr_bucket_brigade* brigade;
} context;


// Check bypass headers.
static int is_bypass_header(const char* str)
{
  static const char* const bypasses[] = {
    "Date", "Server", "Content-Length",
    "Connection", "Content-Type", "Transfer-Encoding",
    "User-Agent",
    NULL
  };
  static const size_t bypasses_len[] = {
    sizeof("Date")-1, sizeof("Server")-1, sizeof("Content-Length")-1,
    sizeof("Connection")-1, sizeof("Content-Type")-1, sizeof("Transfer-Encoding")-1,
    sizeof("User-Agent")-1,
    0
  };
  int it;

  for(it=0; bypasses[it]; it++) {
    if(strncasecmp(bypasses[it], str, bypasses_len[it])==0) return TRUE;
  }
  return FALSE;
}


// Check break status codes.
static int is_break_status(int code)
{
  switch(code) {
  case HTTP_UNAUTHORIZED:
  case HTTP_FORBIDDEN:
    return TRUE;
  default:
    break;
  }
  return FALSE;
}


// Check authorized codes.
static int is_authorized_status(int code)
{
  switch(code) {
  case HTTP_OK:
  case HTTP_CREATED:
  case HTTP_ACCEPTED:
    return TRUE;
  default:
    break;
  }
  return FALSE;
}


// Bypass output data.
static apr_status_t httprequest_auth_output_filter(ap_filter_t* flt, apr_bucket_brigade* bb)
{
  request_rec* rec = (request_rec*)flt->r;
  context* c = (context*)flt->ctx;
  apr_bucket* b = NULL;

  // Pass thru by request types
  if(rec->main || (rec->handler && strcmp(rec->handler, "default-handler")==0)) goto PASS_THRU;

  // Drop buckets.
  while(!APR_BRIGADE_EMPTY(bb)) {
    b = APR_BRIGADE_FIRST(bb);
    apr_bucket_delete(b);
  }

  // Concat buckets.
  APR_BRIGADE_CONCAT(bb, c->brigade);
  APR_BRIGADE_INSERT_TAIL(bb, apr_bucket_eos_create(bb->bucket_alloc));
  rec->status = c->status;

PASS_THRU:
  ap_remove_output_filter(flt);
  return ap_pass_brigade(flt->next, bb);
}


// apr_table_do() callback proc: Copy headers from apache-request to curl-request.
static int each_headers_proc(void* rec, const char* key, const char* value)
{
  if(!is_bypass_header(key)) {
    context* c = (context*)rec;
    char* h = apr_psprintf(c->rec->pool, "%s: %s", key, value);
    AP_LOG_DEBUG(c->rec, "++ %s", h);
    c->headers = curl_slist_append(c->headers, h);
  }
  return TRUE;
}


// CURLOPT_HEADERFUNCTION callback proc: Copy headers from curl-response to apache-response.
static size_t curl_header_proc(const void* _ptr, size_t size, size_t nmemb, void* _info)
{
  context* c = (context*)_info;
  const char* ptr = (const char*)_ptr;

  if(strncmp(ptr, "HTTP/1.", sizeof("HTTP/1.") - 1)==0) {
    int mv, s;
    if(sscanf(ptr, "HTTP/1.%d %d ", &mv, &s)==2) c->status = s;
    return nmemb;
  }
  
  if(is_break_status(c->status)) {
    char* v = strchr(ptr, ':');
    if(v && v[1] && (!is_bypass_header(ptr))) {
      char* h = apr_pstrdup(c->rec->pool, ptr);
      char* k, *v, *next;
      k = apr_strtok(h, ":", &next);
      v = apr_strtok(next, "\r\n", &next);
      AP_LOG_DEBUG(c->rec, "%s => %s", k, v);
      apr_table_set(c->rec->err_headers_out, k, v);
    }
  }
  return nmemb;
}

// CURLOPT_WRITEFUNCTION callback proc: Copy body from curl-response to apache-response.
static size_t curl_body_proc(const void* _ptr, size_t size, size_t nmemb, void* _info)
{
  context* c = (context*)_info;

  if(is_break_status(c->status)) {
    apr_bucket* b = apr_bucket_heap_create(_ptr, size*nmemb, NULL, c->brigade->bucket_alloc);
    APR_BRIGADE_INSERT_TAIL(c->brigade, b);
    AP_LOG_DEBUG(c->rec, "++ 0x%08lx", (unsigned long)b);
  }
  return nmemb;
}

// Dump authentication result.
static apr_status_t authresultdump_handler(ap_filter_t* flt, apr_bucket_brigade* bb)
{
  request_rec* rec = (request_rec*)flt->r;

  AP_LOG_INFO(rec, "Auth result: user=%s, type=%s", rec->user, rec->ap_auth_type);

  ap_remove_output_filter(flt);
  return ap_pass_brigade(flt->next, bb);
}


//
// Main functions.
//
static int httprequest_auth_handler(request_rec *rec)
{
  auth_conf*  conf = (auth_conf*)ap_get_module_config(rec->per_dir_config, &auth_httprequest_module);
  context     ctx;
  CURLcode    ret;
  int threaded_mpm;
  int code=0;

  if(conf->dump) {
    ap_add_output_filter(DUMP_AUTH_RESULT, apr_pmemdup(rec->pool, &ctx, sizeof(ctx)), rec, rec->connection);
  }
  if(conf->enabled!=ENABLED) return OK;

  AP_LOG_DEBUG(rec, "Incomming %s Enabled=%d, URI=%s, port=%d", __FUNCTION__, conf->enabled, conf->uri, conf->port);
  AP_LOG_DEBUG(rec, "  %s %s", rec->method, rec->uri);
  if(apr_table_get(rec->headers_in, X_AUTH_HTTPREQUEST_URI)!=NULL) {
    AP_LOG_WARN(rec, "Check config. Nested request.");
    return OK;
  }

  // Initialize callback-context.
  ctx.curl = curl_easy_init();
  ctx.rec  = rec;
  ctx.headers = NULL;
  ctx.status = 0;
  ctx.brigade = apr_brigade_create(rec->pool, apr_bucket_alloc_create(rec->pool));

  // Initialize libcurl for MPM.
  ap_mpm_query(AP_MPMQ_IS_THREADED, &threaded_mpm);
  curl_easy_setopt(ctx.curl, CURLOPT_NOSIGNAL, threaded_mpm);

  // Bypass request headers, set 'X-Auth-HttpRequest-URI'.
  apr_table_do(each_headers_proc, &ctx, rec->headers_in, NULL);
  each_headers_proc(&ctx, X_AUTH_HTTPREQUEST_URI, rec->uri);

  // Setup URL, port, to bypass response headers and body.
  if(conf->port!=UNSET) curl_easy_setopt(ctx.curl, CURLOPT_PORT, conf->port);
  curl_easy_setopt(ctx.curl, CURLOPT_URL, apr_psprintf(rec->pool, conf->uri, rec->uri));
  curl_easy_setopt(ctx.curl, CURLOPT_HTTPHEADER, ctx.headers);
  curl_easy_setopt(ctx.curl, CURLOPT_USERAGENT, apr_psprintf(rec->pool, "%s %s", VERSION, curl_version()));
  curl_easy_setopt(ctx.curl, CURLOPT_WRITEHEADER, &ctx);
  curl_easy_setopt(ctx.curl, CURLOPT_HEADERFUNCTION, curl_header_proc);
  curl_easy_setopt(ctx.curl, CURLOPT_WRITEDATA, &ctx);
  curl_easy_setopt(ctx.curl, CURLOPT_WRITEFUNCTION, curl_body_proc);

  // Request.
  ret = curl_easy_perform(ctx.curl);
  curl_easy_getinfo(ctx.curl, CURLINFO_RESPONSE_CODE, &code);
  AP_LOG_DEBUG(rec, "curl result(%d) %d", ret, code);

  // Cleanup.
  curl_slist_free_all(ctx.headers);
  curl_easy_cleanup(ctx.curl);

  // Result.
  if(ret==0) {
    if(is_break_status(code)) {
      // Add output filter for bypassed-response.
      AP_LOG_DEBUG(rec, (code==HTTP_UNAUTHORIZED)? "== HTTP_UNAUTHORIZED": "== HTTP_FORBIDDEN");
      ap_add_output_filter(X_AUTH_HTTPREQUEST_URI, apr_pmemdup(rec->pool, &ctx, sizeof(ctx)), rec, rec->connection);
      return OK; // To be continued to output filter ...
    }

    if(is_authorized_status(code)) {
      // Set 'REMOTE_USER' and 'AUTH_TYPE'.
      rec->user = apr_pstrdup(rec->pool, conf->uri);                      // => ENV['REMOTE_USER']
      rec->ap_auth_type = apr_pstrdup(rec->pool, X_AUTH_HTTPREQUEST_URI); // => ENV['AUTH_TYPE']
      AP_LOG_DEBUG(rec, "== AUTHORIZED(%s, %s)", rec->ap_auth_type, rec->user);
    } else {
      AP_LOG_DEBUG(rec, "== PATH THRU");
    }
  } else {
    AP_LOG_WARN(rec, "Check config. http resuest failed (CURLcode = %d)", ret);
  }

  apr_brigade_destroy(ctx.brigade);
  return OK;
}



//
// Configurators, and Register.
// 
static void* config_create(apr_pool_t* p)
{
  auth_conf* conf = apr_palloc(p, sizeof(auth_conf));
  conf->pool = p;
  conf->enabled = UNSET;
  conf->dump = UNSET;
  conf->port = UNSET;
  conf->uri = NULL;

  return conf;
}
 
static void* config_server_create(apr_pool_t* p, server_rec* r)
{
  return config_create(p);
}
 
static void* config_perdir_create(apr_pool_t* p, char* path)
{
  return config_create(p);
}  
 
static void* config_merge(apr_pool_t* p, void* _base, void* _override)
{
  auth_conf* base = _base, *override = _override;
  auth_conf* conf = (auth_conf*)config_create(p);

  conf->enabled = (override->enabled!=UNSET) ? override->enabled : base->enabled;
  conf->dump = (override->dump!=UNSET) ? override->dump : base->dump;
  conf->port = (override->port!=UNSET) ? override->port : base->port;
  conf->uri  = apr_pstrdup(p, (override->uri!=NULL)? override->uri: base->uri);

  return conf;
}
 
static const char* auth_enable(cmd_parms* cmd, void* _conf, int flag)
{
  auth_conf* conf = _conf;
  conf->enabled = flag ? ENABLED : DISABLED;
  return NULL;
}

static const char* auth_dump(cmd_parms* cmd, void* _conf, int flag)
{
  auth_conf* conf = _conf;
  conf->dump = flag ? ENABLED : DISABLED;
  return NULL;
}

static const char* auth_port(cmd_parms* cmd, void* _conf, const char* param)
{
  auth_conf* conf = _conf;
  conf->port = (int)apr_atoi64(param);
  if(conf->port<=0 || conf->port>65535) {
    conf->port = UNSET;
    return "Wrong numer. Use 1..65535.";
  }
  return NULL;
}

static const char* auth_uri(cmd_parms* cmd, void* _conf, const char* param)
{
  auth_conf* conf = _conf;
  if(ap_is_url(param)) {
    conf->uri = apr_pstrdup(conf->pool, param);
  } else
  if(apr_isalpha(param[0])) {
    conf->uri = apr_pstrdup(conf->pool, param);
  } else
  if(param[0]=='/') {
    conf->uri = apr_psprintf(conf->pool, "localhost%s", param);
  } else {
    return "Bad string for request.";
  }
  return NULL;
}

static const command_rec config_cmds[] = {
  AP_INIT_FLAG( "HttpRequestAuth", auth_enable, NULL, OR_OPTIONS, "On|Off"),
  AP_INIT_FLAG( "HttpRequestAuth-DumpResult", auth_dump, NULL, OR_OPTIONS, "On|Off"),
  AP_INIT_TAKE1("HttpRequestAuth-RequestURI", auth_uri, NULL, OR_OPTIONS, "Authentication request uri"),
  AP_INIT_TAKE1("HttpRequestAuth-RequestPort", auth_port, NULL, OR_OPTIONS, "Authentication request port"),
  { NULL },
};

static void register_hooks(apr_pool_t *p)
{
  ap_hook_access_checker(httprequest_auth_handler, NULL, NULL, APR_HOOK_MIDDLE);
  ap_register_output_filter(X_AUTH_HTTPREQUEST_URI, httprequest_auth_output_filter, NULL, AP_FTYPE_CONTENT_SET);
  ap_register_output_filter(DUMP_AUTH_RESULT, authresultdump_handler, NULL, AP_FTYPE_CONTENT_SET);
}

/* Dispatch list for API hooks */
module AP_MODULE_DECLARE_DATA auth_httprequest_module = {
  STANDARD20_MODULE_STUFF, 
  config_perdir_create, /* create per-dir    config structures */
  config_merge,         /* merge  per-dir    config structures */
  config_server_create, /* create per-server config structures */
  config_merge,         /* merge  per-server config structures */
  config_cmds,          /* table of config file commands       */
  register_hooks        /* register hooks                      */
};
