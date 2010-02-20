#include "httpd.h"
#include "http_config.h"
#include "http_protocol.h"
#include "http_request.h"
#include "http_log.h"
#include "http_core.h"
#include "ap_config.h"
#include "ap_mpm.h"
#include "apr_lib.h"
#include "apr_strings.h"
#include "util_md5.h"
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <error.h>
#include <curl/curl.h>

#include "mod_auth.h"

#define UNSET     (-1)
#define DISABLED  (0)
#define ENABLED   (1)

#define HR_AUTH   "AuthHttpRequest"
#define X_HR_AUTH "X-Auth-HttpRequest"
static const char VERSION[] = "mod_auth_httprequest/0.1";
static const char X_AUTH_HTTPREQUEST_URL[]  = X_HR_AUTH "-URL";
static const char SECRET[]           = X_HR_AUTH "-Secret";
static const char DUMP_AUTH_RESULT[] = X_HR_AUTH "-DumpResult";

module AP_MODULE_DECLARE_DATA auth_httprequest_module;

#define AP_LOG_DEBUG(rec, fmt, ...) ap_log_rerror(APLOG_MARK, APLOG_DEBUG,  0, rec, fmt, ##__VA_ARGS__)
#define AP_LOG_INFO(rec, fmt, ...)  ap_log_rerror(APLOG_MARK, APLOG_INFO,   0, rec, "[" HR_AUTH "] " fmt, ##__VA_ARGS__)
#define AP_LOG_WARN(rec, fmt, ...)  ap_log_rerror(APLOG_MARK, APLOG_WARNING,0, rec, "[" HR_AUTH "] " fmt, ##__VA_ARGS__)
#define AP_LOG_ERR(rec, fmt, ...)   ap_log_rerror(APLOG_MARK, APLOG_ERR,    0, rec, "[" HR_AUTH "] " fmt, ##__VA_ARGS__)

// Config store.
typedef struct {
  apr_pool_t*  pool;
  char* url;
  char* secret;
  char* errdoc;
  int   dump;
} auth_conf;


// Callbacks context.
typedef struct {
  request_rec*  rec;
  CURL* curl;
  struct curl_slist* headers;
  int   status;
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


// Check break status codes.
static int is_break_status(int code)
{
  return !is_authorized_status(code);
}


// Check authentication type.
static int is_auth_httprequest_required(request_rec* rec)
{
  const apr_array_header_t* requires = ap_requires(rec);
  struct require_line* rl = (struct require_line*)requires->elts;
  int it;

  AP_LOG_DEBUG(rec, "  Core::AuthType=%s", ap_auth_type(rec));
  AP_LOG_DEBUG(rec, "  Core::AuthName=%s", ap_auth_name(rec));

  if(strcasecmp(ap_auth_type(rec), HR_AUTH)!=0) return FALSE; // Type is not match.
  for(it=0; it<requires->nelts; it++) {
    AP_LOG_DEBUG(rec, "  Core::Requires[%d]=%s", it, rl[it].requirement);
    if(strcasecmp(rl[it].requirement, "valid-request")==0) return TRUE;  // Found.
  }
  return FALSE;
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


// Dump authentication result.
static apr_status_t auth_result_dump_filter(ap_filter_t* flt, apr_bucket_brigade* bb)
{
  request_rec* rec = (request_rec*)flt->r;

  AP_LOG_INFO(rec, "Auth result: user=%s, type=%s", rec->user, rec->ap_auth_type);

  ap_remove_output_filter(flt);
  return ap_pass_brigade(flt->next, bb);
}


//
// Main functions.
//
static int check_auth_handler(request_rec *rec)
{
  auth_conf*  conf = (auth_conf*)ap_get_module_config(rec->per_dir_config, &auth_httprequest_module);
  context     ctx;
  CURLcode    ret;
  const char* secret, *url;
  int threaded_mpm;
  int code=0;

  AP_LOG_DEBUG(rec, "Incomming %s URI=%s", __FUNCTION__, conf->url);

  // Check requires.
  if(!is_auth_httprequest_required(rec))  return DECLINED;  // Not required.
  if(!conf->url[0]) return OK;  // URL is empty.

  AP_LOG_DEBUG(rec, "  %s %s", rec->method, rec->uri);

  // Enable to dump authorize result.
  if(conf->dump==ENABLED) {
    ap_add_output_filter(DUMP_AUTH_RESULT, apr_pmemdup(rec->pool, &ctx, sizeof(ctx)), rec, rec->connection);
  }

  // Skip nested request.
  secret = apr_table_get(rec->headers_in, SECRET);
  if(secret) {
    AP_LOG_DEBUG(rec, "  %s: %s", SECRET, secret);
    if(strstr(secret, conf->secret)) {
      AP_LOG_DEBUG(rec, "Check config. Nested request.");
      rec->user = apr_pstrdup(rec->pool, conf->url);  
      return OK;
    }
  }

  // Initialize callback-context.
  ctx.curl = curl_easy_init();
  ctx.rec  = rec;
  ctx.headers = NULL;
  ctx.status = 0;

  // Initialize libcurl for MPM.
  ap_mpm_query(AP_MPMQ_IS_THREADED, &threaded_mpm);
  curl_easy_setopt(ctx.curl, CURLOPT_NOSIGNAL, threaded_mpm);

  // Bypass request headers, set 'X-Auth-HttpRequest-URI'.
  apr_table_do(each_headers_proc, &ctx, rec->headers_in, NULL);
  each_headers_proc(&ctx, X_AUTH_HTTPREQUEST_URL, rec->uri);
  each_headers_proc(&ctx, SECRET, conf->secret);

  // Setup URL to bypass response headers and body.
  curl_easy_setopt(ctx.curl, CURLOPT_URL, url = apr_psprintf(rec->pool, conf->url, rec->uri));
  curl_easy_setopt(ctx.curl, CURLOPT_CUSTOMREQUEST, "HEAD");
  curl_easy_setopt(ctx.curl, CURLOPT_HTTPHEADER, ctx.headers);
  curl_easy_setopt(ctx.curl, CURLOPT_USERAGENT, apr_psprintf(rec->pool, "%s %s", VERSION, curl_version()));
  curl_easy_setopt(ctx.curl, CURLOPT_WRITEHEADER, &ctx);
  curl_easy_setopt(ctx.curl, CURLOPT_HEADERFUNCTION, curl_header_proc);

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
      // Break request, set custom response.
      if(conf->errdoc) {
        char* msg = apr_psprintf(rec->pool, conf->errdoc, code);
        AP_LOG_DEBUG(rec, "Custom response: %s", msg);
        ap_custom_response(rec, code, msg);
      }
      return code;
    }

    if(is_authorized_status(code)) {
      // Set 'REMOTE_USER' and 'AUTH_TYPE'.
      rec->user = apr_pstrdup(rec->pool, conf->url); // => ENV['REMOTE_USER']
      AP_LOG_DEBUG(rec, "== AUTHORIZED(%s, %s)", rec->ap_auth_type, rec->user);
    } else {
      AP_LOG_DEBUG(rec, "== PATH THRU");
    }
  } else {
    static const char* const ce[8] = {
      "", "E_PROTOCOL", "E_INIT", "E_MALFORMAT",
      "E_MALFORMAT_USER", "E_PROXY", "E_HOST", "E_CONNECT",
    };
    AP_LOG_WARN(rec, "Check config. http resuest failed [%s] %s(CURLcode = %d)", url, ((ret<8)? ce[ret]: ce[0]), ret);
    
  }

  return OK;
}

// Break request.
static int break_request_handler(request_rec *rec)
{
  AP_LOG_DEBUG(rec, "Incomming %s", __FUNCTION__);
  if(!is_auth_httprequest_required(rec))  return DECLINED;  // Not required.
  return is_break_status(rec->status)? rec->status: OK;
}



//
// Configurators, and Register.
// 
static const char* auth_url(cmd_parms* cmd, void* _conf, const char* param)
{
  auth_conf* conf = _conf;
  if(ap_is_url(param)) {
    conf->url = apr_pstrdup(conf->pool, param);
  } else
  if(apr_isalpha(param[0])) {
    conf->url = apr_pstrdup(conf->pool, param);
  } else
  if(param[0]=='/') {
    conf->url = apr_psprintf(conf->pool, "localhost%s", param);
  } else {
    return "Bad string for request.";
  }
  return NULL;
}

static const char* auth_secret(cmd_parms* cmd, void* _conf, const char* param)
{
  auth_conf* conf = _conf;
  int fd, rd=0;
  unsigned char buf[256];

  if((fd=open(param, O_RDONLY))>=0) {
    rd = read(fd, buf, sizeof(buf));
    conf->secret = ap_md5_binary(conf->pool, buf, rd);
    close(fd);
  } else {
    return "Could not open file.";
  }
  return NULL;
}

static void* config_create(apr_pool_t* p, char* path)
{
  auth_conf* conf = apr_palloc(p, sizeof(auth_conf));
  conf->pool = p;
  conf->dump = UNSET;
  conf->url = "localhost%s";
  conf->secret = apr_pstrdup(p, "b41d38160ff124d7ecfe717e657846db");
  conf->errdoc = NULL;

  return conf;
}
 
static const command_rec config_cmds[] = {
  AP_INIT_TAKE1(HR_AUTH "-URL", auth_url, NULL, OR_AUTHCFG, HR_AUTH ": Authentication request url."),
  AP_INIT_TAKE1(HR_AUTH "-Secret", auth_secret, NULL, OR_OPTIONS, HR_AUTH "-Secret: Source file name for MD5."),
  AP_INIT_TAKE1(HR_AUTH "-ErrorDocument", ap_set_string_slot, (void*)APR_OFFSETOF(auth_conf, errdoc),
                                          OR_OPTIONS, HR_AUTH "-ErrorDocument: ErrorDocument."),
  AP_INIT_FLAG (HR_AUTH "-DumpResult", ap_set_flag_slot, (void*)APR_OFFSETOF(auth_conf, dump), OR_OPTIONS, ""),
  { NULL },
};

static void register_hooks(apr_pool_t *p)
{
  ap_hook_check_user_id(check_auth_handler, NULL, NULL, APR_HOOK_MIDDLE);
  ap_hook_auth_checker(break_request_handler, NULL, NULL, APR_HOOK_MIDDLE);
  ap_register_output_filter(DUMP_AUTH_RESULT, auth_result_dump_filter, NULL, AP_FTYPE_CONTENT_SET);
}

/* Dispatch list for API hooks */
module AP_MODULE_DECLARE_DATA auth_httprequest_module = {
  STANDARD20_MODULE_STUFF, 
  config_create,  /* create per-dir    config structures */
  NULL,           /* merge  per-dir    config structures */
  NULL,           /* create per-server config structures */
  NULL,           /* merge  per-server config structures */
  config_cmds,    /* table of config file commands       */
  register_hooks  /* register hooks                      */
};
