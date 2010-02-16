#include "httpd.h"
#include "http_config.h"
#include "http_protocol.h"
#include "http_request.h"
#include "ap_config.h"
#include "http_log.h"
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

module AP_MODULE_DECLARE_DATA auth_httprequest_module;

#define AP_LOG_DEBUG(rec, fmt, ...) ap_log_rerror(APLOG_MARK, APLOG_DEBUG,  0, rec, fmt, ##__VA_ARGS__)
#define AP_LOG_INFO(rec, fmt, ...)  ap_log_rerror(APLOG_MARK, APLOG_INFO,   0, rec, fmt, ##__VA_ARGS__)
#define AP_LOG_WARN(rec, fmt, ...)  ap_log_rerror(APLOG_MARK, APLOG_WARNING,0, rec, "[HttpRequestAuth] " fmt, ##__VA_ARGS__)
#define AP_LOG_ERR(rec, fmt, ...)   ap_log_rerror(APLOG_MARK, APLOG_ERR,    0, rec, "[HttpRequestAuth] " fmt, ##__VA_ARGS__)

// Config store.
typedef struct {
  int   enabled;
  char  uri[128];
  int   port;
} auth_conf;


// curl handlings in enum headers.
typedef struct {
  request_rec*  rec;
  CURL*   curl;
  struct curl_slist* headers;
  int   result_status;
  int   tmp_fd;
  char* tmp_name;
} enum_headers;


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
};


// Bypass output data.
static apr_status_t httprequest_auth_output_filter(ap_filter_t* flt, apr_bucket_brigade* bb)
{
  request_rec* rec = (request_rec*)flt->r;
  enum_headers* e = (enum_headers*)flt->ctx;
  apr_bucket* b = NULL;
  struct stat s;
  void* buf = NULL;

  // Pass thru by request types
  if(rec->main || (rec->handler && strcmp(rec->handler, "default-handler")==0)) goto PASS_THRU;

  AP_LOG_DEBUG(rec, "Incoming %s", __FUNCTION__);

  // Drop buckets.
  AP_LOG_DEBUG(rec, "-- Dropping bucket.");
  while(!APR_BRIGADE_EMPTY(bb)) {
    b = APR_BRIGADE_FIRST(bb);
    apr_bucket_delete(b);
  }
  AP_LOG_DEBUG(rec, "-- Building bucket.");
  for(;;) {
    if((e->tmp_fd=open(e->tmp_name, O_RDONLY))<0) break;
    if(fstat(e->tmp_fd, &s)<0) break;
    if((buf=malloc(s.st_size))==NULL) break;
    if(read(e->tmp_fd, buf, s.st_size)!=s.st_size) break;
    close(e->tmp_fd);
    e->tmp_fd = -1;
    APR_BRIGADE_INSERT_TAIL(bb, apr_bucket_heap_create(buf, s.st_size, free, bb->bucket_alloc));
    APR_BRIGADE_INSERT_TAIL(bb, apr_bucket_eos_create(bb->bucket_alloc));
    rec->status = e->result_status;
    goto PASS_THRU;
  }
  AP_LOG_ERR(rec, "Bucket build failed. fd=%d, buf=0x%08x (%s).", e->tmp_fd, (unsigned int)buf, strerror(errno));
  if(e->tmp_fd>=0) close(e->tmp_fd);
  free(buf);
  e->tmp_fd = -1;
  rec->status = HTTP_INTERNAL_SERVER_ERROR;
  ap_send_error_response(rec, 0);
  return rec->status;

PASS_THRU:
  AP_LOG_DEBUG(rec, "-- done.");
  ap_remove_output_filter(flt);
  return ap_pass_brigade(flt->next, bb);
}


// apr_table_do() callback proc: Copy headers from apache-request to curl-request.
static int each_headers_proc(void* rec, const char* key, const char* value)
{
  if(!is_bypass_header(key)) {
    enum_headers* e = (enum_headers*)rec;
    char* h = apr_psprintf(e->rec->pool, "%s: %s", key, value);
    AP_LOG_DEBUG(e->rec, "++ %s", h);
    e->headers = curl_slist_append(e->headers, h);
  }
  return TRUE;
}


// CURLOPT_HEADERFUNCTION callback proc: Copy headers from curl-response to apache-response.
static size_t curl_header_proc(const void* _ptr, size_t size, size_t nmemb, void* _info)
{
  enum_headers* e = (enum_headers*)_info;
  const char* ptr = (const char*)_ptr;

  if(strncmp(ptr, "HTTP/1.", sizeof("HTTP/1.") - 1)==0) {
    int mv, s;
    if(sscanf(ptr, "HTTP/1.%d %d ", &mv, &s)==2) e->result_status = s;
    if((e->result_status==HTTP_UNAUTHORIZED) || (e->result_status==HTTP_FORBIDDEN)) {
      e->tmp_fd = mkstemp(e->tmp_name);
      if(e->tmp_fd<0) AP_LOG_ERR(e->rec, "Failed to open tmpfile(%s)", strerror(errno));
    }
    return nmemb;
  }
  
  if((e->result_status==HTTP_UNAUTHORIZED) || (e->result_status==HTTP_FORBIDDEN)) {
    char* v = strchr(ptr, ':');
    if(v && v[1] && (!is_bypass_header(ptr))) {
      char* h = apr_pstrdup(e->rec->pool, ptr);
      char* k, *v, *next;
      k = apr_strtok(h, ":", &next);
      v = apr_strtok(next, "\r\n", &next);
      AP_LOG_DEBUG(e->rec, "%s => %s", k, v);
      apr_table_set(e->rec->err_headers_out, k, v);
    }
  }
  return nmemb;
}

// CURLOPT_WRITEFUNCTION callback proc: Copy body from curl-response to apache-response.
static size_t curl_body_proc(const void* _ptr, size_t size, size_t nmemb, void* _info)
{
  enum_headers* e = (enum_headers*)_info;

  if(e->tmp_fd>=0) {
    ssize_t w = write(e->tmp_fd, _ptr, size*nmemb);
    if(w!=(size*nmemb)) AP_LOG_WARN(e->rec, "Failed to write to tmpfile(%d)", errno);
  }
  return nmemb;
}


//
// Main functions.
//
static int httprequest_auth_handler(request_rec *rec)
{
  auth_conf*    conf = (auth_conf*)ap_get_module_config(rec->per_dir_config, &auth_httprequest_module);
  enum_headers  eh;
  CURLcode      ret;
  int threaded_mpm;
  int respcode=0;

  AP_LOG_DEBUG(rec, "Incomming %s", __FUNCTION__);
  AP_LOG_DEBUG(rec, "%s %s / %d, %s:%d", rec->method, rec->uri,
      conf->enabled, conf->uri, conf->port);
  if(conf->enabled!=ENABLED) return OK;
  if(apr_table_get(rec->headers_in, X_AUTH_HTTPREQUEST_URI)!=NULL) {
    AP_LOG_WARN(rec, "Check config. Nested request.");
    return OK;
  }

  eh.curl = curl_easy_init();
  eh.rec  = rec;
  eh.headers = NULL;
  eh.result_status = 0;
  ap_mpm_query(AP_MPMQ_IS_THREADED, &threaded_mpm);
  curl_easy_setopt(eh.curl, CURLOPT_NOSIGNAL, threaded_mpm);
  if(conf->port!=UNSET) curl_easy_setopt(eh.curl, CURLOPT_PORT, conf->port);
  curl_easy_setopt(eh.curl, CURLOPT_URL, apr_psprintf(rec->pool, conf->uri, rec->uri));
  apr_table_do(each_headers_proc, &eh, rec->headers_in, NULL);
  each_headers_proc(&eh, X_AUTH_HTTPREQUEST_URI, rec->uri);
  curl_easy_setopt(eh.curl, CURLOPT_HTTPHEADER, eh.headers);
  curl_easy_setopt(eh.curl, CURLOPT_USERAGENT, apr_psprintf(rec->pool, "%s %s", VERSION, curl_version()));
  curl_easy_setopt(eh.curl, CURLOPT_WRITEHEADER, &eh);
  curl_easy_setopt(eh.curl, CURLOPT_HEADERFUNCTION, curl_header_proc);
  curl_easy_setopt(eh.curl, CURLOPT_WRITEDATA, &eh);
  curl_easy_setopt(eh.curl, CURLOPT_WRITEFUNCTION, curl_body_proc);
  eh.tmp_fd = -1;
  eh.tmp_name = apr_psprintf(rec->pool, "%s/XAuthHttpRequest-XXXXXX", "/tmp");
  ret = curl_easy_perform(eh.curl);
  curl_slist_free_all(eh.headers);
  curl_easy_getinfo(eh.curl, CURLINFO_RESPONSE_CODE, &respcode);
  AP_LOG_DEBUG(rec, "curl result(%d) %d", ret, respcode);
  curl_easy_cleanup(eh.curl);

  if(ret==0) {
    switch(respcode) {
    case HTTP_UNAUTHORIZED:
    case HTTP_FORBIDDEN:
      AP_LOG_DEBUG(rec, (respcode==HTTP_UNAUTHORIZED)? "== HTTP_UNAUTHORIZED": "== HTTP_FORBIDDEN");
      if(eh.tmp_fd) {
        close(eh.tmp_fd);
        eh.tmp_fd = -1;
        ap_add_output_filter(X_AUTH_HTTPREQUEST_URI, apr_pmemdup(rec->pool, &eh, sizeof(eh)), rec, rec->connection);
      } else {
         AP_LOG_DEBUG(rec, "*** Why done NOT open !? ***");
      }
      return OK; // To be continued to output filter ...

    case HTTP_OK:
    case HTTP_CREATED:
    case HTTP_ACCEPTED:
      rec->user = apr_pstrdup(rec->pool, "authorized");           // => ENV['REMOTE_USER']
      rec->ap_auth_type = apr_pstrdup(rec->pool, "HttpRequest");  // => ENV['AUTH_TYPE']
      AP_LOG_DEBUG(rec, "== AUTHORIZED(%s, %s)", rec->ap_auth_type, rec->user);
      break;
    default:
      AP_LOG_DEBUG(rec, "== PATH THRU");
      break;
    }
  }
  if(eh.tmp_fd>=0) {
    AP_LOG_DEBUG(rec, "*** Why open it !? ***");
    close(eh.tmp_fd);
  }
  return OK;
}


// dump authentication result.
static void authresultdump_handler(request_rec *rec)
{
  AP_LOG_DEBUG(rec, "Auth result: user=%s, type=%s", rec->user, rec->ap_auth_type);
}


//
// Configurators, and Register.
// 
static void* config_create(apr_pool_t* p)
{
  auth_conf* conf = apr_palloc(p, sizeof(auth_conf));
  conf->enabled = UNSET;
  conf->port = UNSET;
  strcpy(conf->uri, "localhost%s");

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
  auth_conf* conf = apr_palloc(p, sizeof(auth_conf));

  conf->enabled = (override->enabled!=UNSET) ? override->enabled : base->enabled;
  conf->port = (override->port!=UNSET) ? override->port : base->port;
  strncpy(conf->uri, (override->uri[0])  ? override->uri : base->uri, sizeof(conf->uri));

  return conf;
}
 
static const char* auth_enable(cmd_parms* cmd, void* _conf, int flag)
{
  auth_conf* conf = _conf;
  conf->enabled = flag ? ENABLED : DISABLED;
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
  strncpy(conf->uri, param, sizeof(conf->uri));
  return NULL;
}

static const command_rec config_cmds[] = {
  AP_INIT_FLAG( "HttpRequestAuth", auth_enable, NULL, OR_OPTIONS, "On|Off"),
  AP_INIT_TAKE1("HttpRequestAuth-RequestURI", auth_uri, NULL, OR_OPTIONS, "Authentication request uri"),
  AP_INIT_TAKE1("HttpRequestAuth-RequestPort", auth_port, NULL, OR_OPTIONS, "Authentication request port"),
  { NULL },
};

static void register_hooks(apr_pool_t *p)
{
  ap_hook_access_checker(httprequest_auth_handler, NULL, NULL, APR_HOOK_MIDDLE);
  ap_register_output_filter(X_AUTH_HTTPREQUEST_URI, httprequest_auth_output_filter, NULL, AP_FTYPE_CONTENT_SET);
  ap_hook_insert_filter(authresultdump_handler, NULL, NULL, APR_HOOK_LAST);
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
