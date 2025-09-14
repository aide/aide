// watch.c  —  Real-time watcher for AIDE (Linux/inotify)
// gcc -O2 -Wall -Wextra -o aide-watch watch.c
// Requires: Linux, glibc. Run as root (aide needs perms).
// Usage:
//   sudo ./aide-watch \
//        --config /etc/aide/aide.conf \
//        --include /etc --include /bin --include /usr/bin \
//        --exclude /var/log --exclude /tmp \
//        --batch-ms 3000 --debounce-ms 1500
//
// What it does:
// - Recursively watches included directories using inotify
// - Debounces and batches file change events (CREATE/MODIFY/DELETE/ATTRIB/MOVE)
// - On each batch window expiration, collapses changed paths to minimal roots
// - Runs targeted AIDE checks: prefers `aide --path-check <root>`
//   (fallback: generates a temporary scoped config and runs `aide --check`)
// - Logs to stdout; exit non-zero only on fatal errors
//
// Notes:
// - This is "detect-only". It never promotes the AIDE DB.
// - Excludes are simple prefix matches.
// - If you monitor many dirs, consider raising fs.inotify.max_user_watches.
// - You can turn this into a systemd service (unit example after code).

#define _GNU_SOURCE
#include <sys/inotify.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/select.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <signal.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#ifndef PATH_MAX
#define PATH_MAX 4096
#endif

// ---------- small utilities ----------
static volatile sig_atomic_t g_stop = 0;
static void on_signal(int sig){ (void)sig; g_stop = 1; }

static uint64_t now_ms(void){
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec*1000ULL + (uint64_t)(ts.tv_nsec/1000000ULL);
}

static void die(const char* fmt, ...){
    va_list ap; va_start(ap, fmt);
    vfprintf(stderr, fmt, ap); va_end(ap);
    fprintf(stderr, "\n");
    exit(1);
}

static void logi(const char* fmt, ...){
    va_list ap; va_start(ap, fmt);
    vfprintf(stdout, fmt, ap); va_end(ap);
    fprintf(stdout, "\n"); fflush(stdout);
}

static bool starts_with(const char* s, const char* p) {
    size_t ls=strlen(s), lp=strlen(p);
    if(lp>ls) return false;
    return strncmp(s,p,lp)==0;
}

static bool is_dir(const char* path) {
    struct stat st;
    if(lstat(path, &st)!=0) return false;
    return S_ISDIR(st.st_mode);
}

static bool is_dot_dir(const char* name){
    return (strcmp(name,".")==0 || strcmp(name,"..")==0);
}

// ---------- config / args ----------
typedef struct {
    char** includes; int n_includes;
    char** excludes; int n_excludes;
    char  aide_conf[PATH_MAX];
    int   batch_ms;
    int   debounce_ms;
} cfg_t;

static void cfg_init(cfg_t* c){
    c->includes=NULL; c->n_includes=0;
    c->excludes=NULL; c->n_excludes=0;
    c->aide_conf[0]='\0';
    c->batch_ms=3000;
    c->debounce_ms=1500;
}

static void arr_push(char*** arr, int* n, const char* s){
    *arr = (char**)realloc(*arr, sizeof(char*)*(*n+1));
    (*arr)[*n] = strdup(s);
    (*n)++;
}

static void parse_args(cfg_t* c, int argc, char** argv){
    for(int i=1;i<argc;i++){
        if(strcmp(argv[i],"--include")==0 && i+1<argc) {
            arr_push(&c->includes,&c->n_includes,argv[++i]);
        } else if(strcmp(argv[i],"--exclude")==0 && i+1<argc) {
            arr_push(&c->excludes,&c->n_excludes,argv[++i]);
        } else if(strcmp(argv[i],"--config")==0 && i+1<argc) {
            strncpy(c->aide_conf, argv[++i], sizeof(c->aide_conf)-1);
        } else if(strcmp(argv[i],"--batch-ms")==0 && i+1<argc) {
            c->batch_ms = atoi(argv[++i]);
        } else if(strcmp(argv[i],"--debounce-ms")==0 && i+1<argc) {
            c->debounce_ms = atoi(argv[++i]);
        } else if(strcmp(argv[i],"--help")==0) {
            printf("Usage: %s --config /etc/aide/aide.conf "
                   "--include <dir> [--include <dir> ...] "
                   "[--exclude <dir> ...] [--batch-ms N] [--debounce-ms N]\n", argv[0]);
            exit(0);
        } else {
            die("Unknown arg: %s (use --help)", argv[i]);
        }
    }
    if(c->n_includes==0) die("Must specify at least one --include");
    if(c->aide_conf[0]=='\0') die("Must specify --config /path/to/aide.conf");
}

// ---------- exclude check ----------
static bool is_excluded(const cfg_t* c, const char* path){
    for(int i=0;i<c->n_excludes;i++){
        if(starts_with(path, c->excludes[i])) return true;
    }
    return false;
}

// ---------- watch table (wd -> dir path) ----------
typedef struct {
    int wd;
    char path[PATH_MAX];
} wd_ent_t;

typedef struct {
    wd_ent_t* v; int n, cap;
} wd_tbl_t;

static void wd_add(wd_tbl_t* t, int wd, const char* path){
    if(t->n==t->cap){ t->cap = t->cap? t->cap*2:128; t->v = realloc(t->v, t->cap*sizeof(wd_ent_t)); }
    t->v[t->n].wd = wd;
    strncpy(t->v[t->n].path, path, PATH_MAX-1);
    t->v[t->n].path[PATH_MAX-1]='\0';
    t->n++;
}

static const char* wd_find(const wd_tbl_t* t, int wd){
    for(int i=0;i<t->n;i++) if(t->v[i].wd==wd) return t->v[i].path;
    return NULL;
}

// ---------- recursive watch ----------
static int inoty_fd = -1;

static void add_watch_dir_recursive(const cfg_t* c, wd_tbl_t* table, const char* root){
    // Skip excluded roots
    if(is_excluded(c, root)) return;
    if(!is_dir(root)) return;

    int wd = inotify_add_watch(inoty_fd, root, 
        IN_CREATE|IN_MODIFY|IN_DELETE|IN_ATTRIB|IN_MOVED_FROM|IN_MOVED_TO|IN_CLOSE_WRITE);
    if(wd<0){
        logi("[warn] inotify_add_watch failed for %s: %s", root, strerror(errno));
    } else {
        wd_add(table, wd, root);
        // Recurse
        DIR* d = opendir(root);
        if(!d) return;
        struct dirent* de;
        char path[PATH_MAX];
        while((de=readdir(d))){
            if(is_dot_dir(de->d_name)) continue;
            snprintf(path, sizeof(path), "%s/%s", root, de->d_name);
            if(is_dir(path)) add_watch_dir_recursive(c, table, path);
        }
        closedir(d);
    }
}

static void add_all_includes(const cfg_t* c, wd_tbl_t* table){
    for(int i=0;i<c->n_includes;i++){
        add_watch_dir_recursive(c, table, c->includes[i]);
    }
}

// ---------- changed paths set (dedupe) ----------
typedef struct node_s {
    char path[PATH_MAX];
    uint64_t last_ts;
    struct node_s* next;
} node_t;

static bool set_contains(node_t* head, const char* path){
    for(node_t* p=head;p;p=p->next) if(strcmp(p->path, path)==0) return true;
    return false;
}

static void set_add(node_t** head, const char* path, uint64_t ts){
    if(set_contains(*head, path)) return;
    node_t* n = (node_t*)malloc(sizeof(node_t));
    strncpy(n->path, path, PATH_MAX-1); n->path[PATH_MAX-1]='\0';
    n->last_ts = ts;
    n->next = *head; *head = n;
}

static void set_free(node_t** head){
    node_t* p=*head;
    while(p){ node_t* q=p->next; free(p); p=q; }
    *head=NULL;
}

// ---------- collapse to roots ----------
static bool is_parent_or_same(const char* parent, const char* child){
    size_t lp=strlen(parent);
    if(strncmp(parent, child, lp)!=0) return false;
    if(child[lp]=='\0') return true;
    return (child[lp]=='/');
}

static node_t* collapse_roots(node_t* head){
    // naive O(n^2) prune: remove any path that has an ancestor within the set
    for(node_t* p=head;p;p=p->next){
        node_t* prev=NULL;
        for(node_t* q=head;q;){
            if(q!=p && is_parent_or_same(p->path, q->path)){
                // remove q
                node_t* tmp = q->next;
                if(prev) prev->next = tmp; else head = tmp;
                if(q==p){ q=tmp; continue; } // shouldn't happen since q!=p
                free(q);
                q=tmp;
            } else { prev=q; q=q->next; }
        }
    }
    return head;
}

// ---------- exec helpers ----------
static int exec_cmd_capture(const char* cmd){
    logi("[exec] %s", cmd);
    int rc = system(cmd);
    if(rc==-1){
        logi("[error] system() failed: %s", strerror(errno));
        return -1;
    }
    if(WIFEXITED(rc)) return WEXITSTATUS(rc);
    if(WIFSIGNALED(rc)) {
        logi("[error] command killed by signal %d", WTERMSIG(rc));
        return 128+WTERMSIG(rc);
    }
    return rc;
}

static bool aide_has_path_check(void){
    // quick heuristic: `aide --help | grep -q path-check`
    int rc = system("aide --help 2>/dev/null | grep -q -- '--path-check'");
    return (rc==0);
}

static int run_aide_tempconf(const cfg_t* c, node_t* roots){
    // Create a tiny temp conf that reuses the real DB but narrows scope to the roots.
    char tmpf[] = "/tmp/aide.reactive.XXXXXX";
    int fd = mkstemp(tmpf);
    if(fd<0) { logi("[error] mkstemp failed: %s", strerror(errno)); return 2; }

    FILE* f = fdopen(fd, "w");
    if(!f){ logi("[error] fdopen failed"); close(fd); unlink(tmpf); return 2; }

    // Minimal: database paths inherit from main conf via -c <conf> on cmdline
    // We only need rule lines for roots. We'll use a generic strict rule.
    fprintf(f, "report_url=stdout\n");
    fprintf(f, "@@define STRICT p+i+n+u+g+s+m+c+sha256+acl+selinux+xattrs\n");
    for(node_t* p=roots;p;p=p->next){
        fprintf(f, "%s @@STRICT\n", p->path);
    }
    // Exclusions
    for(int i=0;i<c->n_excludes;i++){
        fprintf(f, "!%s\n", c->excludes[i]);
    }
    fclose(f);

    char cmd[8192];
    // Use main conf for DB/crypto settings (-c), and our temp conf to narrow the tree (--config=file:...)
    // Many AIDE builds accept only one --config, so we rely on `-c` for main and include the narrowed list by file: path
    // For portability, just use our temp conf alone; admins should ensure DB settings in the main conf are default locations.
    // If you want to inherit exactly, you can parse the main conf; keeping simple here.
    snprintf(cmd, sizeof(cmd),
             "aide --check --config %s", tmpf);

    int rc = exec_cmd_capture(cmd);
    unlink(tmpf);
    return rc;
}

static int run_targeted_checks(const cfg_t* c, node_t* roots){
    int worst_rc = 0;
    if(aide_has_path_check()){
        for(node_t* p=roots;p;p=p->next){
            char cmd[8192];
            snprintf(cmd, sizeof(cmd),
                     "aide --path-check '%s' -c '%s'",
                     p->path, c->aide_conf);
            int rc = exec_cmd_capture(cmd);
            if(rc>worst_rc) worst_rc=rc;
        }
        return worst_rc;
    } else {
        // One temp-conf run covering all roots (faster)
        return run_aide_tempconf(c, roots);
    }
}

// ---------- main loop ----------
int main(int argc, char** argv){
    cfg_t cfg; cfg_init(&cfg);
    parse_args(&cfg, argc, argv);

    signal(SIGINT, on_signal);
    signal(SIGTERM, on_signal);

    inoty_fd = inotify_init1(IN_NONBLOCK);
    if(inoty_fd<0) die("inotify_init1 failed: %s", strerror(errno));

    wd_tbl_t table = {0};
    add_all_includes(&cfg, &table);
    if(table.n==0) die("No directories could be watched. Check permissions/paths.");

    logi("[info] watching %d directories", table.n);
    uint64_t last_flush = now_ms();

    node_t* changed = NULL; // set of changed paths (files or dirs)
    // simple debounce cache: a linked list with timestamps
    node_t* debounced = NULL;

    while(!g_stop){
        fd_set rfds; FD_ZERO(&rfds); FD_SET(inoty_fd, &rfds);
        struct timeval tv;
        int to_ms = cfg.batch_ms>0 ? cfg.batch_ms : 1000;
        tv.tv_sec = to_ms/1000; tv.tv_usec = (to_ms%1000)*1000;

        int sel = select(inoty_fd+1, &rfds, NULL, NULL, &tv);
        if(sel < 0){
            if(errno==EINTR) continue;
            die("select failed: %s", strerror(errno));
        }

        // read all available events
        if(sel>0 && FD_ISSET(inoty_fd, &rfds)){
            char buf[64*1024];
            ssize_t len = read(inoty_fd, buf, sizeof(buf));
            if(len < 0){
                if(errno==EAGAIN || errno==EINTR) { /* try later */ }
                else logi("[warn] read error: %s", strerror(errno));
            } else if(len==0){
                // nothing
            } else {
                ssize_t i=0;
                while(i < len){
                    struct inotify_event *ev = (struct inotify_event*)&buf[i];
                    const char* base = wd_find(&table, ev->wd);
                    if(base){
                        char full[PATH_MAX];
                        if(ev->len>0 && ev->name[0]){
                            snprintf(full, sizeof(full), "%s/%s", base, ev->name);
                        } else {
                            snprintf(full, sizeof(full), "%s", base);
                        }
                        // Debounce
                        bool skip=false;
                        uint64_t t = now_ms();
                        for(node_t* d=debounced; d; d=d->next){
                            if(strcmp(d->path, full)==0){
                                if((int)(t - d->last_ts) < cfg.debounce_ms) { skip=true; }
                                d->last_ts = t;
                                break;
                            }
                        }
                        if(!skip){
                            // add/update debounce entry
                            if(!set_contains(debounced, full)) set_add(&debounced, full, t);
                            // ignore excluded prefixes
                            if(!is_excluded(&cfg, full)){
                                set_add(&changed, full, t);
                                // also add parent dir as a more stable root if file event
                                char parent[PATH_MAX]; strncpy(parent, full, sizeof(parent)-1); parent[sizeof(parent)-1]='\0';
                                char* slash = strrchr(parent, '/');
                                if(slash && slash!=parent){ *slash = '\0'; if(!is_excluded(&cfg, parent)) set_add(&changed, parent, t); }
                            }
                        }
                    }
                    i += sizeof(struct inotify_event) + ev->len;
                }
            }
        }

        uint64_t now = now_ms();
        if((int)(now - last_flush) >= cfg.batch_ms && changed){
            // collapse and run aide
            changed = collapse_roots(changed);
            logi("[info] triggering AIDE on changed roots:");
            for(node_t* p=changed;p;p=p->next) logi("  - %s", p->path);

            int rc = run_targeted_checks(&cfg, changed);
            if(rc==0) logi("[info] AIDE check: no problems detected");
            else logi("[warn] AIDE check returned rc=%d (see above output for details)", rc);

            set_free(&changed);
            last_flush = now_ms();
        }
    }

    logi("[info] stopping...");
    set_free(&changed);
    set_free(&debounced);
    close(inoty_fd);
    return 0;
}
