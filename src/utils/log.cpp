#include "miner.h"
#include <stdio.h>
#include <stdarg.h>
#include <time.h>
#include <sys/time.h>
#include <unistd.h>

static pthread_mutex_t applog_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_once_t applog_init_once = PTHREAD_ONCE_INIT;
static bool use_colors = false;

static void init_applog(void)
{
    use_colors = isatty(fileno(stderr)) != 0;
}

void applog(int prio, const char *fmt, ...)
{
    const char *color = "";

    /* Quiet mode hides info/debug chatter but keeps share results visible:
     * Accepted/Rejected lines are LOG_NOTICE, and silently mining with no
     * feedback (ccminer -q still shows shares) reads as "not working". */
    if (opt_quiet && prio > LOG_NOTICE)
        return;

    pthread_once(&applog_init_once, init_applog);

    switch (prio) {
    case LOG_ERR:
        color = CL_RED;
        break;
    case LOG_WARNING:
        color = CL_YLW;
        break;
    case LOG_NOTICE:
        color = CL_WHT;
        break;
    case LOG_INFO:
        color = "";
        break;
    case LOG_DEBUG:
    default:
        if (!opt_debug)
            return;
        color = CL_GRY;
        break;
    }

    pthread_mutex_lock(&applog_lock);

    // Timestamp
    struct timeval tv;
    struct tm tm;
    gettimeofday(&tv, NULL);
    localtime_r(&tv.tv_sec, &tm);

    // Print with timestamp and color
    if (use_colors && color[0]) {
        fprintf(stderr, "%s[%02d:%02d:%02d]%s ",
                color, tm.tm_hour, tm.tm_min, tm.tm_sec, CL_N);
    } else {
        fprintf(stderr, "[%02d:%02d:%02d] ",
                tm.tm_hour, tm.tm_min, tm.tm_sec);
    }

    // Print message
    va_list ap;
    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);

    fprintf(stderr, "\n");
    fflush(stderr);

    pthread_mutex_unlock(&applog_lock);
}

void format_hashrate(double hashrate, char *output, size_t output_size)
{
    if (!output || output_size == 0)
        return;

    if (hashrate < 1000.0) {
        snprintf(output, output_size, "%.2f H/s", hashrate);
    } else if (hashrate < 1000000.0) {
        snprintf(output, output_size, "%.2f kH/s", hashrate / 1000.0);
    } else if (hashrate < 1000000000.0) {
        snprintf(output, output_size, "%.2f MH/s", hashrate / 1000000.0);
    } else {
        snprintf(output, output_size, "%.2f GH/s", hashrate / 1000000000.0);
    }
}
