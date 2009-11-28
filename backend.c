/* Copyright (c) 2007, Matthew W. Jones
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:
 *
 * * Redistributions of source code must retain the above copyright notice,
 *   this list of conditions and the following disclaimer.
 * * Redistributions in binary form must reproduce the above copyright notice,
 *   this list of conditions and the following disclaimer in the documentation
 *   and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR
 * CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
 * EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
 * PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
 * PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
 * LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
 * NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

/* ProcAn backends */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <syslog.h>
#include <stdarg.h>
#include <sys/time.h>
#include <sys/param.h>
#include <pthread.h>
#include <unistd.h>
#include "procan.h"
#include "backend.h"

#if defined (linux)
#define MAXLOGNAME 9
#endif

/* Syslog backend, LOG_NOTICE might bother some people
 * but it is easier than teaching people how to use syslog
 * in the future I would like to add more syslog configuration
 * to the procan config
 */
int syslog_backend(procan_config *pc, struct timeval *schedtime)
{
    int i;
    struct timeval nowtime;

    if (schedtime->tv_sec == 0)
        {
            if (pc->logfrequency == 0)
                return BACKEND_ERROR;
            gettimeofday(schedtime, NULL);
            schedtime->tv_sec = schedtime->tv_sec + ((pc->logfrequency * 60) * 60);
            return BACKEND_NORMAL;
        }

    gettimeofday(&nowtime,NULL);
    if (nowtime.tv_sec >= schedtime->tv_sec)
        {
            printf("Logging to syslog.\n");
            schedtime->tv_sec = nowtime.tv_sec + ((pc->logfrequency * 60) * 60);
            openlog("procan", LOG_CONS, LOG_DAEMON);
            char *info = get_statistics_str();
            syslog(LOG_NOTICE, "Interesting Processes: %s", info);
            //free(info); /* Seems to cause corrupted redzone
            closelog();
        }

    pthread_mutex_lock(&procchart_mutex);
    int *inds = (int *)calloc(numprocavs, sizeof(int));
    int n = get_warns(inds, pc, SYSLOG_BACKEND);
    if (n > 0)
        openlog("procan", LOG_CONS, LOG_DAEMON);
    for (i = 0; i < n; i++)
        {
            if (!procavs[inds[i]].dwarned)
                {
                    syslog(LOG_NOTICE, "WARNING: %s has triggered a warning for being too interesting (%d)",
                           procavs[inds[i]].command, procavs[inds[i]].intrest_score);
                    procavs[inds[i]].dwarned = 1;
                }
        }
    if (n > 0)
        closelog();
    n = get_alarms(inds, pc, SYSLOG_BACKEND);
    if (n > 0)
        openlog("procan", LOG_CONS, LOG_DAEMON);
    for (i = 0; i < n; i++)
        {
            if (!procavs[inds[i]].dalarmed)
                {
                    syslog(LOG_ALERT, "ALERT: %s has triggered an alarm for being too interesting (%d)",
                           procavs[inds[i]].command, procavs[inds[i]].intrest_score           );
                    procavs[inds[i]].dalarmed = 1;
                }
        }
    if (n > 0)
        closelog();
    pthread_mutex_unlock(&procchart_mutex);
    free(inds);
    return BACKEND_NORMAL;
}

/* The mail backend, works in a very similar way to syslog
 * but uses popen to open a pipe to the user supplied MTA
 * "mtapath" in the configuration file
 */
int mail_backend(procan_config *pc, struct timeval *schedtime)
{
    int i;
    FILE *mailpipe=NULL;
    struct timeval nowtime;

    if (schedtime->tv_sec == 0)
        {
            if (pc->mailfrequency == 0 || strcmp(pc->adminemail, "") == 0)
                return BACKEND_ERROR;
            gettimeofday(schedtime, NULL);
            schedtime->tv_sec = schedtime->tv_sec + ((pc->mailfrequency * 60) * 60);
            return BACKEND_NORMAL;
        }

    gettimeofday(&nowtime, NULL);
    if (nowtime.tv_sec >= schedtime->tv_sec)
        {
            char mta[PATH_MAX];

            printf("Logging via mail.\n");
            schedtime->tv_sec = nowtime.tv_sec + ((pc->mailfrequency * 60) * 60);
            snprintf(mta,PATH_MAX,"%s -t %s", pc->mtapath, pc->adminemail);

            if ((mailpipe = popen(mta, "w")) == NULL)
                {
                    printf("Could not send mail with mail backend.\n");
                    return BACKEND_ERROR;
                }
            else
                {
                    char uname[MAXLOGNAME];

                    getlogin_r(uname, MAXLOGNAME);
                    fprintf(mailpipe, "From: %s\n", uname);
                    fprintf(mailpipe, "Subject: Procan Status Report\n");
                    char *info = get_statistics_str();
                    fprintf(mailpipe, "%s", info);
                    pclose(mailpipe);
                    free(info);
                }
        }

    pthread_mutex_lock(&procchart_mutex);
    char mta[PATH_MAX];

    snprintf(mta,PATH_MAX,"%s -t %s", pc->mtapath, pc->adminemail);
    int *inds = (int *)calloc(numprocavs, sizeof(int));
    int n = get_warns(inds, pc, MAIL_BACKEND);
    if (n > 0)
        {
            if ((mailpipe = popen(mta,"w")) == NULL)
                {
                    printf("Could not send mail with mail backend.\n");
                    free(inds);
                    pthread_mutex_unlock(&procchart_mutex);
                    return BACKEND_ERROR;
                }
        }
    for (i = 0; i < n; i++)
        {
            if (!procavs[inds[i]].mwarned)
                {
                    char uname[MAXLOGNAME];

                    getlogin_r(uname, MAXLOGNAME);
                    fprintf(mailpipe, "From: %s\n", uname);
                    fprintf(mailpipe, "Subject: Procan Warning\n");
                    fprintf(mailpipe, "%s has been warned by ProcAn (%d)",
                            procavs[inds[i]].command, procavs[inds[i]].intrest_score);
                    procavs[inds[i]].mwarned = 1;
                }
        }
    if (n > 0)
        pclose(mailpipe);
    n = get_alarms(inds, pc, MAIL_BACKEND);
    if (n > 0)
        {
            if ((mailpipe = popen(mta,"w")) == NULL)
                {
                    printf("Could not send mail with mail backend.\n");
                    free(inds);
                    pthread_mutex_unlock(&procchart_mutex);
                    return BACKEND_ERROR;
                }
        }
    for (i = 0; i < n; i++)
        {
            if (!procavs[inds[i]].malarmed)
                {
                    char uname[MAXLOGNAME];

                    getlogin_r(uname, MAXLOGNAME);
                    fprintf(mailpipe, "From: %s\n", uname);
                    fprintf(mailpipe, "To: %s\n", pc->adminemail);
                    fprintf(mailpipe, "Subject: Procan Alarm\n");
                    fprintf(mailpipe, "%s has triggered an alarm condition (%d)",
                            procavs[inds[i]].command, procavs[inds[i]].intrest_score);
                    procavs[inds[i]].malarmed = 1;
                }
        }
    if (n > 0)
        pclose(mailpipe);
    pthread_mutex_unlock(&procchart_mutex);

    free(inds);
    return BACKEND_NORMAL;
}

/* Script backend */
int script_backend(procan_config *pc)
{
    int *inds = (int *)calloc(numprocavs, sizeof(int));
    pthread_mutex_lock(&procchart_mutex);
    int n = get_warns(inds, pc, SCRIPT_BACKEND);
    int i;
    if (n > 0)
        {
            if (strcmp(pc->warnscript, "") == 0)
                {
                    free(inds);
                    pthread_mutex_unlock(&procchart_mutex);
                    return BACKEND_ERROR;
                }
        }
    for (i = 0; i < n; i++)
        {
            pid_t cp = fork();
            if (cp >= 0)
                {
                    if (cp == 0)
                        {
                            char sargs[100];

                            snprintf(sargs, 100*sizeof(char), "%s %d %s %d %d",
                                     pc->warnscript,
                                     procavs[inds[i]].lastpid,
                                     procavs[inds[i]].command,
                                     procavs[inds[i]].intrest_score,
                                     procavs[inds[i]].num_intrests);
                            system(sargs);
                            _exit(1);
                        }
                    else
                        {
                            procavs[inds[i]].swarned = 1;
                            continue;
                        }
                }
            else
                {
                    free(inds);
                    pthread_mutex_unlock(&procchart_mutex);
                    return BACKEND_ERROR;
                }
        }
    n = get_alarms(inds, pc, SCRIPT_BACKEND);
    if (n > 0)
        {
            if (strcmp(pc->alarmscript, "") == 0)
                {
                    free(inds);
                    pthread_mutex_unlock(&procchart_mutex);
                    return BACKEND_ERROR;
                }
        }
    for (i = 0; i < n; i++)
        {
            pid_t cp = fork();
            if (cp >= 0)
                {
                    if (cp == 0)
                        {
                            char sargs[100];

                            snprintf(sargs, 100*sizeof(char), "%s %d %s %d %d",
                                     pc->alarmscript,
                                     procavs[inds[i]].lastpid,
                                     procavs[inds[i]].command,
                                     procavs[inds[i]].intrest_score,
                                     procavs[inds[i]].num_intrests);
                            system(sargs);
                            _exit(1);
                        }
                    else
                        {
                            procavs[inds[i]].salarmed = 1;
                            continue;
                        }
                }
        }
    free(inds);
    pthread_mutex_unlock(&procchart_mutex);
    return BACKEND_NORMAL;
}

/* Get a list of procavs indices that match our 'warn' condition
 * returns the number of warns that will be present in *indcs
 * caller should handle mutexes and malloc
 */
int get_warns(int *indcs, procan_config *pc, int backendtype)
{
    int nwarns = 0;
    int i;
    for (i = 0; i < numprocavs; i++)
        {
            if (procavs[i].num_intrests > pc->warnlevel)
                {
                    switch (backendtype)
                        {
                        case MAIL_BACKEND:
                            if (procavs[i].mwarned)
                                continue;
                            break;
                        case SYSLOG_BACKEND:
                            if (procavs[i].dwarned)
                                continue;
                            break;
                        case SCRIPT_BACKEND:
                            if (procavs[i].swarned)
                                continue;
                            break;
                        default:
                            return BACKEND_ERROR;
                            break;  /* Not necessary, but a good habit */
                        }
                    indcs[nwarns] = i;
                    nwarns++;
                }
        }
    return nwarns;
}

/* Get a list of procavs indices that match our 'alarm' condition
 * returns the number of alarms that will be present in *indcs
 * caller should handle mutexes and malloc
 */
int get_alarms(int *indcs, procan_config *pc, int backendtype)
{
    int nalarms = 0;
    int i;
    for (i = 0; i < numprocavs; i++)
        {
            if (procavs[i].num_intrests > pc->alarmlevel)
                {
                    switch (backendtype)
                        {
                        case MAIL_BACKEND:
                            if (procavs[i].malarmed)
                                continue;
                            break;
                        case SYSLOG_BACKEND:
                            if (procavs[i].dalarmed)
                                continue;
                            break;
                        case SCRIPT_BACKEND:
                            if (procavs[i].salarmed)
                                continue;
                            break;
                        default:
                            return BACKEND_ERROR;
                            break;  /* Not necessary, but a good habit */
                        }
                    indcs[nalarms] = i;
                    nalarms++;
                }
        }
    return nalarms;
}
