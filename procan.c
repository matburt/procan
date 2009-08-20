/* Copyright (c) 2007, Matthew W. Jones
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
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

/*
 * An intelligent user process analysis tool for FreeBSD, OpenBSD, or Linux
 */

#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <limits.h>
#include <unistd.h>
#include <paths.h>
#include <string.h>
#include <sys/types.h>
#include <sys/param.h>
#include <sys/sysctl.h>
#include <sys/user.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <pthread.h>
#include <signal.h>

#include "procan.h"
#include "backend.h"
#include "cli.h"
#if defined (__FreeBSD__)
#include "freebsd_collector.h"
#elif defined (__OpenBSD__)
#include "openbsd_collector.h"
#elif defined (linux)
#include "linux_collector.h"
#else
#error Could not determine your operating system.  Make sure it is supported.
#endif

/* Globals with their respective mutexes */
pthread_mutex_t hangup_mutex;
int m_hangup = 0;

pthread_mutex_t procsnap_mutex;
proc_statistics *procsnap;
int numprocsnap = 0;

pthread_mutex_t procchart_mutex;
proc_averages *procavs;
int numprocavs = 0;

pthread_mutex_t pconfig_mutex;
procan_config *pc;
int *bes;

/* Used to signal to the analyzer to use script output or human-readable output */
int scriptoutput = 0;

/* Sorts processes and generates and sorts userlist */
int get_statistics(int *mis, int *uis, int *numints)
{
  int holder, i, j;
  int numids = 0;
  for (i = 0; i < numprocavs; i++)
    {
      mis[i] = i;
      int found = 0;
      for (j = 0; j < numids; j++)
          {
              if (uis[j] == procavs[i].uid)
                  {
                      numints[j]+=procavs[i].num_intrests;
                      found = 1;
                      break;
                  }
          }

      if (!found)
          {
              uis[numids] = procavs[i].uid;
              numints[numids] = procavs[i].num_intrests;
              numids++;
          }
    }

  for (i = 0; i < numids; i++)
      {
          for (j = 0; j < numids; j++)
              {
                  if (numints[j] > numints[j-1])
                      {
                          holder = numints[j];
                          numints[j] = numints[j-1];
                          numints[j-1] = holder;
                          holder = uis[j];
                          uis[j] = uis[j-1];
                          uis[j-1] = holder;
                      }
              }
      }

  for (i = 1; i < numprocavs; i++)
      {
          for (j = 1; j < numprocavs; j++)
              {
                  if (procavs[mis[j]].intrest_score >
                      procavs[mis[j-1]].intrest_score)
                      {
                          holder = mis[j];
                          mis[j] = mis[j-1];
                          mis[j-1] = holder;
                      }
              }
      }
  return numids;
}

/* Fetches a long string with the top 5 processes and why they are the top 5
 * Will also display the top 5 most interesting users.
 * Calling function must free
 */
char* get_statistics_str()
{
    int mis[numprocavs];
    int uis[numprocavs];
    int numints[numprocavs];
    int numids, holder, i, j;
    char *nowstats;
    char thenstats[50];

    if ((nowstats = malloc(sizeof(nowstats) * 300)) == NULL)
        {
            printf("malloc error, can not allocate memory.\n");
            exit(-1);
        }
    numids = 0;

    for (i = 0; i < numprocavs; i++)
        {
            mis[i] = i;
            int found=0;
            for (j = 0; j < numids; j++)
                {
                    if (uis[j] == procavs[i].uid)
                        {
                            numints[j]+=procavs[i].num_intrests;
                            found = 1;
                            break;
                        }
                }

            if (!found)
                {
                    uis[numids] = procavs[i].uid;
                    numints[numids] = procavs[i].num_intrests;
                    numids++;
                }
        }
    for (i = (numids-1); i >= 0; i--)
        {
            for (j = 1; j <= i; j++)
                {
                    if (numints[j-1] > numints[j])
                        {
                            holder = numints[j-1];
                            numints[j-1] = numints[j];
                            numints[j] = holder;
                            holder = uis[j-1];
                            uis[j-1] = uis[j];
                            uis[j] = holder;
                        }
                }

        }

    for (i = (numprocavs-1); i >= 0; i--)
        {
            for (j = 1; j <= i; j++)
                {
                    if (procavs[mis[j-1]].num_intrests > procavs[mis[j]].num_intrests)
                        {
                            holder = mis[j-1];
                            mis[j-1] = mis[j];
                            mis[j] = holder;
                        }
                }
        }

    int place = 0;
    for (i = numprocavs-1; i >= numprocavs-5; i--)
        {
            if (procavs[mis[i]].num_intrests < 1)
                continue;
            place++;
            snprintf(thenstats,50,"%i: %s (%i) because of %s %s %s\n",
                     place,
                     procavs[mis[i]].command,
                     procavs[mis[i]].lastpid,
                     (procavs[mis[i]].pintrests > procavs[mis[i]].mintrests) ? "process load." : "memory usage.",
                     (procavs[mis[i]].swarned || procavs[mis[i]].dwarned || procavs[mis[i]].mwarned) ? "*WARNED*" : "",
                     (procavs[mis[i]].salarmed || procavs[mis[i]].dalarmed || procavs[mis[i]].malarmed) ? "*ALARMED*" : "");
            nowstats = strncat(nowstats, (const char *)thenstats, 50);
        }

    nowstats = strncat(nowstats, "\nTop 5 users:\n", 14);
    place = 0;
    for (i = numids-1; i >= numids-5; i--)
        {
            if (numints[i] < 1)
                continue;
            place++;
            snprintf(thenstats,50,"%i: %i with total interest value of: %i\n",
                     place,
                     uis[i],
                     numints[i]);
            nowstats = strncat(nowstats, (const char *)thenstats, 50);
        }
    return nowstats;
}

int pipe_mode()
{
    pthread_t *threads;
    int i, e;
    scriptoutput = 1;

    signal(SIGCHLD, SIG_IGN);
    signal(SIGHUP, handle_sig);
    signal(SIGTERM, handle_sig);
    signal(SIGUSR1, handle_sig);

    pthread_mutex_init(&procsnap_mutex,NULL);
    pthread_mutex_init(&procchart_mutex,NULL);
    pthread_mutex_init(&hangup_mutex,NULL);
    pthread_mutex_init(&pconfig_mutex,NULL);

    if ((threads = (pthread_t *)malloc(2*sizeof(*threads))) == NULL)
        {
            printf("malloc error, can not allocate memory.\n");
            exit(-1);
        }

    if (( e = pthread_create(&threads[0], NULL, collector_thread, NULL)) != 0)
        printf("collector experienced a pthread error: %i\n",e);
    if (( e = pthread_create(&threads[1], NULL, analyzer_thread, NULL)) != 0)
        printf("analyzer experienced a pthread error: %i\n",e);

    pthread_mutex_lock(&hangup_mutex);
    while (m_hangup != 1)
        {
            sleep(2);  /* Pipe mode output is handled in the analyzer thread */
        }

    pthread_mutex_lock(&hangup_mutex);
    m_hangup=1;
    pthread_mutex_unlock(&hangup_mutex);

    pthread_join(threads[0],NULL);
    pthread_join(threads[1],NULL);
    pthread_mutex_destroy(&hangup_mutex);
    pthread_mutex_destroy(&procsnap_mutex);
    pthread_mutex_destroy(&procchart_mutex);
    pthread_mutex_destroy(&pconfig_mutex);
    free(threads);
#if defined (linux)
    for (i = 0; i < numprocsnap; i++)
        {
            if (procsnap[i]._command != NULL)
                free(procsnap[i]._command);
        }
#endif
    free(procsnap);
    for (i = 0; i < numprocavs; i++)
        {
            if (procavs[i].command != NULL)
                free(procavs[i].command);
        }
    free(procavs);

    return 0;
}

/*
  Housekeeping is performed on all processes that are active.
  This includes resetting the hourly_intrests flag and warn and alarm flags
 */
void perform_housekeeping(long current)
{
    int i;
    pthread_mutex_lock(&procchart_mutex);
    for (i = 0; i < numprocavs; i++)
        {
            if (procavs[i].last_interest_time > 0 &&
                (current - procavs[i].last_interest_time) > 3600)
                {
                    if (procavs[i].intrest_score > 0)
                        procavs[i].intrest_score = procavs[i].intrest_score / 2;
                    if (procavs[i].num_intrests > 0)
                        procavs[i].num_intrests = procavs[i].num_intrests / 2;
                    procavs[i].num_intrests = 0;
                    procavs[i].interest_threshold = DEFAULT_INTEREST_THRESHOLD;
                    procavs[i].mintrests = 0;
                    procavs[i].pintrests = 0;
                    procavs[i].mwarned = 0;
                    procavs[i].malarmed = 0;
                    procavs[i].swarned = 0;
                    procavs[i].salarmed = 0;
                    procavs[i].dwarned = 0;
                    procavs[i].dalarmed = 0;
                    procavs[i].last_interest_time = current;
                }
        }
    pthread_mutex_unlock(&procchart_mutex);
}

/* Reset statistics and collections */
void reset_statistics()
{
    int i;
    pthread_mutex_lock(&procchart_mutex);
    for (i = 0; i < numprocavs; i++)
        {
            procavs[i].mwarned = 0;
            procavs[i].malarmed = 0;
            procavs[i].swarned = 0;
            procavs[i].salarmed = 0;
            procavs[i].dwarned = 0;
            procavs[i].dalarmed = 0;
            procavs[i].intrest_score = 0;
            procavs[i].num_intrests = 0;
            procavs[i].mintrests = 0;
            procavs[i].pintrests = 0;
        }
    pthread_mutex_unlock(&procchart_mutex);
}

int should_ignore_proc(char *name)
{
    int i;
    for (i = 0; i < pc->nclusions; i++)
        {
            if (strncmp(pc->exclusions[i], name, strlen(pc->exclusions[i])) == 0)
                return 1;
        }
    return 0;
}

int should_ignore_uid(int uid)
{
    int i;
    for (i = 0; i < pc->nuids; i++)
        {
            if (uid == pc->euids[i])
                return 1;
        }
    return 0;
}

/* Daemon mode detaches from the shell, fork() is called from main */
int daemon_mode()
{
    pthread_t *threads;
    int i,e;

    if (setsid() < 0)
        {
            free_config(pc);
            exit(1);
        }

    for(i = getdtablesize(); i >= 0; --i)
        close(i);
    i = open("/dev/null",O_RDWR);
    dup(i);
    dup(i);
    umask(027);
    chdir("/");

    /* The 3 signals we watch for, and ignore the return value of children */
    signal(SIGCHLD, SIG_IGN);
    signal(SIGHUP, handle_sig);
    signal(SIGTERM, handle_sig);
    signal(SIGUSR1, handle_sig);

    pthread_mutex_init(&procsnap_mutex,NULL);
    pthread_mutex_init(&procchart_mutex,NULL);
    pthread_mutex_init(&hangup_mutex,NULL);
    pthread_mutex_init(&pconfig_mutex,NULL);

    if ((threads = (pthread_t *)malloc(2*sizeof(*threads))) == NULL)
        {
            printf("malloc error, can not allocate memory.\n");
            exit(-1);
        }

    if (( e = pthread_create(&threads[0], NULL, collector_thread, NULL)) != 0)
        exit(0);
    if (( e = pthread_create(&threads[1], NULL, analyzer_thread, NULL)) != 0)
        exit(0);

    pthread_mutex_lock(&hangup_mutex);
    while (m_hangup != 1)
        {
            pthread_mutex_unlock(&hangup_mutex);
            sleep(2);
            pthread_mutex_lock(&hangup_mutex);
        }

    pthread_join(threads[0],NULL);
    pthread_join(threads[1],NULL);
    pthread_mutex_destroy(&hangup_mutex);
    pthread_mutex_destroy(&procsnap_mutex);
    pthread_mutex_destroy(&procchart_mutex);
    pthread_mutex_destroy(&pconfig_mutex);
    free(threads);
    free(procsnap);
    for (i = 0; i < numprocavs; i++)
        {
            if (procavs[i].command != NULL)
                free(procavs[i].command);
        }
    free(procavs);
    return 0;
}

void usage()
{
    printf("Usage: procan [options] [-b [backend1 backend2 ...]]\n");
    printf("Options:\n");
    printf("  -i: Interactive Mode\n");
    printf("  -d: Daemon Mode\n");
    printf("  -p: Pipe Mode\n");
    printf("  -b: Use given backends.\n\n");
    printf("Backends:\n");
    printf("  mail: Send digest and warning messages to an administrator\n");
    printf("  script: Run a script or scripts based on given conditions\n");
    printf("  syslog: Log to syslog periodically\n\n");
    printf("Interactive Mode Commands:\n");
    printf("  q: Quit\n\n");
    printf("Author: Matthew W. Jones <mat@matburt.net>\n");
    printf("http://matburt.net/projects/procan\n");
}

/* Signal handler, signals registered in main */
void handle_sig(int sig)
{
    switch(sig)
        {
        case SIGHUP:
            pthread_mutex_lock(&pconfig_mutex);
            free_config(pc);
            pc = get_config();
            pthread_mutex_unlock(&pconfig_mutex);
            break;
        case SIGTERM:
            pthread_mutex_lock(&hangup_mutex);
            m_hangup=1;
            pthread_mutex_unlock(&hangup_mutex);
            break;
        case SIGUSR1:
            reset_statistics();
            break;
        }
}

int main(int argc, char *argv[])
{
    int i,j;
    int intract = -1;
    bes = calloc(3, sizeof(int));

    /* Read the command line arguments */
    for (i = 0; i < argc; i++)
        {
            if (strncmp(argv[i], "-i", 2) == 0)
                intract = INTERACTIVE_MODE;
            else if (strncmp(argv[i], "-d", 2) == 0)
                intract = BACKGROUND_MODE;
            else if (strncmp(argv[i], "-p", 2) == 0)
                intract = PIPE_MODE;
            else if (strncmp(argv[i], "-b", 2) == 0)
                {
                    printf("Using backends: ");
                    for (j = 0; j < ((argc-i+1 < 3) ? argc-i : 3); j++)
                        {
                            i++;
                            if (strncmp(argv[i], "mail", 4) == 0)
                                {
                                    bes[j] = MAIL_BACKEND;
                                    printf(" mail");
                                }
                            else if (strncmp(argv[i], "script", 6) == 0)
                                {
                                    bes[j] = SCRIPT_BACKEND;
                                    printf(" script");
                                }
                            else if (strncmp(argv[i], "syslog", 6) == 0)
                                {
                                    bes[j] = SYSLOG_BACKEND;
                                    printf(" syslog");
                                }
                            else
                                {
                                    printf("\nUnsupported backend %s, exiting.\n", argv[i]);
                                    free(bes);
                                    exit(-1);
                                }
                        }
                    printf("\n");
                }
        }

    pc = get_config();

    if (intract == INTERACTIVE_MODE)
        interactive_mode();
    else if (intract == PIPE_MODE)
        pipe_mode();
    else if (intract == BACKGROUND_MODE)
        {
            pid_t _p = fork();
            if (_p < 0)
                {
                    printf("Fork error.\n");
                    free_config(pc);
                    exit(1);
                }
            if (_p > 0)
                {
                    printf("ProcAn Started.\n");
                    exit(0);
                }
            else
                daemon_mode();
        }
    else
        {
            usage();
            exit(-1);
        }

    exit(0);
}
