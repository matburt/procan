/* Copyright (c) 2007, Matthew W. Jones
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without modification, 
 * are permitted provided that the following conditions are met:
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

/* ProcAn's interactive display */
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
#include <curses.h>
#include <panel.h>
#include <signal.h>
#include <sys/ioctl.h>
#include "procan.h"
#include "cli.h"

/* Interactive mode remains in the foreground and recieves commands from stdin
 * it has the same functionality as far as backends as the daemon mode
 * but does not detach */
int interactive_mode()
{
  WINDOW *proc_win;
  WINDOW *user_win;
  PANEL *procpanel;
  PANEL *userpanel;

  pthread_t *threads;
  char *procline = (char *)malloc(100*sizeof(*procline));;
  int i,e, inp;
  int startx, starty, width, height;
  
  /* The 3 signals we watch for, and ignore the return value of children */
  signal(SIGCHLD, SIG_IGN);
  signal(SIGHUP, handle_sig);
  signal(SIGTERM, handle_sig);
  signal(SIGUSR1, handle_sig);

  pthread_mutex_init(&procsnap_mutex,NULL);
  pthread_mutex_init(&procchart_mutex,NULL);
  pthread_mutex_init(&hangup_mutex,NULL);
  pthread_mutex_init(&pconfig_mutex,NULL);

  threads = (pthread_t *)malloc(2*sizeof(*threads));
  
  if (( e = pthread_create(&threads[0], NULL, collector_thread, NULL)) != 0)
    printf("collector experienced a pthread error: %i\n",e);
  if (( e = pthread_create(&threads[1], NULL, analyzer_thread, NULL)) != 0)
    printf("analyzer experienced a pthread error: %i\n",e);

  /* Start Curses */
  initscr();			
  cbreak();			
  keypad(stdscr, TRUE);
  noecho();
  refresh();
  
  /* get the full screen's coordinate */
  getmaxyx(stdscr, height, width);
  startx = 0;
  starty = 0;
  
  /* Create and set up the windows */
  proc_win = newwin(height-6, width, starty, startx);
  user_win = newwin(6, width, starty+(height-6), startx);

  procpanel = new_panel(proc_win);
  userpanel = new_panel(user_win);

  update_panels();
  doupdate();
  nodelay(proc_win, TRUE);
  nodelay(user_win, TRUE);


  int refreshcounter = 0;

  struct timeval *now = (struct timeval *)malloc(sizeof(struct timeval));

  while ((inp = wgetch(proc_win)) != 113 && m_hangup != 1)
    {
      if (refreshcounter == 0)
        {
          gettimeofday(now,NULL);
          pthread_mutex_lock(&procchart_mutex);
          
          wclear(proc_win);
          wclear(user_win);
          mvwaddstr(proc_win, 1, 1, "Active Processes:");          
          mvwaddstr(user_win, 1, 1, "Active Users:");
          mvwaddstr(proc_win, 2, 1, "command | lpid | cpu |  rssz  | cpugn | szgn | rsszgn | I | #I");

          int *mis = (int *)malloc(numprocavs*sizeof(int));
          int *uis = (int *)malloc(numprocavs*sizeof(int));
          int *numints = (int *)malloc(numprocavs*sizeof(int));

          int numids = get_statistics(mis, uis, numints);

          for (i = 0; i < numprocavs; i++)
            {
              if (procavs[mis[i]].last_measure_time > now->tv_sec - 30)
                {
                  snprintf(procline, 100, "%8.8s %6i %5i %6i %6i %6i %8i %3i %3i", 
                           procavs[mis[i]].command,
                           procavs[mis[i]].lastpid,
                           procavs[mis[i]].last_percent,
                           procavs[mis[i]].last_rssize,
                           procavs[mis[i]].mov_percent,
                           procavs[mis[i]].avg_size_gain,
                           procavs[mis[i]].avg_rssize_gain,
                           procavs[mis[i]].intrest_score,
                           procavs[mis[i]].num_intrests);
                  mvwaddstr(proc_win, (i+3), 1, procline);
                }

            }

          for (i = 0; i < numids; i++)
            {
              snprintf(procline, 100, "%5i (%i)", uis[i], numints[i]);
              mvwaddstr(user_win, (i+2), 1, procline);
            }

          free(mis);
          free(uis);
          free(numints);
          
          box(proc_win, 0, 0);
          box(user_win, 0, 0);
          wrefresh(proc_win); 
          wrefresh(user_win); 
          
          pthread_mutex_unlock(&procchart_mutex);
          refreshcounter = 100;
        }
      refreshcounter--;
      usleep(20);
    }

  endwin();
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
  free(procline);
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
