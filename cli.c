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
#include "procan.h"
#include "cli.h"

#if defined (linux)
#include <signal.h>
#endif

/* Interactive mode remains in the foreground and recieves commands from stdin
 * it has the same functionality as far as backends as the daemon mode
 * but does not detach */
int interactive_mode()
{
  pthread_t *threads;
  char lcommand;
  int i,e;

  /* The 2 signals we watch for, and ignore the return value of children */
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
 
  while ((lcommand = getchar()) != 'q' && m_hangup != 1)
    {
      if (lcommand == 'p')
	{
	  struct timeval *now = (struct timeval *)malloc(sizeof(struct timeval));
	  gettimeofday(now,NULL);
	  pthread_mutex_lock(&procchart_mutex);
	  printf("command -- lastpid -- lasttime -- num_seen -- mov_percent -- size_gain -- rssize_gain -- #measures -- interest -- num interests\n");
	  for (i = 0; i < numprocavs; i++)
	    {
	      if (procavs[i].last_measure_time > now->tv_sec - 30)
		{
		  printf("%s -- %i -- %i -- %li -- %i -- %i -- %i -- %i -- %i -- %i -- %i\n", 
			 procavs[i].command,
			 procavs[i].uid,
			 procavs[i].lastpid,
			 procavs[i].last_measure_time,
			 procavs[i].num_seen,
			 procavs[i].mov_percent,
			 procavs[i].avg_size_gain,
			 procavs[i].avg_rssize_gain,
			 procavs[i].times_measured,
			 procavs[i].intrest_score,
			 procavs[i].num_intrests);
		}
	    }
	  free(now);
	  pthread_mutex_unlock(&procchart_mutex);
	}
      else if (lcommand == 's')
	{
	  printf("Showing the top 5 most interesting active processes and why:\n");
	  char *info = get_statistics();
	  printf("%s", info);
	  //free(info); /* This seems to cause corrupted redzones, not sure why */
	}
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

