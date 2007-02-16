/*
 * procan  1.0 12/21/2005
 * An intelligent user process analysis tool for FreeBSD, OpenBSD, or Linux
 * Written by:  Matthew W. Jones <mat@matburt.net>
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

/* Fetches a long string with the top 5 processes and why they are the top 5
 * Will also display the top 5 most interesting users. 
 * Calling function must free
 */
char* get_statistics()
{
  int *mis = (int *)calloc(numprocavs, sizeof(int));
  int *uis = (int *)malloc(numprocavs*sizeof(int));
  int *numints = (int *) malloc(numprocavs*sizeof(int));
  int numids, holder, i, j;
  char *nowstats = (char *)calloc(300, sizeof(char));
  char *thenstats = (char *)malloc(50*sizeof(char));
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
      snprintf(thenstats,50,"%i: %s because of %s %s %s\n",
	       place,
	       procavs[mis[i]].command,
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
#if defined (linux) //Wish I could do this on FreeBSD
  if (thenstats != NULL)
#endif
  free(thenstats);
  free(mis);
  free(uis);
  free(numints);
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

  threads = (pthread_t *)malloc(2*sizeof(*threads));
  
  if (( e = pthread_create(&threads[0], NULL, collector_thread, NULL)) != 0)
    printf("collector experienced a pthread error: %i\n",e);
  if (( e = pthread_create(&threads[1], NULL, analyzer_thread, NULL)) != 0)
    printf("analyzer experienced a pthread error: %i\n",e);

  pthread_mutex_lock(&hangup_mutex);
  while (m_hangup != 1)
    {
      pthread_mutex_unlock(&hangup_mutex);
      sleep(2);
      pthread_mutex_lock(&hangup_mutex);
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

/*
  Housekeeping is performed on all processes that are active.
  This includes resetting the hourly_intrests flag and warn and alarm flags
 */
void perform_housekeeping()
{
  int i;
  pthread_mutex_lock(&procchart_mutex);
  for (i = 0; i < numprocavs; i++)
    {
      procavs[i].hourly_intrests = 0;
      procavs[i].mwarned = 0;
      procavs[i].malarmed = 0;
      procavs[i].swarned = 0;
      procavs[i].salarmed = 0;
      procavs[i].dwarned = 0;
      procavs[i].dalarmed = 0;
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
      procavs[i].hourly_intrests = 0;
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
  printf("  p: list processes being tracked\n");
  printf("  s: Show the top 5 most interesting processes and users\n");
  printf("  q: Quit\n\n");
  printf("Author: Matthew W. Jones <mat@matburt.net>\n");
  printf("http://matburt.homeunix.com/projects/procan\n");
}

/* Signal handler, signals registered in main */
void handle_sig(int sig)
{
  switch(sig)
    {
    case SIGHUP:
      printf("Re-reading configuration...\n");
      pthread_mutex_lock(&pconfig_mutex);
      free_config(pc);
      pc = get_config();
      pthread_mutex_unlock(&pconfig_mutex);
      break;
    case SIGTERM: /* Will not shutdown interactive mode because getchar() blocks for input */
      printf("Shutting Down ProcAn\n");
      pthread_mutex_lock(&hangup_mutex);
      m_hangup=1;
      pthread_mutex_unlock(&hangup_mutex);
      break;
    case SIGUSR1:
      printf("Resetting statistics\n");
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
      if (strcmp(argv[i], "-i") == 0)
	intract = INTERACTIVE_MODE;
      else if (strcmp(argv[i], "-d") == 0)
	intract = BACKGROUND_MODE;
      else if (strcmp(argv[i], "-p") == 0)
	intract = PIPE_MODE;
      else if (strcmp(argv[i], "-b") == 0)
	{
	  printf("Using backends: ");
	  for (j = 0; j < ((argc-i+1 < 3) ? argc-i : 3); j++)
	    {
	      i++;
	      if (strcmp(argv[i], "mail") == 0)
		{
		  bes[j] = MAIL_BACKEND;
		  printf(" mail");
		}
	      else if (strcmp(argv[i], "script") == 0)
		{
		  bes[j] = SCRIPT_BACKEND;
		  printf(" script");
		}
	      else if (strcmp(argv[i], "syslog") == 0)
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
