/* ProcAn Analyzer
 * Written by:  Matthew W. Jones <matburt@oss-institute.org>
 *
 * TODO:  Report hourly interests to pipe
 */
#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
#include <sys/time.h>
#include <string.h>
#include <unistd.h>
#include "procan.h"
#include "backend.h"

/* Globals from procan.c, they are initialized there. */
extern pthread_mutex_t hangup_mutex;
extern int m_hangup;

extern pthread_mutex_t procsnap_mutex;
extern proc_statistics *procsnap;
extern int numprocsnap;

extern pthread_mutex_t procchart_mutex;
extern proc_averages *procavs;
extern int numprocavs;

extern pthread_mutex_t pconfig_mutex;
extern procan_config *pc;
extern int *bes;

extern int scriptoutput;

/* Will analyze process data gathered by the collector
 * looking for 'interesting' processes and apply an adaptive threshold
 * to analyze the level of interest.
 */
void* analyzer_thread(void *a)
{
  int hangup=0;
  int i,j= 0;
  struct timeval *atimev = (struct timeval *)malloc(sizeof(struct timeval));
  struct timeval *_t = (struct timeval *)malloc(sizeof(struct timeval));
  struct timeval *syslog_time = (struct timeval *)calloc(1,sizeof(struct timeval));
  struct timeval *mail_time = (struct timeval *)calloc(1,sizeof(struct timeval));
  struct timeval *housekeeping_time = (struct timeval *)malloc(sizeof(struct timeval));
  gettimeofday(housekeeping_time, NULL);
  housekeeping_time->tv_sec = housekeeping_time->tv_sec + 3600; /* 1 hour */

  while (!hangup)  /* Thread Run Loop */
    {
      gettimeofday(atimev,NULL);
      pthread_mutex_lock(&procsnap_mutex);
      for (i = 0; i < numprocsnap; i++)
	{
	  int foundhistory = -1;
	  if (procsnap[i]._command == NULL )
		  continue;
	  pthread_mutex_lock(&procchart_mutex);
	  if (procavs == NULL)
	    procavs = (proc_averages *) calloc(MAXPROCAVS, sizeof(proc_averages));
	  
	  for (j = 0; j < numprocavs; j++) /* Search for matching history */
	    {
	      if ((strncmp((const char *)procsnap[i]._command, 
			    (const char *)procavs[j].command, sizeof(procavs[j].command)) == 0) &&
		  procsnap[i]._pid == procavs[j].lastpid)
		{
		  foundhistory = j;
		  break;
		}
	    }
	  if (foundhistory == -1) /* If it's not found, pick an unused slot */
	    {
	      if (should_ignore_proc(procsnap[i]._command) 
		  || should_ignore_uid(procsnap[i]._uid))
		{
		  pthread_mutex_unlock(&procchart_mutex);
		  continue;
		}
	      int uuslot = -1;
	      int k;
	      for (k = 0; k < numprocavs; k++)
		{
		  if (procavs[k].last_measure_time < (atimev->tv_sec - 30))
		    {
		      uuslot = k;
		      break;
		    }
		}
	      if (uuslot == -1)
		{
		  uuslot = numprocavs;
		  k = 0;
		}
	      else
		k = 1;
	      if (procavs[uuslot].command == NULL)   /* Create an entry for it */
		procavs[uuslot].command = calloc(25, sizeof(char));
	      strncpy(procavs[uuslot].command, procsnap[i]._command, 25);
	      procavs[uuslot].lastpid = procsnap[i]._pid;
	      procavs[uuslot].uid = procsnap[i]._uid;
	      gettimeofday(_t, NULL);
	      procavs[uuslot].last_measure_time = _t->tv_sec;
	      procavs[uuslot].num_seen = 1;
	      procavs[uuslot].mov_percent = 0;
	      procavs[uuslot].last_percent = procsnap[i]._perc;
	      procavs[uuslot].avg_size_gain = 0;
	      procavs[uuslot].last_size = procsnap[i]._size;
	      procavs[uuslot].avg_rssize_gain = 0;
	      procavs[uuslot].last_rssize = procsnap[i]._rssize;
	      procavs[uuslot].times_measured = 1;
	      procavs[uuslot].ticks_interesting = 0;
	      procavs[uuslot].ticks_since_interesting = 0;
	      procavs[uuslot].intrest_score = 0;
	      procavs[uuslot].interest_threshold = DEFAULT_INTEREST_THRESHOLD;
	      procavs[uuslot].num_intrests = 0;
	      procavs[uuslot].hourly_intrests = 0;
	      procavs[uuslot].mintrests = 0;
	      procavs[uuslot].pintrests = 0;
	      procavs[uuslot].dwarned = 0;
	      procavs[uuslot].dalarmed = 0;
	      procavs[uuslot].mwarned = 0;
	      procavs[uuslot].malarmed = 0;
	      procavs[uuslot].swarned = 0;
	      procavs[uuslot].salarmed = 0;
	      if (k == 0) 
		numprocavs++;
	    }
	  else   /* This means we found the history, now we begin the analysis */
	    {  
	      procavs[foundhistory].lastpid = procsnap[i]._pid;
	      if (procsnap[i]._perc > 0 && procavs[foundhistory].last_percent > 0)
		procavs[foundhistory].mov_percent++;
	      else if (procsnap[i]._perc == 0 && procavs[foundhistory].last_percent == 0)
		{
		  procavs[foundhistory].intrest_score = procavs[foundhistory].intrest_score - 5*procavs[foundhistory].mov_percent;
		  procavs[foundhistory].mov_percent = 0;
		}
	      if (procavs[foundhistory].mov_percent >= 5) 
		{
		  procavs[foundhistory].intrest_score = procavs[foundhistory].intrest_score + 5;
		  if (scriptoutput)
		    {
		      fprintf(stdout, "[proc,%s,%i,+5,%i,%i]\n", procavs[foundhistory].command,
			     procavs[foundhistory].lastpid,
			     procavs[foundhistory].intrest_score,
			     procavs[foundhistory].num_intrests);
		      fflush(stdout);
		    }
		  procavs[foundhistory].pintrests++;
		  procavs[foundhistory].mov_percent = 0;
		}
	      procavs[foundhistory].last_percent = procsnap[i]._perc;
	      procavs[foundhistory].avg_size_gain = procsnap[i]._size - procavs[foundhistory].last_size;
	      procavs[foundhistory].last_size = procsnap[i]._size;
	      if (procavs[foundhistory].avg_size_gain > 0)
		{
		  procavs[foundhistory].intrest_score = procavs[foundhistory].intrest_score + 1;
		  procavs[foundhistory].mintrests++;
		  if (scriptoutput)
		    {
		      fprintf(stdout,"[mem,%s,%i,+1,%i,%i]\n", procavs[foundhistory].command,
			     procavs[foundhistory].lastpid,
			     procavs[foundhistory].intrest_score,
			     procavs[foundhistory].num_intrests);
		      fflush(stdout);
		    }
		}
	      if (procavs[foundhistory].avg_size_gain < 0)
		{
		  procavs[foundhistory].intrest_score = procavs[foundhistory].intrest_score - 1;
		  if (scriptoutput)
		    {
		      fprintf(stdout, "[mem,%s,%i,-1,%i,%i]\n", procavs[foundhistory].command,
			     procavs[foundhistory].lastpid,
			     procavs[foundhistory].intrest_score,
			     procavs[foundhistory].num_intrests);
		      fflush(stdout);
		    }
		}
	      procavs[foundhistory].avg_rssize_gain = procsnap[i]._rssize - procavs[foundhistory].last_rssize;
	      procavs[foundhistory].last_rssize = procsnap[i]._rssize;
	      if (procavs[foundhistory].avg_rssize_gain > 0)
		{
		  procavs[foundhistory].intrest_score = procavs[foundhistory].intrest_score + 1;
		  procavs[foundhistory].mintrests++;
		  if (scriptoutput)
		    {
		      fprintf(stdout, "[rss,%s,%i,+1,%i,%i]\n", procavs[foundhistory].command,
			     procavs[foundhistory].lastpid,
			     procavs[foundhistory].intrest_score,
			     procavs[foundhistory].num_intrests);
		      fflush(stdout);
		    }
		}
	      if (procavs[foundhistory].avg_rssize_gain < 0)
		{
		  procavs[foundhistory].intrest_score = procavs[foundhistory].intrest_score - 1;
		  if (scriptoutput)
		    {
		      fprintf(stdout, "[rss,%s,%i,-1,%i,%i]\n", procavs[foundhistory].command,
			     procavs[foundhistory].lastpid,
			     procavs[foundhistory].intrest_score,
			     procavs[foundhistory].num_intrests);
		      fflush(stdout);
		    }
		}

	      if (procavs[foundhistory].intrest_score > procavs[foundhistory].interest_threshold)
		{
		  if (!scriptoutput)
		    {
		      fprintf(stdout, "%s looks intresting (score: %i).\n",procavs[foundhistory].command, 
			     procavs[foundhistory].intrest_score);
		    }
		  procavs[foundhistory].ticks_interesting++;
		  procavs[foundhistory].ticks_since_interesting = 0;
		  procavs[foundhistory].num_intrests++;
		  procavs[foundhistory].hourly_intrests++;
		}
	      else
		{
		  procavs[foundhistory].ticks_since_interesting+=1;
		  procavs[foundhistory].ticks_interesting = 0;
		}

	      if (procavs[foundhistory].ticks_since_interesting > ADAPTIVE_THRESHOLD*2)
		{
		  procavs[foundhistory].interest_threshold = procavs[foundhistory].intrest_score + 1;
		  procavs[foundhistory].ticks_since_interesting = 0;
		}
	      if (procavs[foundhistory].ticks_interesting > ADAPTIVE_THRESHOLD)
		{
		  procavs[foundhistory].interest_threshold = procavs[foundhistory].intrest_score + ADAPTIVE_THRESHOLD;
		  if (!scriptoutput)
		    printf("Adaptive threshold for %s increased.\n",procavs[foundhistory].command);
		}

	      gettimeofday(_t,NULL);
	      procavs[foundhistory].times_measured = procavs[foundhistory].times_measured + 1;
	      procavs[foundhistory].last_measure_time = _t->tv_sec;
	    }
	  
	  pthread_mutex_unlock(&procchart_mutex);
	}
      pthread_mutex_unlock(&procsnap_mutex);
      pthread_mutex_lock(&pconfig_mutex);
      for (i = 0; i < 3; i++)    /* Backend Processing at the end of the analysis cycle */
	{
	  switch (bes[i])
	    {
	    case SYSLOG_BACKEND:
	      if (syslog_backend(pc, syslog_time) == BACKEND_ERROR)
		bes[i] = 0;
	      break;
	    case MAIL_BACKEND:
	      if (mail_backend(pc, mail_time) == BACKEND_ERROR)
		bes[i] = 0;
	      break;
	    case SCRIPT_BACKEND:
	      if (script_backend(pc) == BACKEND_ERROR)
		bes[i] = 0;
	      break;
	    default:
	      break;
	    }
	}
      pthread_mutex_unlock(&pconfig_mutex);
      pthread_mutex_lock(&hangup_mutex);
      if(m_hangup)
	hangup=1;
      pthread_mutex_unlock(&hangup_mutex);
      if (atimev->tv_sec >= housekeeping_time->tv_sec) /* Perform hourly housekeeping */
	{
	  perform_housekeeping();
	  housekeeping_time->tv_sec = atimev->tv_sec + 3600;
	}
      if (!hangup)
	sleep(1);
    }
  if (!scriptoutput)
    printf("Analyzer Thread Exiting\n");
  free_config(pc);
  free(bes);
  free(atimev);
  free(_t);
  free(syslog_time);
  free(mail_time);
  return NULL;
}
