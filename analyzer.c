/* Copyright (c) 2007, Matthew W. Jones
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * * Redistribution of source code must retain the above copyright notice,
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

/* ProcAn Analyzer
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

/* Write script stdout in pipe mode */
void script_output(char *type, char *cmd, int lastpid, int movement, int score, int niterests)
{
  if (movement >= 0)
    fprintf(stdout, "[%s,%s,%i,+%i,%i,%i]\n", type,
	    cmd,lastpid,movement,score,niterests);
  else
    fprintf(stdout, "[%s,%s,%i,%i,%i,%i]\n", type,
	    cmd,lastpid,movement,score,niterests);
  fflush(stdout);
}

/* Locate a free slot in the procavs list.
 * it can do this by picking the first slot whose process
 * has expired or by picking the first unused slot.
 *
 * By using this mechanism we are able to reuse memory for
 * new processes.
 */
int get_unused_slot(struct timeval atimev)
{
  int uuslot = -1;
  int k;
  for (k = 0; k < numprocavs; k++)
    {
      if (procavs[k].last_measure_time < (atimev.tv_sec - 30))
        {
          uuslot = k;
          break;
        }
    }

  //MAXPROCAVS should be more of an interval for growing
  //the numprocavs space instead of an upper limit.
  if (uuslot == -1 && numprocavs < MAXPROCAVS)
    {
      uuslot = numprocavs;
      numprocavs++;
    }
  return uuslot;
}

/* Modify a single proc_averages instance based on a change in score
 * if we are using script output this will also notify. Any other notification
 * that needs to be done in the future should be done here.
 */
void modify_interest(proc_averages *pav, char *type, int change)
{
  pav->intrest_score = pav->intrest_score + change;
  pav->mintrests++;
  if (scriptoutput)
    {
      script_output(type,
		    pav->command,
		    pav->lastpid,
		    change,
		    pav->intrest_score,
		    pav->num_intrests);
    }
}

void initialize_slot(proc_averages *pav, proc_statistics *pc, long curtime)
{
  //  if (pav->command == NULL)   /* Create an entry for it */
  //  {
      if ((pav->command = malloc(25*sizeof(char))) == NULL)
          {
              printf("malloc error, can not allocate memory.\n");
              exit(-1);
          }
      //  }
  strncpy(pav->command, pc->_command, 25);
  pav->lastpid = pc->_pid;
  pav->uid = pc->_uid;
  pav->last_measure_time = curtime;
  pav->last_interest_time = curtime;
  pav->num_seen = 1;
  pav->mov_percent = 0;
  pav->last_percent = pc->_perc;
  pav->avg_size_gain = 0;
  pav->last_size = pc->_size;
  pav->avg_rssize_gain = 0;
  pav->last_rssize = pc->_rssize;
  pav->times_measured = 1;
  pav->ticks_interesting = 0;
  pav->ticks_since_interesting = 0;
  pav->intrest_score = 0;
  pav->interest_threshold = DEFAULT_INTEREST_THRESHOLD;
  pav->num_intrests = 0;
  pav->mintrests = 0;
  pav->pintrests = 0;
  pav->dwarned = 0;
  pav->dalarmed = 0;
  pav->mwarned = 0;
  pav->malarmed = 0;
  pav->swarned = 0;
  pav->salarmed = 0;
}

/* Will analyze process data gathered by the collector
 * looking for 'interesting' processes and apply an adaptive threshold
 * to analyze the level of interest.
 */
void* analyzer_thread(void *a)
{
  int hangup=0;
  int i,j= 0;
  analyzer_times an_time;

  while (!hangup)  /* Thread Run Loop */
    {
      gettimeofday(&an_time.atimev,NULL);
      pthread_mutex_lock(&procsnap_mutex);
      for (i = 0; i < numprocsnap; i++)
	{
	  int foundhistory = -1;
	  if (procsnap[i]._command == NULL )
            continue;
	  pthread_mutex_lock(&procchart_mutex);

	  if (should_ignore_proc(procsnap[i]._command)
	      || should_ignore_uid(procsnap[i]._uid))
	    {
	      pthread_mutex_unlock(&procchart_mutex);
	      continue;
	    }
	  if (procavs == NULL)
	    {
	      if ((procavs = (proc_averages *) malloc(MAXPROCAVS*sizeof(proc_averages))) == NULL)
		{
		  printf("malloc error, can not allocate memory.\n");
		  exit(-1);
		}
	    }

	  for (j = 0; j < numprocavs; j++) /* Search for matching history */
	    {
	      if (procsnap[i]._pid == procavs[j].lastpid)
		{
		  foundhistory = j;
		  break;
		}
	    }
	  if (foundhistory == -1) /* If it's not found, pick an unused slot */
	    {
              int uuslot = get_unused_slot(an_time.atimev);
              if (uuslot == -1) //this usually means we are full, which really needs to be fixed.
                continue;

	      gettimeofday(&an_time._t, NULL);

	      initialize_slot(&procavs[uuslot], &procsnap[i], an_time._t.tv_sec);
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
		  modify_interest(&procavs[foundhistory],"proc",5);
		  procavs[foundhistory].pintrests++;
		  procavs[foundhistory].mov_percent = 0;
		}
	      procavs[foundhistory].last_percent = procsnap[i]._perc;
	      procavs[foundhistory].avg_size_gain = procsnap[i]._size - procavs[foundhistory].last_size;
	      procavs[foundhistory].last_size = procsnap[i]._size;

	      if (procavs[foundhistory].avg_size_gain > 0)
		modify_interest(&procavs[foundhistory], "mem", 1);

	      if (procavs[foundhistory].avg_size_gain < 0)
		modify_interest(&procavs[foundhistory],"mem",-1);

	      procavs[foundhistory].avg_rssize_gain = procsnap[i]._rssize - procavs[foundhistory].last_rssize;
	      procavs[foundhistory].last_rssize = procsnap[i]._rssize;
	      if (procavs[foundhistory].avg_rssize_gain > 0)
		modify_interest(&procavs[foundhistory],"rss",1);

	      if (procavs[foundhistory].avg_rssize_gain < 0)
		modify_interest(&procavs[foundhistory],"rss",-1);

	      //some interest calculations related to state changing
	      if (procavs[foundhistory].intrest_score > procavs[foundhistory].interest_threshold)
		{
		  procavs[foundhistory].ticks_interesting++;
		  procavs[foundhistory].ticks_since_interesting = 0;
		  procavs[foundhistory].num_intrests++;
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
		procavs[foundhistory].interest_threshold = procavs[foundhistory].intrest_score + ADAPTIVE_THRESHOLD;

	      gettimeofday(&an_time._t,NULL);
	      procavs[foundhistory].times_measured = procavs[foundhistory].times_measured + 1;
	      procavs[foundhistory].last_measure_time = an_time._t.tv_sec;
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
	      if (syslog_backend(pc, &an_time.syslog_time) == BACKEND_ERROR)
		bes[i] = 0;
	      break;
	    case MAIL_BACKEND:
	      if (mail_backend(pc, &an_time.mail_time) == BACKEND_ERROR)
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
      perform_housekeeping(an_time._t.tv_sec);
      if (!hangup)
	sleep(1);
    }
  free_config(pc);
  free(bes);
  return NULL;
}
