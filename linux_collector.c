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

/* Linux Collector */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <pthread.h>
#include <ctype.h>
#include "procan.h"
#include "linux_collector.h"

/* The collector thread is responsible
 * for collecting data about running processes
 * and placing them in a structure that 
 * The analyzer thread can read quickly
 */
void* collector_thread(void *a)
{
  PROCTAB *proct;
  proc_t  *proc_info;
  int hangup = 0;
  
  while (!hangup)
    {
      pthread_mutex_lock(&procsnap_mutex);
      proct = openproc(PROC_FILLARG | PROC_FILLSTAT | PROC_FILLSTATUS);//PROC_FILLMEM | PROC_FILLSTATUS | PROC_FILLSTAT | PROC_FILLARG);
      if (procsnap == NULL)
	{
	  procsnap = (proc_statistics *) calloc(MAXPROCAVS, sizeof(proc_statistics));
	  if (procsnap == NULL)
	    {
	      printf("Can not allocate memory.");
	      exit(-1);
	    }
	}
      numprocsnap = 0;
      while((proc_info = readproc(proct,NULL)))
	{
	  if (procsnap[numprocsnap]._command == NULL)
	    {
	      if ((procsnap[numprocsnap]._command = (char*)malloc(20*sizeof(char))) == NULL)
		{
		  printf("malloc error, can not allocate memory.\n");
		  exit(-1);
		}

	      if (procsnap[numprocsnap]._command == NULL)
		{
		  printf("Can not allocate memory.");
		  exit(-1);
		}
	    }
	  procsnap[numprocsnap]._pid = proc_info->tid;
	  procsnap[numprocsnap]._uid = proc_info->ruid;
	  strncpy(procsnap[numprocsnap]._command, proc_info->cmd, 20);
	  procsnap[numprocsnap]._rssize = proc_info->rss;
	  procsnap[numprocsnap]._size = proc_info->size;
	  procsnap[numprocsnap]._perc = proc_info->pcpu;
	  procsnap[numprocsnap]._age = 0;
	  procsnap[numprocsnap]._read = 0;
	  freep(proc_info);
	  numprocsnap++;
	}
      closeproc(proct);
      pthread_mutex_unlock(&procsnap_mutex);
      pthread_mutex_lock(&hangup_mutex);
      if (m_hangup)
	hangup = 1;
      pthread_mutex_unlock(&hangup_mutex);
      if (!hangup)
	sleep(1);
    }
  return NULL;
}

/* This method will free a linux proc_t entry
 * this method is here because libproc's freeprocs
 * method does not always seem to be available
 */
void freep(proc_t* proc)
{
  if (!proc)
    return;
  if (proc->cmdline)
    free((void*)*proc->cmdline);
  if (proc->environ)
    free((void*)*proc->environ);
  free(proc);
}
