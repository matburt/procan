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
  int i;
  
  while (!hangup)
    {
      pthread_mutex_lock(&procsnap_mutex);
      proct = openproc(PROC_FILLARG | PROC_FILLSTAT | PROC_FILLSTATUS);//PROC_FILLMEM | PROC_FILLSTATUS | PROC_FILLSTAT | PROC_FILLARG);
      if (procsnap == NULL)
	procsnap = (proc_statistics *) calloc(MAXPROCAVS, sizeof(proc_statistics));
      if (procsnap == NULL)
	{
	  printf("Can not allocate memory.");
	  exit(-1);
	}
      numprocsnap = 0;
      while((proc_info = readproc(proct,NULL)))
	{
	  if (procsnap[numprocsnap]._command == NULL)
	    procsnap[numprocsnap]._command = (char*)malloc(20*sizeof(char));
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
  printf("Collector Thread Exiting\n");
  return NULL;
}

/* This method will free a linux proc_t entry
 * this method is here because libproc's freeprocs
 * method does not always seem to be available
 */
void freep(proc_t* p)
{
  if (!p)     /* in case p is NULL */
    return;
  /* ptrs are after strings to avoid copying memory when building them. */
  /* so free is called on the address of the address of strvec[0]. */
  if (p->cmdline)
    free((void*)*p->cmdline);
  if (p->environ)
    free((void*)*p->environ);
  free(p);
}
