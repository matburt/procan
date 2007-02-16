/* OpenBSD Collector */
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
#include <sys/time.h>
#include <pthread.h>

#include "procan.h"
#include "openbsd_collector.h"

/* The collector thread is responsible
 * for collecting data about running processes
 * and placing them in a structure that 
 * The analyzer thread can read quickly
 */
void* collector_thread(void *a)
{
  struct kinfo_proc2 *kprocaccess, *kpptr;
  int mib[6] = {CTL_KERN, 
	       KERN_PROC2, 
	       KERN_PROC_UID, 
	       (int)getuid(), 
	       sizeof(struct kinfo_proc2),
	       0};
  int numprocs;
  int i, sstat;
  int hangup = 0;
  size_t psize;

  pthread_mutex_lock(&procsnap_mutex);
  
  pthread_mutex_unlock(&procsnap_mutex);
  while (!hangup)    /* Thread run loop */
    {
      pthread_mutex_lock(&procsnap_mutex);
      /* We use the sysctl interface to gain access to the processes.
       * I have used code from OpenBSD top here */
      if ((sstat = sysctl(mib, 6, NULL, &psize,NULL,0)) == -1)
	{
	  fprintf(stderr, "Error in getprocs: fetching the size of the process tree.\n");
	  exit(-1);
	}
      kprocaccess = (struct kinfo_proc2 *)calloc(MAXPROCAVS, 
						 sizeof(struct kinfo_proc2));
      kpptr = kprocaccess;
      psize = 5 * psize / 4;
      mib[5] = (int)(psize / sizeof(struct kinfo_proc2));
      if ((sstat = sysctl(mib, 6, kprocaccess, &psize, NULL, 0)) == -1)
	{
	  fprintf(stderr, "Error in getprocs: failed to fetch the actual process tree.\n");
	  exit(-2);
	}
      numprocs = (int)(psize / sizeof(struct kinfo_proc2));      
      if (procsnap == NULL)
	procsnap = (proc_statistics *) calloc(MAXPROCAVS, sizeof(proc_statistics));
      if (procsnap == NULL)
	{
	  printf("Can not allocate memory.");
	  exit(-1);
	}
      numprocsnap = numprocs;
      for (i = 0; i < numprocs; i++)
	{ /* For each running process we do this and drop it into the array. */
	  procsnap[i]._pid = kpptr->p_pid;
	  procsnap[i]._pid = kpptr->p_uid;
	  procsnap[i]._command = calloc(KI_MAXCOMLEN, sizeof(char));
	  strlcpy(procsnap[i]._command, kpptr->p_comm, KI_MAXCOMLEN);
	  procsnap[i]._rssize = kpptr->p_vm_rssize;
	  procsnap[i]._size = kpptr->p_uru_ixrss;
	  procsnap[i]._perc = kpptr->p_pctcpu;
	  procsnap[i]._age = kpptr->p_ustart_sec;
	  procsnap[i]._read = 0;
	  //printf("%i -> %s\n",procsnap[i]._pid,procsnap[i]._command);
	  kpptr++;
	}
      if (kprocaccess != NULL)
	free(kprocaccess);
      pthread_mutex_unlock(&procsnap_mutex);
      pthread_mutex_lock(&hangup_mutex);
      if(m_hangup)
	hangup=1;
      pthread_mutex_unlock(&hangup_mutex);
      if (!hangup)
	sleep(1);
    }
  printf("Collector Thread Exiting\n");
  return NULL;
}

