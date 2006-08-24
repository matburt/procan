/* FreeBSD Collector Source */
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <kvm.h>
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
#include "freebsd_collector.h"

/* The collector thread is responsible
 * for collecting data about running processes
 * and placing them in a structure that 
 * The analyzer thread can read quickly
 */
void* collector_thread(void *a)
{
  char ebuffer[_POSIX2_LINE_MAX]; 
  kvm_t *kaccess;
  struct kinfo_proc *kprocaccess;
  int numprocs;
  int i;
  int hangup = 0;

  pthread_mutex_lock(&procsnap_mutex);
  
  /* Initialize access to the KVM Interface */
    if ((kaccess = kvm_openfiles(_PATH_DEVNULL,_PATH_DEVNULL,NULL,O_RDONLY, ebuffer)) == NULL)
    {
      fprintf(stderr, "kvm error:%s\n", ebuffer);
      exit(-1);
    }
  while (!hangup)    /* Thread run loop */
    {
      //pthread_mutex_lock(&procsnap_mutex);
      if ((kprocaccess = kvm_getprocs(kaccess, KERN_PROC_ALL, 
				      (int)getuid(), &numprocs)) == NULL)
	{
	  fprintf(stderr, "Error in getprocs: %s",kvm_geterr(kaccess));
	  exit(-1);
	}
      
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
	  procsnap[i]._pid = kprocaccess->ki_pid;
	  procsnap[i]._uid = kprocaccess->ki_uid;
	  procsnap[i]._command = kprocaccess->ki_comm;
	  procsnap[i]._rssize = kprocaccess->ki_rssize;
	  procsnap[i]._size = kprocaccess->ki_size;
	  procsnap[i]._perc = kprocaccess->ki_pctcpu;
	  procsnap[i]._age = kprocaccess->ki_runtime;
	  procsnap[i]._read = 0;
	  //printf("%i -> %s\n",procsnap[i]._pid,procsnap[i]._command);
	  kprocaccess++;
	}
      pthread_mutex_unlock(&procsnap_mutex);
      pthread_mutex_lock(&hangup_mutex);
      if(m_hangup)
	hangup=1;
      pthread_mutex_unlock(&hangup_mutex);
      if (!hangup)
	{
	  sleep(1);
	  pthread_mutex_lock(&procsnap_mutex);
	}
    }
  printf("Collector Thread Exiting\n");
  kvm_close(kaccess);
  return NULL;
}
