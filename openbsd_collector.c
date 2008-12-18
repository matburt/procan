/* Copyright (c) 2007, Matthew W. Jones
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:
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
          {
              procsnap = (proc_statistics *) calloc(MAXPROCAVS, sizeof(proc_statistics));
              if (procsnap == NULL)
                  {
                      printf("Can not allocate memory.");
                      exit(-1);
                  }
          }
      numprocsnap = numprocs;
      for (i = 0; i < numprocs; i++)
          { /* For each running process we do this and drop it into the array. */
              procsnap[i]._pid = kpptr->p_pid;
              procsnap[i]._uid = kpptr->p_uid;
              if (procsnap[i]._command == NULL)
                  procsnap[i]._command = malloc(KI_MAXCOMLEN + 1 * sizeof(char));
              strlcpy(procsnap[i]._command, kpptr->p_comm, KI_MAXCOMLEN);
              procsnap[i]._rssize = kpptr->p_vm_rssize;
              procsnap[i]._size = kpptr->p_uru_ixrss;
              procsnap[i]._perc = kpptr->p_pctcpu;
              procsnap[i]._age = kpptr->p_ustart_sec;
              procsnap[i]._read = 0;
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
  return NULL;
}
