/* Copyright (c) 2008, Matthew W. Jones
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

/* Configuration Parser */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include "procan.h"

/* Will search for, process and load procan configuration
 * returns a procan_config structure that the caller should free
 * invoked at startup and when a SIGHUP is recieved
 */
procan_config* get_config()
{
  FILE *cfile = NULL;
  char *cfiles[] = {"/etc/procan.conf", "/etc/procan/procan.conf",
		     "/usr/etc/procan.conf","/usr/etc/procan/procan.conf",
		     "/usr/local/etc/procan.conf","~/.procan.conf"
		     "/usr/local/etc/procan/procan.conf", "./procan.conf",NULL};
  int i = 0;
  while ((cfiles[i] != NULL) && 
	 ((cfile = fopen(cfiles[i], "r")) == NULL))
    i++;
  
  if (!cfile)
    {
      printf("Configuration file not found.\n");
      exit(-1);
    }
  
  procan_config *pc = (procan_config *)calloc(1, sizeof(procan_config));
  while (!feof(cfile))
    {
      char *line = (char *)calloc(100, sizeof(char));
      fgets(line, 100, cfile);
      if (line[0] == '#' || isspace(line[0]))
	{
	  free(line);
	  continue;
	}
      else
	{
	  char *midptr = line;
	  char *fptr = strsep(&midptr, ":");
	  if (midptr == NULL || feof(cfile))
	    break;
	  while (isspace(midptr[0]))
	    midptr++;
	  if (strcmp(midptr, "") == 0)
	    {
	      free(line);
	      continue;
	    }
	  char *toks = malloc(20*sizeof(char));
	  char *brk;
	  i = 0;
	  if (strcmp(fptr,"excludeuids") == 0)
	    {
	      i = 0;
	      pc->euids = calloc(20, sizeof(int));
	      for (toks = strtok_r(midptr, " \t", &brk);
		   toks && i < 20;
		   toks = strtok_r(NULL, " \t", &brk))
		{
		  pc->euids[i] = (int)strtol(toks, (char **)NULL, 10);
		  i++;
		}
	      pc->nuids = i;
	    }
	  else if (strcmp(fptr,"includeuids") == 0)
	    {
	      i = 0;
	      pc->iuids = calloc(20, sizeof(int));
	      for (toks = strtok_r(midptr, " \t", &brk);
		   toks && i < 20;
		   toks = strtok_r(NULL, " \t", &brk))
		{
		  pc->iuids[i] = (int)strtol(toks, (char **)NULL, 10);
		  i++;
		}
	      pc->nuids = i;
	    }
	  else if (strcmp(fptr,"excludeprocs") == 0)
	    {
	      i = 0;
	      for (toks = strtok_r(midptr, " \t", &brk);
		   toks && i < 20;
		   toks = strtok_r(NULL, " \t", &brk))
		{
		  if (toks == NULL)
		    break;
		  strncpy(pc->exclusions[i], toks, 20);
		  char *b = strpbrk(pc->exclusions[i], "\n");
		  if (b != NULL)
		    b[0] = '\0';
		  i++;
		}
	      pc->nclusions = i;
	    }
	  else if (strcmp(fptr,"adminemail") == 0)
	    {
	      pc->adminemail = malloc(40*sizeof(char));
	      strncpy(pc->adminemail, midptr, 40);
	      char *b = strpbrk(pc->adminemail, "\n");
	      if (b != NULL)
		b[0] = '\0';
	    }
	  else if (strcmp(fptr,"warnlevel") == 0)
	    pc->warnlevel = (int)strtol(midptr, (char **)NULL, 10);
	  else if (strcmp(fptr,"alarmlevel") == 0)
	    pc->alarmlevel = (int)strtol(midptr, (char **)NULL, 10);
	  else if (strcmp(fptr,"mailfrequency") == 0)
	    pc->mailfrequency = (int)strtol(midptr, (char **)NULL, 10);
	  else if (strcmp(fptr,"logfrequency") == 0)
	    pc->logfrequency = (int)strtol(midptr, (char **)NULL, 10);
	  else if (strcmp(fptr,"warnscript") == 0)
	    {
	      pc->warnscript = malloc(100*sizeof(char));
	      strncpy(pc->warnscript, midptr, 100);
	      char *b = strpbrk(pc->warnscript, "\n");
	      if (b != NULL)
		b[0] = '\0';
	    }
	  else if (strcmp(fptr,"alarmscript") == 0)
	    {
	      pc->alarmscript = malloc(100*sizeof(char));
	      strncpy(pc->alarmscript, midptr, 100);
	      char *b = strpbrk(pc->alarmscript, "\n");
	      if (b != NULL)
		b[0] = '\0';
	    }
	  else if (strcmp(fptr, "mtapath") == 0)
	    {
	      pc->mtapath = malloc(50*sizeof(char));
	      strncpy(pc->mtapath, midptr, 50);
	      char *b = strpbrk(pc->mtapath, "\n");
	      if (b != NULL)
		b[0] = '\0';
	    }
	  free(toks);
	}
      free(line);
    }
#if defined (__FreeBSD__)  /* FreeBSD lists cpu idles in the process list, which can really screw us up.*/
  strncpy(pc->exclusions[pc->nclusions], "idle: cpu", 9);
  pc->nclusions++;
  strncpy(pc->exclusions[pc->nclusions], "syncer", 6);
  pc->nclusions++;
  strncpy(pc->exclusions[pc->nclusions], "swi", 3);
  pc->nclusions++;
  strncpy(pc->exclusions[pc->nclusions], "irq", 3);
  pc->nclusions++;
#endif
  return pc;
}

void free_config(procan_config *pc)
{
  if (!(!pc->euids))
    free(pc->euids);
  if (!(!pc->iuids))
    free(pc->iuids);
  if (!(!pc->adminemail))
    free(pc->adminemail);
  if (!(!pc->warnscript))
    free(pc->warnscript);
  if (!(!pc->alarmscript))
    free(pc->alarmscript);
  if (!(!pc->mtapath))
    free(pc->mtapath);
  free(pc);
}
