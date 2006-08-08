/* Main Header for ProcAn
 * This defines the process structures
 * used by the collector and analyzer
 */

#ifndef PROCAN_H
#define PROCAN_H

#define MAXPROCAVS 500                /* Maximum unique procs to analyze */
#define DEFAULT_INTEREST_THRESHOLD 5  /* Default Threshold for Interesting procs */
#define ADAPTIVE_THRESHOLD 5          /* Adaptation threshold for interesting procs */

#define INTERACTIVE_MODE 0            /* Interactive Mode Flag */
#define BACKGROUND_MODE 1             /* Daemon/Server Mode Flag */
#define PIPE_MODE 2                   /* Pipe Mode Flag */

#define SYSLOG_BACKEND 1              /* Enable the syslog backend */
#define MAIL_BACKEND 2                /* Enable the mailer backend */
#define SCRIPT_BACKEND 3              /* Enable the script backend */

#define BACKEND_ERROR 0              /* Backend Experienced an Unrecoverable Error */
#define BACKEND_WARNING 1            /* Backend Recieved a Temporary Warning */
#define BACKEND_NORMAL 2

/* The following struct is populated by the collector
   it is supposed to be a lightweight container for 
   a snapshot of a process
*/
typedef struct 
{
  int _pid;        /* Proc's pid */
  int _uid;
  char *_command;  /* Command string */
  int _rssize;     /* The Resident Set Size */
  int _size;       /* Virtual Size */
  int _perc;       /* % Processor load */
  int _age;        /* How long it has been running */
  int _read;       /* Mutex flag to prevent duplication */
}proc_statistics;

/* The following struct is used to keep history data
   about individual types of processes
*/
typedef struct
{
  char *command;
  int uid;
  int lastpid;
  long last_measure_time;
  int num_seen;
  int last_seen;
  int mov_percent;
  int last_percent;
  int avg_size_gain;
  int last_size;
  int avg_rssize_gain;
  int last_rssize;
  int times_measured;
  int intrest_score;
  int ticks_interesting;
  int ticks_since_interesting;
  int hourly_intrests;
  int num_intrests;
  int mintrests;
  int pintrests;
  int interest_threshold;
  int dwarned;
  int dalarmed;
  int mwarned;
  int malarmed;
  int swarned;
  int salarmed;
}proc_averages;

/* Procan Configuration structure */
typedef struct
{
  int *euids;
  int *iuids;
  int nuids;
  char exclusions[20][20];
  int nclusions;
  char *adminemail;
  int warnlevel;
  int alarmlevel;
  int mailfrequency;
  int logfrequency;
  char *warnscript;
  char *alarmscript;
  char *mtapath;
}procan_config;

/* Will analyze process data gathered by the collector
 * looking for 'interesting' processes and apply an adaptive threshold
 * to analyze the level of interest.
 */
void* analyzer_thread(void *a);

/* Will gather and return ProcAn's configuration */
procan_config* get_config(void);

/* Handles the freeing of the config struct */
void free_config(procan_config *pc);

/* Will fetch a character array of statistics */
char* get_statistics(void);

/* Perform hourly housekeeping */
void perform_housekeeping(void);

/* Used to determine if a process is in our ignore list */
int should_ignore_proc(char *name);

/* Used to determine if a uid is in our ignore list */
int should_ignore_uid(int uid);

/* Signal Handler */
void handle_sig(int sig);
#endif
