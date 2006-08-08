extern pthread_mutex_t hangup_mutex;
extern int m_hangup;

extern pthread_mutex_t procsnap_mutex;
extern proc_statistics *procsnap;
extern int numprocsnap;

extern pthread_mutex_t procchart_mutex;
extern proc_averages *procavs;
extern int numprocavs;

/* The collector thread is responsible
 * for collecting data about running processes
 * and placing them in a structure that 
 * The analyzer thread can read quickly
 */
void* collector_thread(void *a);
