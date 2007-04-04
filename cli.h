extern pthread_mutex_t hangup_mutex;
extern int m_hangup;

extern pthread_mutex_t procsnap_mutex;
extern proc_statistics *procsnap;
extern int numprocsnap;

extern pthread_mutex_t procchart_mutex;
extern proc_averages *procavs;
extern int numprocavs;

extern pthread_mutex_t pconfig_mutex;

extern void* collector_thread(void *a);

int interactive_mode();
