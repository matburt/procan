extern pthread_mutex_t procchart_mutex;
extern proc_averages *procavs;
extern int numprocavs;

int syslog_backend(procan_config *pc, struct timeval *schedtime);
int mail_backend(procan_config *pc, struct timeval *schedtime);
int script_backend(procan_config *pc);
int get_warns(int *indcs, procan_config *pc, int backendtype);
int get_alarms(int *indcs, procan_config *pc, int backendtype);
