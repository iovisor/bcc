Task Detector
------

This is a tool to trace the related schedule events of a specified task, eg the migration, sched in/out, wakeup and sleep/block.

The event was translated into sentence to be more readable, by execute command 'schedsnoop -t 4314', we continually trace the schedule events related to 'test' like:

```Shell
# schedsnoop -t 4314
Start tracing schedule events 
Target thread ID 4314
----------------------------
2020-06-19 16:27:07.947329      CPU=2      TID=4314   COMM=test                ENQUEUE                                               
2020-06-19 16:27:07.947421      CPU=2      TID=0      COMM=swapper/2           PREEMPTED                            92us             
2020-06-19 16:27:07.947429      CPU=2      TID=4314   COMM=test                EXECUTE AFTER WAITED                 100us            
2020-06-19 16:27:08.143353      CPU=2      TID=4314   COMM=test                WAIT AFTER EXECUTED                  195ms            
2020-06-19 16:27:08.143356      CPU=2      TID=24009  COMM=kworker/2:1         PREEMPT                                               
2020-06-19 16:27:08.143368      CPU=2      TID=24009  COMM=kworker/2:1         DEQUEUE AFTER PREEMPTED              12us             
2020-06-19 16:27:08.143370      CPU=2      TID=4314   COMM=test                EXECUTE AFTER WAITED                 17us             
----------------------------
```

This could be helpful on debugging the competition on CPU resource, to find out when and who has stolen the CPU for how long.

It can also tracing the syscall by append options -s.

```Shell
# schedsnoop -t 4314 -s
Start tracing schedule events (include SYSCALL)
Target thread ID 4314
----------------------------
2020-06-19 16:27:22.850918      CPU=2      TID=4314   COMM=test                ENQUEUE                                               
2020-06-19 16:27:22.850947      CPU=2      TID=0      COMM=swapper/2           PREEMPTED                            29us             
2020-06-19 16:27:22.850950      CPU=2      TID=4314   COMM=test                EXECUTE AFTER WAITED                 31us             
2020-06-19 16:27:22.850967      CPU=2      TID=4314   COMM=test                SC [1:write] ENTER                                    
2020-06-19 16:27:22.850984      CPU=2      TID=4314   COMM=test                SC [1:write] TAKE 17us TO EXIT                        
2020-06-19 16:27:23.118601      CPU=2      TID=4314   COMM=test                WAIT AFTER EXECUTED                  267ms            
2020-06-19 16:27:23.118606      CPU=2      TID=24009  COMM=kworker/2:1         PREEMPT                                               
...
```

Add debug option -d could print raw timestamp

```Shell
# schedsnoop -t 4314 -d
Start tracing schedule events 
Target thread ID 4314
----------------------------
400231700673269      CPU=2      TID=4314   COMM=test                ENQUEUE                                               
400231700742401      CPU=2      TID=0      COMM=swapper/2           PREEMPTED                            69us             
400231700747527      CPU=2      TID=24009  COMM=kworker/2:1         PREEMPT                                               
400231701020508      CPU=2      TID=24009  COMM=kworker/2:1         DEQUEUE AFTER PREEMPTED              272us            
400231701028563      CPU=2      TID=24114  COMM=kworker/2:0         PREEMPT                                               
400231701090181      CPU=2      TID=24114  COMM=kworker/2:0         DEQUEUE AFTER PREEMPTED              61us             
400231701095608      CPU=2      TID=4314   COMM=test                EXECUTE AFTER WAITED                 422us            
...
``` 
