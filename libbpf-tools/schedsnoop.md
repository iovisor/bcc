Task Detector
------

Schedsnoop is a tool that traces the related schedule events of a specified task, e.g. the migration, sched in/out, wakeup and sleep/block. It will record the preemption information during tracing and output a report at the end to find out who has stolen the CPU for the most.

By execute command 'schedsnoop -t 4314', we continually trace the schedule events related to 'test' and finally output a report to show the top 10 processes that have preempted our target task (sorted by average preemption time):

```Shell
# schedsnoop -t 26371
Start tracing schedule events related to tid 26371
Press CTRL+C or wait until target exits to see report

Preemption Report:
CPU  TID    COMM                          Count  Avg       Longest   
2    2487   gsd-color                     1      139us     139us     
2    3241   gmain                         8      44us      92us      
2    0      swapper/2                     5      33us      38us      
2    1546   crond                         1      30us      30us      
2    697    kworker/2:1H                  11     13us      40us      
2    2798   JS Helper                     1      10us      10us      
2    24667  kworker/2:1                   8      8487ns    18us      
2    20     migration/2                   8      3475ns    4133ns    
2    1297   xfsaild/dm-2                  2      3149ns    3206ns    
```

It can also tracing the syscall by append options -s, which will output a syscall report at the end.

```Shell
# schedsnoop -t 26371 -s
Start tracing schedule events related to tid 26371(include SYSCALL)
Press CTRL+C or wait until target exits to see report

Preemption Report:
CPU  TID    COMM                          Count  Avg       Longest   
3    704    kworker/3:1H                  5      88us      240us     
3    3236   gmain                         4      59us      106us     
3    0      swapper/3                     3      58us      126us     
3    3764   kworker/3:1                   6      6359ns    17us      
3    25     migration/3                   5      2134ns    2249ns    

SYSCALL Report:
CPU  TID    SYSCALL                       Count  Avg       Longest   
3    3236   gmain[7:poll]                 3      6666ms    8000ms    
3    26371  test[35:nanosleep]            3      2003ms    2008ms    
3    26371  test[1:write]                 7      27us      68us      
3    3236   gmain[254:inotify_add_watch]  32     3867ns    64us      
```

With log option -l, it will print each related events synchronously with human-readable format, which could be more helpful on debugging the competition on CPU resource. If syscall option -s is enabled, it will also print related syscall events. Enabling debug option -d additionally could print raw timestamp instead of local time.

```Shell
# schedsnoop -t 26371 -l
Start tracing schedule events related to tid 26371
Press CTRL+C or wait until target exits to see report
----------------------------
21:29:20.556477     CPU=5      TID=26371  COMM=test                ENQUEUE                                               
21:29:20.556509     CPU=5      TID=0      COMM=swapper/5           PREEMPTED                            32us             
21:29:20.556514     CPU=5      TID=26371  COMM=test                EXECUTE AFTER WAITED                 37us             
21:29:24.366207     CPU=5      TID=26371  COMM=test                WAIT AFTER EXECUTED                  3809ms           
21:29:24.366212     CPU=5      TID=35     COMM=migration/5         PREEMPT                                               
21:29:24.366223     CPU=5      TID=35     COMM=migration/5         DEQUEUE AFTER PREEMPTED              10us             
21:29:24.366241     CPU=5      TID=26371  COMM=test                EXECUTE AFTER WAITED                 34us             
21:29:25.736573     CPU=5      TID=26371  COMM=test                DEQUEUE AFTER EXECUTED               1370ms           
...
``` 
