Task Detector
------

This is a tool to trace the related schedule events of a specified task, eg the migration, sched in/out, wakeup and sleep/block.

The event was translated into sentence to be more readable, by execute command 'task_detector -p 24104' we continually tracing the schedule events related to 'top' like:

```Shell
# task_detector -p 24104
Start tracing schedule events 
Target task pid 24104
----------------------------
102770938643193            CPU=1      PID=24104  COMM=top                 ENQUEUE                                               
102770938684071            CPU=1      PID=0      COMM=IDLE                PREEMPTED                            40us             
102770938684854            CPU=1      PID=24104  COMM=top                 EXECUTE AFTER WAITED                 41us             
102770949149591            CPU=1      PID=24104  COMM=top                 WAIT AFTER EXECUTED                  10464us          
102770949149957            CPU=1      PID=24190  COMM=kworker/1:5-mm_     PREEMPT                                               
102770949153368            CPU=1      PID=24190  COMM=kworker/1:5-mm_     DEQUEUE AFTER PREEMPTED              3411ns           
102770949153470            CPU=1      PID=24104  COMM=top                 EXECUTE AFTER WAITED                 3879ns           
102770949277377            CPU=1      PID=24104  COMM=top                 DEQUEUE AFTER EXECUTED               123us    
----------------------------
```

This could be helpful on debugging the competition on CPU resource, to find out who has stolen the CPU and how much it stolen.

It can also tracing the syscall by append options -s.

```Shell
Start tracing schedule events (include SYSCALL)
Target task pid 24104
----------------------------
104043332442246            CPU=2      PID=24104  COMM=top                 ENQUEUE                                               
104043332475329            CPU=2      PID=0      COMM=IDLE                PREEMPTED                            33us             
104043332476101            CPU=2      PID=24104  COMM=top                 EXECUTE AFTER WAITED                 33us             
104043332525807            CPU=2      PID=24104  COMM=top                 SC [257:openat] ENTER                                 
104043332570577            CPU=2      PID=24104  COMM=top                 SC [257:openat] TAKE 44us TO EXIT                     
104043332577193            CPU=2      PID=24104  COMM=top                 SC [5:fstat] ENTER                                    
104043332582304            CPU=2      PID=24104  COMM=top                 SC [5:fstat] TAKE 5111ns TO EXIT                      
104043332599968            CPU=2      PID=24104  COMM=top                 SC [3:close] ENTER                                    
104043332602472            CPU=2      PID=24104  COMM=top                 SC [3:close] TAKE 2504ns TO EXIT                      
104043332618210            CPU=2      PID=24104  COMM=top                 SC [8:lseek] ENTER                                    
104043332624106            CPU=2      PID=24104  COMM=top                 SC [8:lseek] TAKE 5896ns TO EXIT                      
104043332716699            CPU=2      PID=24104  COMM=top                 SC [257:openat] ENTER                                 
104043332744398            CPU=2      PID=24104  COMM=top                 SC [257:openat] TAKE 27us TO EXIT                    
...
``` 
