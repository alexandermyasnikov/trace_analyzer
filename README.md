
# Simple trace-analyzer - singlestepper

Author: Alexander Myasnikov   myasnikov.alexander.s@gmail.com

Goals:
* Show arguments and result of the called function.

Future:
* Attaching to process by pid.
* Auto attaching to fork processes.
* Analysis every instuction step by step.
* Very slowly.

How to use:
* Run traced process, for example, `./sample/fork`
* Run singlestepper with arguments pid of traced process and list of functions, for example, `./ptrace_singlestep/singlestepper $(pgrep -o fork) info/callbacks_info.cfg`
* To stop the singlestepper send signal C-c or remove file `/tmp/SINGLE_STEPPER_LOCK`

