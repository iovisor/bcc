#!/bin/bash

cmd="ip netns exec host0"
if [[ "$(id -u)" != "0" ]]; then
  cmd="sudo $cmd"
fi

B=/usr/bin/byobu
S=tunnel1

tmux has-session -t $S &> /dev/null

if [[ $? != 0 ]]; then
  $B new-session -s $S -n "c1" -d
  tmux send -t $S "$cmd ping 192.168.0.1 -s512" C-m
  tmux new-window -t $S -n "c2"
  tmux send -t $S "$cmd ping 192.168.0.2 -s128" C-m
  tmux new-window -t $S -n "c3"
  tmux send -t $S "$cmd ping 192.168.0.3 -s1024" C-m
  tmux new-window -t $S -n "c3"
  tmux send -t $S "$cmd ping 192.168.0.4 -s128" C-m
  tmux new-window -t $S -n "c3"
  tmux send -t $S "$cmd ping 192.168.0.5 -s128" C-m
  tmux new-window -t $S -n "c3"
  tmux send -t $S "$cmd ping 192.168.0.6 -s128" C-m
  tmux new-window -t $S -n "c4"
  tmux send -t $S "$cmd ping 192.168.1.2 -s128" C-m
  tmux new-window -t $S -n "c5"
  tmux send -t $S "$cmd ping 192.168.1.4 -s768" C-m
  tmux new-window -t $S -n "c2"
  tmux send -t $S "$cmd ping 192.168.2.2 -s128" C-m
  tmux new-window -t $S -n "c3"
  tmux send -t $S "$cmd ping 192.168.2.7 -s1024" C-m
  tmux new-window -t $S -n "c4"
  tmux send -t $S "$cmd ping 192.168.2.2 -s128" C-m
  tmux new-window -t $S -n "c5"
  tmux send -t $S "$cmd ping 192.168.3.8 -s768" C-m
  tmux new-window -t $S -n "c5"
  tmux send -t $S "$cmd ping 192.168.3.9 -s768" C-m
fi

exec tmux attach -t $S

