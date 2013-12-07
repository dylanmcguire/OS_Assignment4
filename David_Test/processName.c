#! /usr/bin/env stap

//# Copyright (C) 2006 IBM Corp.
//#
//# This file is part of systemtap, and is free software.  You can
//# redistribute it and/or modify it under the terms of the GNU General
//# Public License (GPL); either version 2, or (at your option) any
//# later version.

//#
//# Print the system call count by process ID in descending order.
//#

global syscalls

probe begin {
  print ("Collecting data... Type Ctrl-C to exit and display results\n")
}

probe syscall.* {
  syscalls[pid()]++
}

probe end {
  printf ("%-10s %-s\n", "#SysCalls", "PID")
  foreach (pid in syscalls-)
    printf("%-10d %-d\n", syscalls[pid], pid)
}