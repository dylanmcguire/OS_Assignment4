#! /usr/bin/env stap

//# Copyright (C) 2006 IBM Corp.
//#
//# This file is part of systemtap, and is free software.  You can
//# redistribute it and/or modify it under the terms of the GNU General
//# Public License (GPL); either version 2, or (at your option) any
//# later version.

//#
//# Print the system call count by process name in descending order.
//#

global syscalls

probe begin {
  print ("Collecting data... Type Ctrl-C to exit and display results\n")
}

probe syscall.* {
  syscalls[execname()]++
}

probe end {
  printf ("%-10s %-s\n", "#SysCalls", "Process Name")
  foreach (proc in syscalls-)
    printf("%-10d %-s\n", syscalls[proc], proc)
}