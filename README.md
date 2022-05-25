# BleedingToothResearchs
My own exploit for the BleedingTooth vulnerability

The bug was found by Andy Nguyen but I decide to take it as a challenge for myself as i always wanted
to develop an exploit for remote kernel vulns and as a pratical real exploit for my freebsd blogpost serie at 
https://elkamika.blogspot.com/2019/06/freebsd-kernel-remote-code-execution.html

For now I have done the remote information leak part, I'm still working on the type confusion.
For now wireshark is needed to see the leaked value from remote target. 

gcc -g -o a2mp-leak a2mp-leak.c -lbluetooth; sudo ./a2mp-leak BT_ADDR

