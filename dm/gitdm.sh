#!/bin/bash
git log -p -M skiboot-4.0| PATH=~/gitdm:$PATH gitdm -u -s -a -t -o gitdm-skiboot-4.0.txt -h gitdm-skiboot-4.0.html
git log -p -M 1d880992fd8c8457a2d990ac6622cfd58fb1b261..skiboot-4.0| PATH=~/gitdm:$PATH gitdm -u -s -a -t -o gitdm-skiboot-4.0-excl-r1.txt -h gitdm-skiboot-4.0-excl-r1.html
git log -p -M 1d880992fd8c8457a2d990ac6622cfd58fb1b261..master| PATH=~/gitdm:$PATH gitdm -u -s -a -t -o gitdm-skiboot-master.txt -h gitdm-skiboot-master.html
git log -p -M skiboot-4.0..skiboot-4.1|PATH=~/gitdm:$PATH gitdm -u -s -a -t -o gitdm-skiboot-4.1.txt -h ghtdm-skiboot-4.1.html
