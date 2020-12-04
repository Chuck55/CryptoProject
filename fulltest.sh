#!/usr/bin/expect -f
#
# This Expect script was generated by autoexpect on Thu Dec  3 15:12:34 2020
# Expect and autoexpect were both written by Don Libes, NIST.
#
# Note that autoexpect does not guarantee a working script.  It
# necessarily has to guess about certain things.  Two reasons a script
# might fail are:
#
# 1) timing - A surprising number of programs (rn, ksh, zsh, telnet,
# etc.) and devices discard or ignore keystrokes that arrive "too
# quickly" after prompts.  If you find your new script hanging up at
# one spot, try adding a short sleep just before the previous send.
# Setting "force_conservative" to 1 (see below) makes Expect do this
# automatically - pausing briefly before sending each character.  This
# pacifies every program I know of.  The -c flag makes the script do
# this in the first place.  The -C flag allows you to define a
# character to toggle this mode off and on.

set force_conservative 0  ;# set to 1 to force conservative mode even if
			  ;# script wasn't run conservatively originally
if {$force_conservative} {
	set send_slow {1 .1}
	proc send {ignore arg} {
		sleep .1
		exp_send -s -- $arg
	}
}

#
# 2) differing output - Some programs produce different output each time
# they run.  The "date" command is an obvious example.  Another is
# ftp, if it produces throughput statistics at the end of a file
# transfer.  If this causes a problem, delete these patterns or replace
# them with wildcards.  An alternative is to use the -p flag (for
# "prompt") which makes Expect only look for the last line of output
# (i.e., the prompt).  The -P flag allows you to define a character to
# toggle this mode off and on.
#
# Read the man page for more info.
#
# -Don


set timeout -1
spawn $env(SHELL)
match_max 100000
expect -exact "\[theboss@security CryptoProject\]\$ "
send -- "mkdir testroot1\r"
expect -exact "mkdir testroot1\r
\[theboss@security CryptoProject\]\$ "
send -- "cd testroot1\r"
expect -exact "cd testroot1\r
\[theboss@security testroot1\]\$ "
send -- "cat > a.txt\r"
expect -exact "cat > a.txt\r
"
send -- "this is a\r"
expect -exact "this is a\r
"
send -- ""
expect -exact "^C\r
\[theboss@security testroot1\]\$ "
send -- "cat > b.ttxt"
expect -exact "\[K"
send -- ""
expect -exact "\[K"
send -- ""
expect -exact "\[K"
send -- "txt"
expect -exact "\[K"
send -- ""
expect -exact "\[K"
send -- ""
expect -exact "\[K"
send -- "xt\r"
expect -exact "xt\r
"
send -- "this is b\r"
expect -exact "this is b\r
"
send -- ""
expect -exact "^C\r
\[theboss@security testroot1\]\$ "
send -- "cat > c.txt\r"
expect -exact "cat > c.txt\r
"
send -- "this is c\r"
expect -exact "this is c\r
"
send -- ""
expect -exact "^C\r
\[theboss@security testroot1\]\$ "
send -- "mkdir subdir1 subdir2 subdir3\r"
expect -exact "mkdir subdir1 subdir2 subdir3\r
\[theboss@security testroot1\]\$ "
send -- "cd subdir1\r"
expect -exact "cd subdir1\r
\[theboss@security subdir1\]\$ "
send -- "cat > d.txt\r"
expect -exact "cat > d.txt\r
"
send -- "this is d\r"
expect -exact "this is d\r
"
send -- ""
expect -exact "^C\r
\[theboss@security subdir1\]\$ "
send -- "cat > e.txt\r"
expect -exact "cat > e.txt\r
"
send -- "this is e\r"
expect -exact "this is e\r
"
send -- ""
expect -exact "^C\r
\[theboss@security subdir1\]\$ "
send -- "cat > f.txt\r"
expect -exact "cat > f.txt\r
"
send -- "this is f\r"
expect -exact "this is f\r
"
send -- ""
expect -exact "^C\r
\[theboss@security subdir1\]\$ "
send -- "cd ../subdir2\r"
expect -exact "cd ../subdir2\r
\[theboss@security subdir2\]\$ "
send -- "cat >>"
expect -exact "\[K"
send -- " g.txt\r"
expect -exact " g.txt\r
"
send -- "this is g\r"
expect -exact "this is g\r
"
send -- ""
expect -exact "^C\r
\[theboss@security subdir2\]\$ "
send -- "cat > h.txt\r"
expect -exact "cat > h.txt\r
"
send -- "this is h\r"
expect -exact "this is h\r
"
send -- ""
expect -exact "^C\r
\[theboss@security subdir2\]\$ "
send -- "cat > i.txt\r"
expect -exact "cat > i.txt\r
"
send -- "this is i\r"
expect -exact "this is i\r
"
send -- ""
expect -exact "^C\r
\[theboss@security subdir2\]\$ "
send -- "cd ../subdir3\r"
expect -exact "cd ../subdir3\r
\[theboss@security subdir3\]\$ "
send -- "cat > j.txt\r"
expect -exact "cat > j.txt\r
"
send -- "this is j\r"
expect -exact "this is j\r
"
send -- ""
expect -exact "^C\r
\[theboss@security subdir3\]\$ "
send -- "cat > k.txt\r"
expect -exact "cat > k.txt\r
"
send -- "this is k\r"
expect -exact "this is k\r
"
send -- ""
expect -exact "^C\r
\[theboss@security subdir3\]\$ "
send -- "cat > l.txt\r"
expect -exact "cat > l.txt\r
"
send -- "this is l\r"
expect -exact "this is l\r
"
send -- ""
expect -exact "^C\r
\[theboss@security subdir3\]\$ "
send -- "cd ../..\r"
expect -exact "cd ../..\r
\[theboss@security CryptoProject\]\$ "
send -- "java e"
expect -exact "\[K"
send -- "keygen dude1 public1 private1\r"
expect -exact "keygen dude1 public1 private1\r
\[theboss@security CryptoProject\]\$ "
send -- "java loc"
expect -exact "\[K"
send -- ""
expect -exact "\[K"
send -- ""
expect -exact "\[K"
send -- "keygen dude2 public2 private2\r"
expect -exact "keygen dude2 public2 private2\r
\[theboss@security CryptoProject\]\$ "
send -- "java lock testroot1 public2 private1 dude2\r"
expect -exact "java lock testroot1 public2 private1 dude2\r
Sun RSA public key, 2048 bits\r
  modulus: 17695911870808585548741338128762907087720346124489717780514394988419137770941020905564004615489175952365648718503794564846794712009170335837315785493821865293179793872654994192295417806801466104324354368802974775158061045289374218465469775365062403004399024693911970226293552504278963616636532179956969382538733940320151409499436325907698603831292112061492928338369359327756035955735462535680742412546897373356246658410160017979669828123819751136861319958775221279440191245796444794890323322093076368037922311573050254159571855531043522470809857564603236402273012061822075169698883990184640929393495918007579446553207\r
  public exponent: 65537\r
256\r
\[theboss@security CryptoProject\]\$ "
send -- "cd testroot1\r"
expect -exact "cd testroot1\r
\[theboss@security testroot1\]\$ "
send -- "ls -l\r"
expect -exact "ls -l\r
total 32\r
-rw-r--r-- 1 theboss theboss   26 Dec  3 15:18 a.txt.ci\r
-rw-r--r-- 1 theboss theboss   26 Dec  3 15:18 b.txt.ci\r
-rw-r--r-- 1 theboss theboss   26 Dec  3 15:18 c.txt.ci\r
-rw-r--r-- 1 theboss theboss  272 Dec  3 15:18 keyfile\r
-rw-r--r-- 1 theboss theboss  344 Dec  3 15:18 keyfile.sig\r
drwxr-xr-x 2 theboss theboss 4096 Dec  3 15:18 \[0m\[01;34msubdir1\[0m\r
drwxr-xr-x 2 theboss theboss 4096 Dec  3 15:18 \[01;34msubdir2\[0m\r
drwxr-xr-x 2 theboss theboss 4096 Dec  3 15:18 \[01;34msubdir3\[0m\r
\[theboss@security testroot1\]\$ "
send -- "cd subdir1\r"
expect -exact "cd subdir1\r
\[theboss@security subdir1\]\$ "
send -- "ls -l\r"
expect -exact "ls -l\r
total 12\r
-rw-r--r-- 1 theboss theboss 26 Dec  3 15:18 d.txt.ci\r
-rw-r--r-- 1 theboss theboss 26 Dec  3 15:18 e.txt.ci\r
-rw-r--r-- 1 theboss theboss 26 Dec  3 15:18 f.txt.ci\r
\[theboss@security subdir1\]\$ "
send -- "cd ../subdir2\r"
expect -exact "cd ../subdir2\r
\[theboss@security subdir2\]\$ "
send -- "ls -l\r"
expect -exact "ls -l\r
total 12\r
-rw-r--r-- 1 theboss theboss 26 Dec  3 15:18 g.txt.ci\r
-rw-r--r-- 1 theboss theboss 26 Dec  3 15:18 h.txt.ci\r
-rw-r--r-- 1 theboss theboss 26 Dec  3 15:18 i.txt.ci\r
\[theboss@security subdir2\]\$ "
send -- "cd ../subdir3\r"
expect -exact "cd ../subdir3\r
\[theboss@security subdir3\]\$ "
send -- "ls -l\r"
expect -exact "ls -l\r
total 12\r
-rw-r--r-- 1 theboss theboss 26 Dec  3 15:18 j.txt.ci\r
-rw-r--r-- 1 theboss theboss 26 Dec  3 15:18 k.txt.ci\r
-rw-r--r-- 1 theboss theboss 26 Dec  3 15:18 l.txt.ci\r
\[theboss@security subdir3\]\$ "
send -- "cd ../..\r"
expect -exact "cd ../..\r
\[theboss@security CryptoProject\]\$ "
send -- "java unlock testroot1 public1 private2 dude1\r"
expect -exact "java unlock testroot1 public1 private2 dude1\r
arg0 is: testroot1\r
arg1 is: public1\r
arg2 is: private2\r
arg3 is: dude1\r
Success!\r
Deleted the file: keyfile\r
Deleted the file: keyfile.sig\r
\[theboss@security CryptoProject\]\$ "
send -- "cd testroot1\r"
expect -exact "cd testroot1\r
\[theboss@security testroot1\]\$ "
send -- "ls -l\r"
expect -exact "ls -l\r
total 24\r
-rw-r--r-- 1 theboss theboss   10 Dec  3 15:19 a.txt\r
-rw-r--r-- 1 theboss theboss   10 Dec  3 15:19 b.txt\r
-rw-r--r-- 1 theboss theboss   10 Dec  3 15:19 c.txt\r
drwxr-xr-x 2 theboss theboss 4096 Dec  3 15:19 \[0m\[01;34msubdir1\[0m\r
drwxr-xr-x 2 theboss theboss 4096 Dec  3 15:19 \[01;34msubdir2\[0m\r
drwxr-xr-x 2 theboss theboss 4096 Dec  3 15:19 \[01;34msubdir3\[0m\r
\[theboss@security testroot1\]\$ "
send -- "cat t"
expect -exact "\[K"
send -- "a	"
expect -exact ".txt "
send -- "\r"
expect -exact "\r
this is a\r
\[theboss@security testroot1\]\$ "
send -- "cat b	"
expect -exact ".txt "
send -- "\r"
expect -exact "\r
this is b\r
\[theboss@security testroot1\]\$ "
send -- "cat c	"
expect -exact ".txt "
send -- "\r"
expect -exact "\r
this is c\r
\[theboss@security testroot1\]\$ "
send -- "cd subdir1	"
expect -exact "/"
send -- ""
expect -exact "\[K"
send -- "\r"
expect -exact "\r
\[theboss@security subdir1\]\$ "
send -- "cat d	"
expect -exact ".txt "
send -- "\r"
expect -exact "\r
this is d\r
\[theboss@security subdir1\]\$ "
send -- "cat e	"
expect -exact ".txt "
send -- "\r"
expect -exact "\r
this is e\r
\[theboss@security subdir1\]\$ "
send -- "cat f	"
expect -exact ".txt "
send -- "\r"
expect -exact "\r
this is f\r
\[theboss@security subdir1\]\$ "
send -- "cd ../subdir2\r"
expect -exact "cd ../subdir2\r
\[theboss@security subdir2\]\$ "
send -- "cat g	"
expect -exact ".txt "
send -- "\r"
expect -exact "\r
this is g\r
\[theboss@security subdir2\]\$ "
send -- "cat h	"
expect -exact ".txt "
send -- "\r"
expect -exact "\r
this is h\r
\[theboss@security subdir2\]\$ "
send -- "cat i	"
expect -exact ".txt "
send -- "\r"
expect -exact "\r
this is i\r
\[theboss@security subdir2\]\$ "
send -- "cd ../subdir3\r"
expect -exact "cd ../subdir3\r
\[theboss@security subdir3\]\$ "
send -- "ls -l\r"
expect -exact "ls -l\r
total 12\r
-rw-r--r-- 1 theboss theboss 10 Dec  3 15:19 j.txt\r
-rw-r--r-- 1 theboss theboss 10 Dec  3 15:19 k.txt\r
-rw-r--r-- 1 theboss theboss 10 Dec  3 15:19 l.txt\r
\[theboss@security subdir3\]\$ "
send -- "cat j	"
expect -exact ".txt "
send -- "\r"
expect -exact "\r
this is j\r
\[theboss@security subdir3\]\$ "
send -- "cat 	"
expect -exact ""
send -- "k	"
expect -exact ".txt "
send -- "\r"
expect -exact "\r
this is k\r
\[theboss@security subdir3\]\$ "
send -- "cat l	"
expect -exact ".txt "
send -- "\r"
expect -exact "\r
this is l\r
\[theboss@security subdir3\]\$ "
send -- "cd ../..\r"
expect -exact "cd ../..\r
\[theboss@security CryptoProject\]\$ "
send -- "exit\r"
expect eof