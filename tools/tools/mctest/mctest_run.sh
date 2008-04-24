#!/bin/sh
# 
# A program to act as a test harness for the mctest program
#
# $FreeBSD$
#
# Defaults
size=1024
number=100
group=""
interface="cxgb0"
remote="ssh"
command="/sources/FreeBSD.CURRENT/src/tools/tools/mctest/mctest"
gap=1000

# Arguments are s (size), g (group), n (number), and c (command) followed
# by a set of hostnames.
args=`getopt s:g:n:c:i: $*`
if [ $? != 0 ]
then
    echo 'Usage: mctest_run -s size -g group -n number -c remote command host1 host2 hostN'
    exit 2
fi
set == $args
count=0
for i
do
  case "$i"
      in
      -s) 
	  size=$3; 
	  shift 2;;
      -n)
	  number=$3;
	  shift 2;;
      -g)
	  group=$3;
	  shift 2;;
      -c)
	  command=$3;
	  shift 2;;
      -i)
	  interface=$3;
	  shift 2;;
      --)
	  shift; break;;
      esac
done

#
# Start our remote sink/reflectors
#
shift;
current=0
now=`date "+%Y%m%d%H%M"`
for host in $*
do
  output=$host\_$interface\_$size\_$number\.$now
  $remote $host $command -r -M $# -m $current -n $number -s $size -i $interface > $output &
  sleep 1
  current=`expr $current + 1 `;
done

#
# Start the source/collector on this machine
#
$command -M $# -n $number -s $size -i le1 -t $gap > `uname -n`\_$size\_$number\.$now
