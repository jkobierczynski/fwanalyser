[Expert@server]# cd $FWDIR/log
[Expert@server]# fwm logexport -n -i 2014-04-17_235900.log -o 2014-04-17_235900.txt
Starting... There are 1621547 log records in the file
Processed 20000 out of 1621547 records (1%)

for i in 2014-04-2*.log ; do fwm logexport -n -i $i -o $i.txt; done

for i in 2014-06-15_235900.log 2014-06-16_235900.log 2014-06-17_235900.log 2014-06-18_235900.log ; do fwm logexport -n -i $i -o $i.txt; done