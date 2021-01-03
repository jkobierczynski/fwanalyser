# Examples

# Analyse a single log file for Policy_B policy
./fwanalyser.pl -fwconfigfile=objects/objects_2014-06.csv -fwlogfile=logfiles/2014-06-10_153111.log.txt -fwpolicy=Policy_B -fwreportfile=reports/2014-06-10_153111_Policy_B.html -counter

# Analyse a single log file for Policy_A policy
./fwanalyser.pl -fwconfigfile=objects/objects_2014-06.csv -fwlogfile=logfiles/2014-06-10_153111.log.txt -fwpolicy=Policy_A -fwreportfile=reports/2014-06-10_153111_Policy_A.html -counter

# Analyse a short log file for Policy_A policy, write log to fwanalyser.log, debugging purposes
./fwanalyser.pl -fwconfigfile=objects/objects_2014-06.csv -fwlogfile=logfiles-test/2014-06-10_153111_short.log.txt -fwpolicy=Policy_A -fwreportfile=reports/2014-06-10_153111_Policy_A_short.html -verbose > fwanalyser.log

# Analyse a short log file for Policy_A policy, debugging purposes
./fwanalyser.pl -fwconfigfile=objects/objects_2014-06.csv -fwlogfile=logfiles-test/2014-06-10_153111_short.log.txt -fwpolicy=Policy_A -fwreportfile=reports/2014-06-10_153111_Policy_A_short.html -counter

# Analyse a short log file for Policy_B policy, debugging purposes
./fwanalyser.pl -fwconfigfile=objects/objects_2014-06.csv -fwlogfile=logfiles-test/2014-06-10_153111_short.log.txt -fwpolicy=Policy_B -fwreportfile=reports/2014-06-10_153111_Policy_B.html -counter 

# Analyse a short log file for Policy_B policy, report nonmatched logs, debugging purposes
./fwanalyser.pl -fwconfigfile=objects/objects_2014-06.csv -fwlogfile=logfiles-test/2014-06-10_153111_short.log.txt -fwpolicy=Policy_B -fwreportfile=reports/2014-06-10_153111_Policy_B_short.html -nonmatching

# Analyse a log dir for Policy_A
./fwanalyser.pl -fwconfigfile=objects/objects_2014-06.csv -fwlogdir=logfiles -fwpolicy=Policy_A -fwreportfile=reports/Policy_A.html -counter

# Analyse a log dir for Policy_B policy
./fwanalyser.pl -fwconfigfile=objects/objects_2014-06.csv -fwlogdir=logfiles -fwpolicy=Policy_B -fwreportfile=reports/Policy_B.html -counter

# Analyse a short log dir for Policy_B policy, debugging purposes
 ./fwanalyser.pl -fwconfigfile=objects/objects_2014-06.csv -fwlogdir=logfiles-test -fwpolicy=Policy_B -fwreportfile=reports/2014-06_Policy_B_short.html -counter

# Analyse a log dir for Policy_A policy
./fwanalyser.pl -fwconfigfile=objects/objects_2014-06.csv -fwlogdir=logfiles -fwpolicy=Policy_A -fwreportfile=reports/2014-06_Policy_A_new.html -counter
