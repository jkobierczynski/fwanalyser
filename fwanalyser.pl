#!/usr/bin/perl

use Term::ANSIColor;
use Net::Patricia;
use HTML::Table;
use Data::Dumper;
use Sort::Key::IPv4 qw(ipv4sort);
use Sort::Key::IPv4 qw(netipv4sort);
use Sort::Key::IPv4 qw(ipv4keysort);
use Sort::Key::IPv4 qw(netipv4keysort);
use DBM::Deep;
use Storable;
use NetAddr::IP;
use strict;
###########################################################################
#                                                                         #
#            FW Analyser                                                  #
#                                                                         #
#            For those who don't want to spend $$$$ on analysers          #
#                                                                         #
###########################################################################

### Vars ###

my ($prm_fwconfigfile,$prm_fwlogfile,$prm_fwlogdir,$prm_fwpolicy,$prm_fwreportfile,$prm_verbose,$prm_logrule,$prm_counter,$prm_nonmatching,$prm_nosubnettrie);
my $prm_fwdataread="";
my $prm_fwdatawrite="";
my $logfilename="";
my @entry;
my $fw={};
my $db;
my $dbout;
my $logentry={};
my $logheader={};
my $rulebase_header="";
my $rule_counter=0;
my $log_counter=0;
my $rulehit_counter=0;
my $log_filtered_counter=0;
my $section_header="";
my $subnetlist=[];
my $rules_matched=[];
my $srvgroupstack=[];
my $global_src_subnets=[];
my $global_dst_subnets=[];
my $prm_subnettrie_modulo=8;

### Main Program ###

  &read_parameters();
  if ($prm_fwdataread ne "") {
    #&open_read_persistent_db();
    &open_read_persistent_dbnew();
    #&read_dbreport();
  }
  $fw->{policy}{trie}=new Net::Patricia || die "Could not create a trie ($!)\n";
  &read_fwpolicy_entries();
  &open_fwconfigfile();
  &read_fwconfigfile_entries();
  &process_file_subnets_afterwards();
  if ($prm_fwdataread ne "") {
    #&open_read_persistent_db();
    &open_read_persistent_dbnew();
    #&read_dbreport();
  }
  if (defined $prm_fwlogdir) {
    &open_fwlogdir($prm_fwlogdir);
    while ( defined ($logfilename = readdir FWLOGDIR ) ) { 
      next if $logfilename =~ /^\.\.?$/;
      &open_fwlogfile($prm_fwlogdir."/".$logfilename);
      &read_fwlogfile_header();
      &read_fwlogfile_entries();
      &close_fwlogfile();
    }
    &close_fwlogdir($prm_fwlogdir);
  } else {
    &open_fwlogfile($prm_fwlogfile);
    &read_fwlogfile_header();
    &read_fwlogfile_entries();
    &close_fwlogfile();
  }
  &open_fwreportfile();
  &do_fwreport();
  if ($prm_fwdatawrite ne "") {
    #&open_write_persistent_db();
    &open_write_persistent_dbnew();
    #&write_dbreport();
  }
  &close_fwconfigfile();
  &close_fwreportfile();
#}
exit(0);

### functions ###
#
sub read_parameters() {

  my ($option,$brol,$value);

  foreach my $argv (@ARGV) {
    #$argv =~ /-(\w+)=.*/;
    #print $argv."\n";
    if ($argv =~ /^-e$/) {
      $prm_logrule = $ENV{FWANALYSER_LOGRULE};
      $prm_fwconfigfile = $ENV{FWANALYSER_FWCONFIGFILE};
      $prm_fwlogfile = $ENV{FWANALYSER_FWLOGFILE};
      $prm_fwlogdir = $ENV{FWANALYSER_FWLOGDIR};
      $prm_fwreportfile = $ENV{FWANALYSER_FWREPORTFILE};
      $prm_fwpolicy = $ENV{FWANALYSER_FWPOLICY};
      $prm_fwdataread = $ENV{FWANALYSER_FWDATAREAD};
      $prm_fwdatawrite = $ENV{FWANALYSER_FWDATAWRITE};
      }
    }

  while (@ARGV) {
    $_ = shift @ARGV;
    ($option,$brol,$value) = /-(\w+)(=(\S+))?/;

    # Parsing arguments
    # next arg is verbose mode
    if ($option =~ /verbose/) { $prm_verbose = 1; }
    if ($option =~ /logrule/) { $prm_logrule = $value; }
    if ($option =~ /counter/) { $prm_counter = 1; }
    if ($option =~ /nonmatching/) { $prm_nonmatching = 1; }
    if ($option =~ /nosubnettrie/) { $prm_nosubnettrie = 1; }
    # next arg is the agents file name
    if ($option =~ /fwconfigfile/) { $prm_fwconfigfile = $value; }
    if ($option =~ /fwlogfile/) { $prm_fwlogfile = $value; }
    if ($option =~ /fwlogdir/) { $prm_fwlogdir = $value; }
    if ($option =~ /fwreportfile/) { $prm_fwreportfile = $value; }
    if ($option =~ /fwpolicy/) { $prm_fwpolicy = $value; }
    if ($option =~ /fwdataread/) { $prm_fwdataread = $value; }
    if ($option =~ /fwdatawrite/) { $prm_fwdatawrite = $value; }
  }

  if(!defined $prm_fwconfigfile || (!defined $prm_fwlogfile && !defined $prm_fwlogdir) || !defined $prm_fwreportfile ) {
    &usage();
    exit(1);
  }

  if($prm_verbose){
    print color('green')."Reading Arguments:\n".color('reset');
    print " Argument verbose = ".$prm_verbose?("SET\n"):("NOT SET\n");
    print " Argument verbose logrule = $prm_logrule\n";
    print " Argument counter = ".$prm_counter?("SET\n"):("NOT SET\n");
    print " Argument nonmatching = ".$prm_nonmatching?("SET\n"):("NOT SET\n");
    print " Argument nosubnettrie = ".$prm_nosubnettrie?("SET\n"):("NOT SET\n");
    print " Argument Firewall config file name = $prm_fwconfigfile\n";
    print " Argument Firewall log file name = $prm_fwlogfile\n";
    print " Argument Firewall log dir name = $prm_fwlogdir\n";
    print " Argument Firewall report output html file name = $prm_fwreportfile\n";
    print " Argument Firewall policy = $prm_fwpolicy\n";
    print " Argument Read Persistent Database = $prm_fwdataread\n";
    print " Argument Write Persistent Database = $prm_fwdatawrite\n";
  }
}

sub usage() {
  print "Usage: $0 [-e] [-file=<analyser_file>]]\n";
  print "Parameters:\n";
  print "-e = Use environment variables\n";
  print "-verbose = verbose mode (no arguments)\n";
  print "-logrule = verbose log rule, use number\n" ;
  print "-nonmatching = verbose on non-matching fw logs\n";
  print "-nosubnettrie = don't count subnetstries (makes logfile parsing much faster!)\n";
  print "-fwconfigfile = config csv file to import    , with -e default FWANALYSER_FWCONFIGFILE\n";
  print "-fwlogfile = csv log file to import          , with -e default FWANALYSER_FWLOGFILE\n";
  print "-fwlogdir = csv log file dir to import       , with -e default FWANALYSER_FWLOGDIR\n";
  print "-fwreportfile = report html file             , with -e default FWANALYSER_FWREPORTFILE\n";
  print "-fwpolicy = fw policy to analyse             , with -e default FWANALYSER_FWPOLICY\n";
  print "-fwdataread = read fw persistent database    , with -e default FWANALYSER_FWDATAREAD\n";
  print "-fwdatawrite = write fw persistent database  , with -e default FWANALYSER_FWDATAWRITE\n";
}

sub open_fwconfigfile() {
  !$prm_verbose || print color('green')."Opening $prm_fwconfigfile\n".color('reset');
  open (FWCONFIGFILE, "< $prm_fwconfigfile") or die "Can't open $prm_fwconfigfile";
}

sub close_fwconfigfile() {
  !$prm_verbose || print color('green')."Closing $prm_fwconfigfile\n".color('reset');
  close (FWCONFIGFILE);
}

sub open_fwreportfile() {
  !$prm_verbose || print color('green')."Opening $prm_fwreportfile\n".color('reset');
  open (FWREPORTFILE, "> $prm_fwreportfile") or die "Can't open $prm_fwreportfile";
}

sub close_fwreportfile() {
  !$prm_verbose || print color('green')."Closing $prm_fwreportfile\n".color('reset');
  close (FWREPORTFILE);
}

sub open_read_persistent_db() {
  print color('green')."Opening read Persistent database $prm_fwdataread\n".color('reset');
  $db= new DBM::Deep ( file => $prm_fwdataread , mode => "r");
}

sub open_read_persistent_dbnew() {
  print color('green')."Opening read Persistent database $prm_fwdataread\n".color('reset');
  $fw = retrieve($prm_fwdataread);
}

sub open_write_persistent_db() {
  print color('green')."Opening write Persistent database $prm_fwdatawrite\n".color('reset');
  $dbout= new DBM::Deep ( file => $prm_fwdatawrite , mode => "w");
}

sub open_write_persistent_dbnew() {
  print color('green')."Opening write Persistent database $prm_fwdatawrite\n".color('reset');
  store $fw, $prm_fwdatawrite;
}

sub read_fwconfigfile_entries() {
  !$prm_verbose || print color('green')."Reading file entry's\n".color('reset');
  $fw->{net}{"Any"}="0.0.0.0/0";
  push @{$subnetlist},"0.0.0.0/0";

  while (<FWCONFIGFILE>) {
    chomp;                  # no newline
    s/#.*//;                # no comments
    s/^\s+//;               # no leading white
    s/\s+$//;               # no trailing white
    next unless length;     # anything left?
    @entry=split(/\s*,\s*/, $_);
    chomp(@entry);
    if ($prm_verbose) {
      foreach my $field (@entry) {
        print "[".$field."]";
      }
      print "\n";
    }
    SWITCH: {
      if ($entry[1] =~ /^host/) { process_file_host(); last SWITCH; }
      if ($entry[1] =~ /^cpgw/) { process_file_host(); last SWITCH; }
      if ($entry[1] =~ /^plaingw/) { process_file_plaingw(); last SWITCH; }
      if ($entry[1] =~ /^net/) { process_file_net(); last SWITCH; }
      if ($entry[1] =~ /^group/) { process_file_group(); last SWITCH; }
      if ($entry[1] =~ /^exclgrp/) { process_file_exclgrp(); last SWITCH; }
      if ($entry[1] =~ /^icmp/) { process_file_icmp(); last SWITCH; }
      if ($entry[1] =~ /^tcp/) { process_file_tcp(); last SWITCH; }
      if ($entry[1] =~ /^udp/) { process_file_udp(); last SWITCH; }
      if ($entry[1] =~ /^srvgroup/) { process_file_srvgroup(); last SWITCH; }
      if ($entry[0] =~ /^security_rule/) { process_file_security_rule(0); last SWITCH; }
      if ($entry[0] =~ /^disabled_sec_rule/) { process_file_security_rule(1); last SWITCH; }
      if ($entry[0] =~ /^rulebase_header/) { process_file_rulebase_header(); last SWITCH; }
    }
  }
}

sub read_fwpolicy_entries() {
  if ($prm_verbose) {
    print color('green')."Opening fwpolicy.cfg file\n".color('reset');
  }
  open (FWPOLICY, "< fwpolicy.cfg");
  while (<FWPOLICY>) {
    chomp;                  # no newline
    s/#.*//;                # no comments
    s/^\s+//;               # no leading white
    s/\s+$//;               # no trailing white
    next unless length;     # anything left?
    @entry=split(/\s*;\s*/, $_);
    chomp(@entry);
    $fw->{firewall}{$entry[0]}=$entry[1];
    if ($prm_verbose) {
      print "Firewall ".$entry[0]." has policy ".$entry[1]."\n";
    }
  }
  close(FWPOLICY); 
}

sub process_file_host() {
  $fw->{host}{$entry[0]}=$entry[2]."/32";
  if ($prm_verbose) {
	print color('green')."Adding host ".$entry[0]." with ip = ".$entry[2]."\n".color('reset');
  }
}

sub process_file_plaingw() {
  $fw->{host}{$entry[0]}=$entry[2]."/32";
  if ($prm_verbose) {
	print color('green')."Adding host ".$entry[0]." with ip = ".$entry[2]."\n".color('reset');
  }
}

sub process_file_net() {
  my $ip = NetAddr::IP->new($entry[2],$entry[3]);
  $fw->{net}{$entry[0]}="$ip";
  !$prm_verbose || print color('green')."Adding net ".$entry[0]." with ip = ".$ip."\n".color('reset');
  push @{$subnetlist},"$ip";
}

sub process_file_group() {
  if (!defined $fw->{group}{$entry[0]}{group}) { $fw->{group}{$entry[0]}{group} = []; }
  push @{$fw->{group}{$entry[0]}{group}},$entry[2];
  if ($prm_verbose) {
	print color('green')."Adding group ".$entry[0]." with items = ".$entry[2]."\n".color('reset');
  }
}

sub process_file_exclgrp() {
  $fw->{exclgrp}{$entry[0]} = {include=> $entry[2], exclude=> $entry[3]};
  if ($prm_verbose) {
	print color('green')."Adding exclgrp ".$entry[0]." with include = ".$entry[2]." and exclude = ".$entry[3].color('reset')."\n";
  }
}

sub process_file_icmp() {
  $fw->{service}{icmp}{$entry[0]}=$entry[2];
  if ($prm_verbose) {
	print color('green')."Adding icmp ".$entry[0]." with type = ".$entry[2]."\n".color('reset');
  }
}

sub process_file_tcp() {
  $fw->{service}{tcp}{$entry[0]}=$entry[2];
  if ($prm_verbose) {
	print color('green')."Adding tcp ".$entry[0]." with port = ".$entry[2]."\n".color('reset');
  }
}

sub process_file_udp() {
  $fw->{service}{udp}{$entry[0]}=$entry[2];
  if ($prm_verbose) {
	print color('green')."Adding udp ".$entry[0]." with port = ".$entry[2]."\n".color('reset');
  }
}

sub process_file_srvgroup() {
  if (!defined $fw->{service}{group}{$entry[0]}) { $fw->{service}{group}{$entry[0]} = []; }
  push @{$fw->{service}{group}{$entry[0]}}, $entry[2];
  if ($prm_verbose) {
	print color('green')."Adding srvgroup ".$entry[0]." with service = ".$entry[2]."\n".color('reset');
  }
}

sub process_file_security_rule() {
  my $disabled=shift;
  my @src;
  my @dst;
  my @services;
  my $entries;
  my $rule_src_subnets=[];
  my $rule_dst_subnets=[];
  my $sortedlist=[];
  my $subnet;
  my %seen=();
  my %seen2=();
  my $ip;
  my $ref;

  $rule_counter++;
  if ($prm_fwpolicy ne $rulebase_header) {
    return 0;
  }

  $fw->{policy}{$rulebase_header}{rules}[$rule_counter]={};
  $ref = $fw->{policy}{$rulebase_header}{rules}[$rule_counter];
  
  # rule disabled?
  if ($disabled==1) {
    $ref->{rule_disabled}=1;
    print color('red')."Security Rule $rule_counter is disabled".color('reset')."\n";
  } else {
    print color('blue')."Security Rule $rule_counter".color('reset')."\n";
  }

  #$ref->{src}{$subnet->{entry}} = { counter => 0 };
  $ref->{srcrule}= $entry[1];
  $ref->{src} = {};
  $ref->{dstrule}= $entry[2];
  $ref->{dst} = {};
  $ref->{3} = $entry[3];
  $ref->{servicerule} = $entry[4];
  $ref->{action} = $entry[5];
  $ref->{log} = $entry[6];
  $ref->{firewall} = $entry[7];
  $ref->{8} = $entry[8];
  $ref->{comment} = $entry[9];

  $ref->{srctrie}=new Net::Patricia || die "Could not create a trie ($!)\n";
  $ref->{dsttrie}=new Net::Patricia || die "Could not create a trie ($!)\n";
 
  !$prm_verbose || print "SRC=";
  @src=split(/\s*;\s*/, $entry[1]);
  resolve_recursive_entries($global_src_subnets,$rule_src_subnets,$ref->{src},\@src,'include');
  @{$sortedlist} = netipv4keysort { $_->{subnet} } @{$rule_src_subnets};
  @{$rule_src_subnets} = grep {! $seen{$_->{subnet}}++ } @{$sortedlist};
  foreach $subnet (@{$rule_src_subnets}) {
    $ref->{src}{$subnet->{entry}} = { entry => $subnet->{entry}, counter => 0 };
    # Local Src Trie used for network entry lookup
    if (!defined $ref->{srctrie}->match_string($subnet->{subnet})) {
      $ref->{srctrie}->add_string($subnet->{subnet},[ { entry => $subnet->{entry}, incl => $subnet->{incl}, refcounter => $ref->{src}{$subnet->{entry}}}]);
    } else {
      $entries=[];
      push @{$entries},@{$ref->{srctrie}->match_string($subnet->{subnet})};
      push @{$entries},{ entry => $subnet->{entry}, incl => $subnet->{incl}, refcounter => $ref->{src}{$subnet->{entry}}};
      $ref->{srctrie}->add_string($subnet->{subnet}, $entries);
    }
  }
  if ($prm_verbose) {
    print "\n=";
    foreach my $subnet (@{$rule_src_subnets}) {
      if ($subnet->{incl} eq 'include') { print "[".color('blue').$subnet->{subnet}.color('reset')."]"; }
      if ($subnet->{incl} eq 'exclude') { print "[".color('red')."!".$subnet->{subnet}.color('reset')."]"; }
    }
  print "\n";
  print "DST=";
  }
  @dst=split(/\s*;\s*/, $entry[2]);
  resolve_recursive_entries($global_dst_subnets,$rule_dst_subnets,$ref->{dst},\@dst,'include');
  @{$sortedlist} = netipv4keysort { $_->{subnet} } @{$rule_dst_subnets};
  @{$rule_dst_subnets} = grep {! $seen2{$_->{subnet}}++ } @{$sortedlist};
  foreach $subnet (@{$rule_dst_subnets}) {
    $ref->{dst}{$subnet->{entry}} = { entry => $subnet->{entry}, counter => 0 };
    # Local Dst Trie used for network entry lookup
    if (!defined $ref->{dsttrie}->match_string($subnet->{subnet})) {
      $ref->{dsttrie}->add_string($subnet->{subnet},[ { entry => $subnet->{entry}, incl => $subnet->{incl}, refcounter => $ref->{dst}{$subnet->{entry}}}]);
    } else {
      $entries=[];
      push @{$entries},@{$ref->{dsttrie}->match_string($subnet->{subnet})};
      push @{$entries},{ entry => $subnet->{entry},  incl => $subnet->{incl}, refcounter => $ref->{dst}{$subnet->{entry}}};
      $ref->{dsttrie}->add_string($subnet->{subnet}, $entries);
    }
  }
  if ($prm_verbose) {
    print "\n=";
    foreach my $subnet (@{$rule_dst_subnets}) {
      if ($subnet->{incl} eq 'include') { print "[".color('blue').$subnet->{subnet}.color('reset')."]"; }
      if ($subnet->{incl} eq 'exclude') { print "[".color('red')."!".$subnet->{subnet}.color('reset')."]"; }
    }
    print "\n";
  }
  @services=split(/\s*;\s*/, $entry[4]);
  chomp(@services);
  foreach my $srv (@services) {
    resolver_recursive_srv($ref,$srv,[]);
  }
}

sub process_file_subnets_afterwards($) {
my %seen=();
my $sortedlist=[];
my $rules=[];
my $subnet;

  @{$sortedlist} = netipv4keysort { $_->{subnet} } @{$global_src_subnets};
  #@{$ipsrcsubnets} = grep {! $seen{$_->{subnet}}++ } @{$sortedlist};
  #foreach $subnet (@{$ipsrcsubnets}) {
  foreach $subnet (@{$sortedlist}) {
    # Global Src Trie used for rule lookup
    if (!defined $fw->{policy}{$prm_fwpolicy}{srctrie}->match_string($subnet->{subnet})) {
      $fw->{policy}{$prm_fwpolicy}{srctrie}->add_string($subnet->{subnet}, [{ rule => $subnet->{rule}, subnet => $subnet->{subnet}, incl => $subnet->{incl} }]);
    } else {
      $rules=[];
      push @{$rules},@{$fw->{policy}{$prm_fwpolicy}{srctrie}->match_string($subnet->{subnet})};
      push @{$rules},({ rule => $subnet->{rule}, subnet => $subnet->{subnet}, incl => $subnet->{incl} });
      $fw->{policy}{$prm_fwpolicy}{srctrie}->add_string($subnet->{subnet}, $rules);
    }
    #if ($prm_verbose) {
    #  print "Subnet: ".$subnet->{subnet}."\n"; 
    #  foreach my $subnet (@{$fw->{policy}{$prm_fwpolicy}{srctrie}->match_string($subnet->{subnet})}) {
    #    if ($subnet->{incl} eq 'include') { print "[".color('blue').$subnet->{rule}.color('reset')."]"; }
    #    if ($subnet->{incl} eq 'exclude') { print "[".color('red')."!".$subnet->{rule}.color('reset')."]"; }
    #  }
    #  print "\n";
    #}
  }
  
  @{$sortedlist} = netipv4keysort { $_->{subnet} } @{$global_dst_subnets};
  #@{$ipdstsubnets} = grep {! $seen2{$_->{subnet}}++ } @{$sortedlist};
  #foreach $subnet (@{$ipdstsubnets}) {
  foreach $subnet (@{$sortedlist}) {
    # Global Dst Trie used for rule lookup
    if (!defined $fw->{policy}{$prm_fwpolicy}{dsttrie}->match_string($subnet->{subnet})) {
      $fw->{policy}{$prm_fwpolicy}{dsttrie}->add_string($subnet->{subnet}, [{ rule => $subnet->{rule}, subnet => $subnet->{subnet}, incl => $subnet->{incl} }]);
    } else {
      $rules=[];
      push @{$rules},@{$fw->{policy}{$prm_fwpolicy}{dsttrie}->match_string($subnet->{subnet})};
      push @{$rules},({ rule => $subnet->{rule}, subnet => $subnet->{subnet}, incl => $subnet->{incl} });
      $fw->{policy}{$prm_fwpolicy}{dsttrie}->add_string($subnet->{subnet}, $rules);
    }
    #if ($prm_verbose) {
    #  print "Subnet: ".$subnet->{subnet}."\n"; 
    #  foreach my $subnet (@{$fw->{policy}{$prm_fwpolicy}{dsttrie}->match_string($subnet->{subnet})}) {
    #    if ($subnet->{incl} eq 'include') { print "[".color('blue').$subnet->{rule}.color('reset')."]"; }
    #    if ($subnet->{incl} eq 'exclude') { print "[".color('red')."!".$subnet->{rule}.color('reset')."]"; }
    #  }
    #  print "\n";
    #}
  }
}

sub resolver_recursive_srv($) {
  my $ref = shift;
  my $srv = shift;
  my $srvgroupstack = shift;
  my $stack = [];
  my $range = [];
  #if (defined $fw->{service}{group}{$srv}) {
  push @{$stack},{ entry => $srv, counter => 0 }; 
  push @{$stack},@{$srvgroupstack}; 
  if ($srv eq 'Any') {  $ref->{serviceany} = { entry=> "Any", counter => 0 }; }
  $ref->{servicenotfound} = { entry=> "Service not found", counter => 0 };
  foreach my $srvgroupentry (@{$fw->{service}{group}{$srv}}) {
    resolver_recursive_srv($ref,$srvgroupentry,$stack);
  }
  if (defined $fw->{service}{icmp}{$srv}) {
    if (!defined $ref->{service}{icmp}{$fw->{service}{icmp}{$srv}}) { $ref->{service}{icmp}{$fw->{service}{icmp}{$srv}}=[ { entry=> "$srv", counter => 0 } ]; }
    my $srvgroups=[];
    push @{$srvgroups},@{$ref->{service}{icmp}{$fw->{service}{icmp}{$srv}}};    
    push @{$srvgroups},@{$srvgroupstack};
    $ref->{service}{icmp}{$fw->{service}{icmp}{$srv}}=$srvgroups;
    print color('green')."Register service ".$srv."=icmp/".$fw->{service}{icmp}{$srv}." ";
    foreach my $srventry (@{$srvgroups}) {
      print "[".$srventry->{entry}."]";    
    }
    print color('reset')."\n";
  } elsif (defined $fw->{service}{tcp}{$srv}) {
    if (!defined $ref->{service}{tcp}{$fw->{service}{tcp}{$srv}}) { $ref->{service}{tcp}{$fw->{service}{tcp}{$srv}}=[ { entry=> "$srv", counter => 0 } ]; }
    my $srvgroups=[];
    push @{$srvgroups},@{$ref->{service}{tcp}{$fw->{service}{tcp}{$srv}}};    
    push @{$srvgroups},@{$srvgroupstack};
    $ref->{service}{tcp}{$fw->{service}{tcp}{$srv}}=$srvgroups;
    print color('green')."Register service ".$srv."=tcp/".$fw->{service}{tcp}{$srv}." ";
    if ($fw->{service}{tcp}{$srv} =~ /\d+-\d+/) {
      print color("magenta"). $fw->{service}{tcp}{$srv}." is een range ".color("reset")."\n";
      if (!defined $ref->{servicerange}{tcp}{range}{$fw->{service}{tcp}{$srv}}) { $ref->{servicerange}{tcp}{range}{$fw->{service}{tcp}{$srv}}=[ { entry => "$srv", counter => 0 } ]; }
      my $srvgroups=[];
      push @{$srvgroups},@{$ref->{servicerange}{tcp}{range}{$fw->{service}{tcp}{$srv}}};    
      push @{$srvgroups},@{$srvgroupstack};
      $ref->{servicerange}{tcp}{range}{$fw->{service}{tcp}{$srv}}=$srvgroups;   
    }
    foreach my $srventry (@{$srvgroups}) {
      print "[".$srventry->{entry}."]";    
    }
    print color('reset')."\n";
  } elsif (defined $fw->{service}{udp}{$srv}) {
    if (!defined $ref->{service}{udp}{$fw->{service}{udp}{$srv}}) { $ref->{service}{udp}{$fw->{service}{udp}{$srv}}=[ { entry=> "$srv", counter => 0 } ]; }
    my $srvgroups=[];
    push @{$srvgroups},@{$ref->{service}{udp}{$fw->{service}{udp}{$srv}}};    
    push @{$srvgroups},@{$srvgroupstack};
    $ref->{service}{udp}{$fw->{service}{udp}{$srv}}=$srvgroups;    
    print color('green')."Register service ".$srv."=udp/".$fw->{service}{udp}{$srv}." ";
    if ($fw->{service}{udp}{$srv} =~ /\d+-\d+/) {
      print color("magenta"). $fw->{service}{udp}{$srv}." is een range ".color("reset")."\n";
      if (!defined $ref->{servicerange}{udp}{range}{$fw->{service}{udp}{$srv}}) { $ref->{servicerange}{udp}{range}{$fw->{service}{udp}{$srv}}=[ { entry => "$srv", counter => 0 } ]; }
      my $srvgroups=[];
      push @{$srvgroups},@{$ref->{servicerange}{udp}{range}{$fw->{service}{udp}{$srv}}};    
      push @{$srvgroups},@{$srvgroupstack};
      $ref->{servicerange}{udp}{range}{$fw->{service}{udp}{$srv}}=$srvgroups;   
    }
    foreach my $srventry (@{$srvgroups}) {
      print "[".$srventry->{entry}."]";    
    }
    print color('reset')."\n";
  } elsif (!defined $fw->{service}{group}{$srv}){
    print color('red')."Rule processing service ".$srv." not found".color('reset')."\n";  
  }
}

sub resolve_recursive_entries($) {
  my $rule_subnets=shift;
  my $global_subnets=shift;
  my $ref=shift;
  my $entries=shift;
  my $incl=shift;
  foreach my $entry (@{$entries}) {
    # $incl is always set on 'include' on top, the ! sets the $incl to 'exclude' and propogates recursive
    if ($entry =~ s/!(.*)/$1/) {
       $incl='exclude';
    }
    if ($incl eq 'include') { print "[".color('blue').$entry.color('reset')."]"; }
    if ($incl eq 'exclude') { print "[".color('red')."!".$entry.color('reset')."]"; }
    if ($entry eq 'Any') {
       push @{$global_subnets},{  'entry' => "Any",
                                  'subnet' => "0.0.0.0/0",
                                  'rule' => $rule_counter,
                                  'incl' => "$incl" };
       push @{$rule_subnets},{    'entry' => "Any",
                                  'subnet' => "0.0.0.0/0",
                                  'rule' => $rule_counter,
                                  'incl' => "$incl" };
       $ref->{"Any"} = { entry => $entry, counter => 0 };
    }
    if (defined $fw->{host}{$entry}) {
       push @{$global_subnets},{  'entry' => $entry,
                                  'subnet' => $fw->{host}{$entry},
                                  'rule' => $rule_counter,
                                  'incl' => "$incl" };
       push @{$rule_subnets},{    'entry' => $entry,
                                  'subnet' => $fw->{host}{$entry},
                                  'rule' => $rule_counter,
                                  'incl' => "$incl" };
       $ref->{$entry} = { entry => $entry, counter => 0 };
    }
    if (defined $fw->{net}{$entry}) {
       push @{$global_subnets},{  'entry' => $entry,
                                  'subnet' => $fw->{net}{$entry},
                                  'rule' => $rule_counter,
                                  'incl' => "$incl" };
       push @{$rule_subnets},{    'entry' => $entry,
                                  'subnet' => $fw->{net}{$entry},
                                  'rule' => $rule_counter,
                                  'incl' => "$incl" };
       $ref->{$entry} = { entry => $entry, counter => 0 };
    }
    if (defined $fw->{exclgrp}{$entry}) {
      if ($incl eq 'include') {
        if ($fw->{exclgrp}{$entry}{include} eq 'Any') {
          resolve_recursive_entries($global_subnets,$rule_subnets,$ref,[ "Any" ],'include');
        } else {
          resolve_recursive_entries($global_subnets,$rule_subnets,$ref,$fw->{group}{$fw->{exclgrp}{$entry}{include}}{group},'include');
        }
        resolve_recursive_entries($global_subnets,$rule_subnets,$ref,$fw->{group}{$fw->{exclgrp}{$entry}{exclude}}{group},'exclude');
      }
      if ($incl eq 'exclude') {
        resolve_recursive_entries($global_subnets,$rule_subnets,$ref,$fw->{group}{$fw->{exclgrp}{$entry}{include}}{group},'exclude');
        resolve_recursive_entries($global_subnets,$rule_subnets,$ref,$fw->{group}{$fw->{exclgrp}{$entry}{exclude}}{group},'include');
      }
    }
    if (defined $fw->{group}{$entry}) {
      resolve_recursive_entries($global_subnets,$rule_subnets,$ref,$fw->{group}{$entry}{group},$incl);
    }
  }
  print "\n";
}

sub process_file_rulebase_header() {
  $rulebase_header = $entry[1];
  $rule_counter = 0;
  print color('yellow')."Rulebase Header = ".$entry[1]."\n".color('reset');
  $fw->{policy}{$rulebase_header}{srctrie}=new Net::Patricia || die "Could not create a trie ($!)\n";
  $fw->{policy}{$rulebase_header}{dsttrie}=new Net::Patricia || die "Could not create a trie ($!)\n";
  $fw->{policy}{$rulebase_header}{srctrie}->add_string("0.0.0.0/0",[]);
  $fw->{policy}{$rulebase_header}{dsttrie}->add_string("0.0.0.0/0",[]);
}

sub process_file_section_header() {
  $section_header = $entry[1];
  print color('purple')."Rulebase Header = ".$entry[1]."\n".color('reset');
}

sub open_fwlogdir() {
  if ($prm_verbose) {
    print color('green')."Opening $prm_fwlogdir\n".color('reset');
  }
  opendir (FWLOGDIR, $prm_fwlogdir) or die "Can't open $prm_fwlogdir";
}

sub close_fwlogdir() {
  if ($prm_verbose) {
    print color('green')."Closing $prm_fwlogdir\n".color('reset');
  }
  closedir (FWLOGDIR) or die "Can't close $prm_fwlogdir";
}

sub open_fwlogfile($) {
  my $fwlogfile=shift;
  if ($prm_counter) {
    print "\n";
  }
  if ($prm_verbose || $prm_counter) {
    print color('green')."Opening $fwlogfile\n".color('reset');
  }
  open (FWLOGFILE, "< $fwlogfile") or die "Can't open $fwlogfile";
}

sub close_fwlogfile() {
  if ($prm_verbose) {
    print color('green')."Close logfile\n".color('reset');
  }
  close (FWLOGFILE);
}

sub read_fwlogfile_header() {
  $_=<FWLOGFILE>;
  chomp;                  # no newline
  s/#.*//;                # no comments
  s/^\s+//;               # no leading white
  s/\s+$//;               # no trailing white
  next unless length;     # anything left?
  @entry=split(/\s*;\s*/, $_);
  chomp(@entry);
  my $i=0;
  foreach my $field (@entry) {
    $logheader->{byfield}{$field}=$i;
    $logheader->{bynumber}{$i}=$field;
    !$prm_verbose || print "[".$field."]";
    $i++;
  }
  print "\n";
}

sub read_fwlogfile_entries() {
  my $matched;
  if ($prm_verbose) {
    print color('green')."Reading file entry's\n".color('reset');
  }
  while (<FWLOGFILE>) {
    chomp;                  # no newline
    s/#.*//;                # no comments
    s/^\s+//;               # no leading white
    s/\s+$//;               # no trailing white
    next unless length;     # anything left?
    @entry=split(/\s*;\s*/, $_);
    chomp(@entry);
    my $i=0;
    $logentry={};
    foreach my $field (@entry) {
      $logentry->{$logheader->{bynumber}{$i}}="";
      $logentry->{$logheader->{bynumber}{$i}}=$field;
      $i++;
    }
    if ($prm_verbose) {
      print "Num=".$logentry->{num}.",SRC=".$logentry->{src}.",DST=".$logentry->{dst}.",Proto=".$logentry->{proto}.",Service=".$logentry->{service};
      print ",Action=".$logentry->{action}.",Firewall=".$logentry->{orig}.",Rule=".$logentry->{rule}."\n";
    }

    # Running hit counter
    $log_counter++;
    $prm_counter && print "\r".$rulehit_counter."/".$log_filtered_counter."/".$log_counter;

    next unless ($prm_fwpolicy eq $fw->{firewall}{$logentry->{orig}});
    !$prm_verbose || print "log entry is from $prm_fwpolicy firewall\n";
    $log_filtered_counter++;
    $rules_matched=[];
    
    if ($logentry->{src} =~ /(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})/ &&
        $logentry->{dst} =~ /(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})/ ) {
      lookup_firewall_rules($logentry,$rules_matched);
    }
    if (@{$rules_matched} > 0) {
      $matched=0;
      while ((!$matched) && @{$rules_matched} > 0) {
        $matched=match_firewall_rule($logentry,$rules_matched);
        $prm_verbose && print "Evalueer volgende regel\n";
      }
    }
    !$prm_verbose || print "\n";
  }
}

sub lookup_firewall_rules($) {
  my $logentry = shift;
  my $rules_matched = shift;
  my $srcsect={};
  my $dstsect={};
  my $e;
  my @matched=();
  if ($prm_verbose) {
    #!$prm_verbose || print "srcip=".$logentry->{src}." ";
    #if (defined $fw->{policy}{$prm_fwpolicy}{srctrie}->match_string($logentry->{src})) {
      #!$prm_verbose || print "srcrule=";
      #foreach my $srcrule (@{$fw->{policy}{$prm_fwpolicy}{srctrie}->match_string($logentry->{src})}) {
      #  print "[".$srcrule->{rule}."]";
      #  if ($srcrule->{incl} eq 'include') { 
      #    !$prm_verbose || print "[".color('blue').$srcrule->{rule}.color('reset')."]";
      #  } elsif ($srcrule->{incl} eq 'exclude') { 
      #    !$prm_verbose || print "[".color('red').$srcrule->{rule}.color('reset')."]";
      #  } else {
      #    !$prm_verbose || print "[".color('white').$srcrule->{rule}.color('reset')."]";
      #  }
      #}
      #!$prm_verbose || print "\n";
    #}
    #!$prm_verbose || print "dstip=".$logentry->{dst}." ";
    #if (defined $fw->{policy}{$prm_fwpolicy}{dsttrie}->match_string($logentry->{dst})) {
      #!$prm_verbose || print "dstrule=";
      #foreach my $dstrule (@{$fw->{policy}{$prm_fwpolicy}{dsttrie}->match_string($logentry->{dst})}) {
      #  print "[".$dstrule->{rule}."]";
      #  if ($dstrule->{incl} eq 'include') { 
      #    !$prm_verbose || print "[".color('blue').$dstrule->{rule}.color('reset')."]";
      #  } elsif ($dstrule->{incl} eq 'exclude') { 
      #    !$prm_verbose || print "[".color('red').$dstrule->{rule}.color('reset')."]";
      #  } else {
      #    !$prm_verbose || print "[".color('white').$dstrule->{rule}.color('reset')."]";
      #  }
      #}
      #!$prm_verbose || print "\n";
    #}
    !$prm_verbose || print "Matching Rules:";
  }
  foreach $e (@{$fw->{policy}{$prm_fwpolicy}{srctrie}->match_string($logentry->{src})} ) { 
    if ($e->{incl} eq 'include') { $srcsect->{$e->{rule}}=1; }
    if ($e->{incl} eq 'exclude') { $srcsect->{$e->{rule}}=0; }
  }
  foreach $e (@{$fw->{policy}{$prm_fwpolicy}{dsttrie}->match_string($logentry->{dst})} ) { 
    if ($e->{incl} eq 'include') { $dstsect->{$e->{rule}}=1; }
    if ($e->{incl} eq 'exclude') { $dstsect->{$e->{rule}}=0; }
  }
  #foreach $e (@{$fw->{policy}{$prm_fwpolicy}{dsttrie}->match_string($logentry->{dst})}) { 
  #  if ($e->{incl} eq 'exclude' || $logentry->{dst} ne "0.0.0.0/0" ) { $isect->{$e->{rule}}=0; }
  #}
  foreach $e (keys %{$srcsect}) { 
    if ($srcsect->{$e} == 1 && defined $dstsect->{$e} && $dstsect->{$e}== 1 ) { push @matched, $e; }
  }
  foreach $e (sort { $a <=> $b } @matched) { 
    push @{$rules_matched}, $e ;
    !$prm_verbose || print "[".color('cyan').$e.color('reset')."]";
  }
  !$prm_verbose || print "\n";
}

sub match_firewall_rule($) {
  my $logentry = shift;
  my $rules_matched = shift;
  my $rule = shift(@{$rules_matched});
  my $startsrv;
  my $endsrv;
  my $rref;
  my $source_matched=0;
  my $source_entry_matched;
  my $destination_matched=0;
  my $destination_entry_matched;
  my $service_matched=0;
  my $service_entry_matched=0;


  # Ignore disabled rules
  if ($fw->{policy}{$prm_fwpolicy}{rules}[$rule]{rule_disabled} == 1) { 
    ($prm_verbose || $prm_logrule eq $rule ) &&  print color('red')."This rule is disabled".color('reset')."\n";
    return 0; 
  }
 
  $source_matched =      (@{$fw->{policy}{$prm_fwpolicy}{rules}[$rule]{srctrie}->match_string($logentry->{src})}>0) ? 1 : 0;
  $destination_matched = (@{$fw->{policy}{$prm_fwpolicy}{rules}[$rule]{dsttrie}->match_string($logentry->{dst})}>0) ? 1 : 0;

  # First start with service matching

  if (!defined $fw->{policy}{$prm_fwpolicy}{rules}[$rule]{srcsubnets}) {
	$fw->{policy}{$prm_fwpolicy}{rules}[$rule]{srcsubnets}={};
        }
  if (!defined $fw->{policy}{$prm_fwpolicy}{rules}[$rule]{dstsubnets}) {
	$fw->{policy}{$prm_fwpolicy}{rules}[$rule]{dstsubnets}={};
        }


  # Matched Any Service ?
  if (defined $fw->{policy}{$prm_fwpolicy}{rules}[$rule]{serviceany}) {
    $service_matched = 1;
    $fw->{policy}{$prm_fwpolicy}{rules}[$rule]{serviceany}->{counter}++;
      # this should never exit 1; 
      if (defined $fw->{policy}{$prm_fwpolicy}{rules}[$rule]{serviceany}->{rulenr} 
          && $fw->{policy}{$prm_fwpolicy}{rules}[$rule]{serviceany}->{rulenr}!=$rule) {
        ($prm_verbose || $prm_logrule eq $rule ) && print color('cyan')."Matched firewall rule ".$rule.color('reset')."\n";
        print "ERROR refcounter Rule .\n";
        exit 1;
      } else {
        $fw->{policy}{$prm_fwpolicy}{rules}[$rule]{serviceany}->{rulenr}=$rule;
      }

  } elsif (defined $fw->{service}{$logentry->{proto}}) {
    # Matched ICMP?
    if ($logentry->{proto} eq 'icmp') {
      if (defined $fw->{policy}{$prm_fwpolicy}{rules}[$rule]{service}{icmp}{$logentry->{"ICMP Type"}}) {
        ($prm_verbose || $prm_logrule eq $rule ) && print color('cyan')."Matched firewall rule ".$rule." Service ICMP ";
        foreach my $service (@{$fw->{policy}{$prm_fwpolicy}{rules}[$rule]{service}{icmp}{$logentry->{"ICMP Type"}}}) {
          $service_matched = 1;
          $service->{counter}++;
          !$prm_verbose || print "in srvgroup ".$service->{entry}." ";  
          # this should never exit 1; 
          if (defined $service->{rulenr} && $service->{rulenr}!=$rule) {
            print "ERROR refcounter Rule .\n";
            exit 1;
          } else {
            $service->{rulenr}=$rule;
          }   
        }
        ($prm_verbose || $prm_logrule eq $rule ) && print color('reset')."\n";
      } else {
        ($prm_verbose || $prm_logrule eq $rule ) && print color('white')."Service ". $fw->{service}{$logentry->{proto}}." is not in firewall rule ".$rule.color('reset')."\n";
      }

    # Matched a service ?
    } elsif (defined $fw->{policy}{$prm_fwpolicy}{rules}[$rule]{service}{$logentry->{proto}}{$fw->{service}{$logentry->{proto}}{$logentry->{service}}}) {
      ($prm_verbose ||  $prm_logrule eq $rule ) && print color('cyan')."Service ".$logentry->{proto}."/".$logentry->{service}." ";
      foreach my $service (@{$fw->{policy}{$prm_fwpolicy}{rules}[$rule]{service}{$logentry->{proto}}{$fw->{service}{$logentry->{proto}}{$logentry->{service}}}}) {
        # Met die Array gaat hier nog een fout zitten, die tellers van de inherenteerde groepen worden niet voor de entries in elke rule gecombineerd tot gezamelijke tellers
        # dwz voor iedere service wordt individuele srvgroepen geteld, dit moet nog verbeterd worden.
        $service_matched = 1;
        $service->{counter}++;
        ($prm_verbose || $prm_logrule eq $rule ) && print "in srvgroup ".$service->{entry}." ";  
        # this should never exit 1; 
        if (defined $service->{rulenr} && $service->{rulenr}!=$rule) {
          print "ERROR refcounter Rule .\n";
          exit 1;
        } else {
          $service->{rulenr}=$rule;
        }   
      }
      ($prm_verbose || $prm_logrule eq $rule ) && print color('cyan')."is defined in firewall rule ".$rule.color('reset')."\n";
      $service_matched = 1;

    # Matched a service range ?
    } elsif (defined $fw->{policy}{$prm_fwpolicy}{rules}[$rule]{servicerange}{$logentry->{proto}}{range}) {
      foreach my $range (keys %{$fw->{policy}{$prm_fwpolicy}{rules}[$rule]{servicerange}{$logentry->{proto}}{range}}) {
        ($startsrv,$endsrv)=split('-',$range);
        if (($startsrv <= $logentry->{service}) && ($logentry->{service} <= $endsrv)) {
            ($prm_verbose || $prm_logrule eq $rule ) && print color('cyan')."Range ".$logentry->{proto}."/".$range." is defined in firewall rule ".$rule.color('reset')."\n";
            foreach my $srv ( @{$fw->{policy}{$prm_fwpolicy}{rules}[$rule]{servicerange}{$logentry->{proto}}{range}{$range}} ) {
              $srv->{counter}++;
              ($prm_verbose || $prm_logrule eq $rule ) &&  print color('cyan')."srvgroup = ".$srv->{entry}.color('reset')."\n";
              if (defined $srv->{rulenr} && $srv->{rulenr}!=$rule) {
                print "ERROR refcounter Rule .\n";
                exit 1;
              } else {
                $srv->{rulenr}=$rule;
              }   
            }
            $service_matched = 1;
        }
      }
      if ($prm_verbose || $prm_logrule eq $rule ) { 
              print color('white')."Service ".$logentry->{service}." is not in firewall rule ".$rule.color('reset')."\n";
              #print Dumper ( $fw->{policy}{$prm_fwpolicy}{rules}[$rule]{service}{$logentry->{proto}})."\n";
              #print Dumper ( $fw->{service}{$logentry->{proto}}{$logentry->{service}})."\n";
              }
    } else {
      if ($prm_verbose || $prm_logrule eq $rule ) { 
	      print color('white')."Service ".$logentry->{service}." is not in firewall rule ".$rule.color('reset')."\n";
              #print Dumper ( $fw->{policy}{$prm_fwpolicy}{rules}[$rule]{service}{$logentry->{proto}})."\n";
              #print Dumper ( $fw->{service}{$logentry->{proto}}{$logentry->{service}})."\n";
            }
    }
  }

  # Not found service
  if ($prm_nonmatching && $source_matched && $destination_matched && !$service_matched && ($logentry->{rule} == $rule) && ($rule != $#{$fw->{policy}{$prm_fwpolicy}{rules}})) {
      $fw->{policy}{$prm_fwpolicy}{rules}[$rule]{servicenotfound}->{counter}++;
      print "Num=".$logentry->{num}.",SRC=".$logentry->{src}.",DST=".$logentry->{dst}.",Proto=".$logentry->{proto}.",Service=".$logentry->{service};
      print ",Action=".$logentry->{action}.",Firewall=".$logentry->{orig}.",Rule=".$logentry->{rule}."\n";
  }
    

  if ($source_matched && $destination_matched && ( $service_matched || ($rule == $#{$fw->{policy}{$prm_fwpolicy}{rules}}))) {

    $rulehit_counter++;

    if (!$prm_nosubnettrie) {
      check_subnettrie($fw->{policy}{$prm_fwpolicy}{rules}[$rule]{srcsubnets},$logentry->{src},0);
      #foreach my $subnet (keys %{$fw->{policy}{$prm_fwpolicy}{rules}[$rule]{srcsubnets}{subnets}}) {
      #  print "Subnet:".$subnet." Counter=".$fw->{policy}{$prm_fwpolicy}{rules}[$rule]{srcsubnets}{subnets}{$subnet}{counter}."\n";
      #}
      check_subnettrie($fw->{policy}{$prm_fwpolicy}{rules}[$rule]{dstsubnets},$logentry->{dst},0);
      #foreach my $subnet (keys %{$fw->{policy}{$prm_fwpolicy}{rules}[$rule]{dstsubnets}{subnets}}) {
      #  print "Subnet:".$subnet." Counter=".$fw->{policy}{$prm_fwpolicy}{rules}[$rule]{dstsubnets}{subnets}{$subnet}{counter}."\n";
      #}
    }

    # match the source entries ( we should find entries, because of the previous Global patricia match )
    foreach my $src (@{$fw->{policy}{$prm_fwpolicy}{rules}[$rule]{srctrie}->match_string($logentry->{src})}) {
      # Count Source IP not Any
      if ($src->{entry} ne 'Any') { 
        $src->{refcounter}->{counter}++;
          # this should never exit 1; 
          if (defined $src->{refcounter}->{rulenr} && $src->{refcounter}->{rulenr}!=$rule) {
            print "ERROR refcounter Rule .\n";
            exit 1;
          } else {
            $src->{refcounter}->{rulenr}=$rule;
          }
      }
      ($prm_verbose || $prm_logrule eq $rule ) && print color('yellow')."Matched src entry =". $src->{entry}.color('reset')."\n";
    }

    # match the destination entries ( we should find entries, because of the previous Global patricia match )
    foreach my $dst (@{$fw->{policy}{$prm_fwpolicy}{rules}[$rule]{dsttrie}->match_string($logentry->{dst})}) {
      # Count Destination IP not Any
      if ($dst->{entry} ne 'Any') { 
        $dst->{refcounter}->{counter}++;
          # this should never exit 1; 
          if (defined $dst->{refcounter}->{rulenr} && $dst->{refcounter}->{rulenr}!=$rule) {
            print "ERROR refcounter Rule .\n";
            exit 1;
          } else {
            $dst->{refcounter}->{rulenr}=$rule;
          }
      }
      ($prm_verbose || $prm_logrule eq $rule ) && print color('yellow')."Matched dst entry =". $dst->{entry}.color('reset')."\n";
    }
    # Matched 
    return 1;
  }
  # No Match
  return 0;
}

sub check_subnettrie($) {
  my $ref=shift;
  my $ip=shift;
  my $subnetindex=shift;
  my $subnet;
  my $rref;

  $subnet=NetAddr::IP->new($ip,$subnetindex) || die "Could not create NetAddr::IP\n";
  if (!defined $ref->{subnettrie} || !defined $ref->{subnettrie}->match_string($ip)) {
    $ref->{subnettrie}=new Net::Patricia || die "Could not create a trie ($!)\n";
    $ref->{subnettrie}->add_string($subnet->network(), {});
  }
  #print "ip:".$ip."\n";
  my $subnets={};
  $rref=$ref->{subnettrie}->match_string($ip);
  #print "Match_string: ".$rref->{addstring}."\n";
  foreach my $subnet (keys %{$rref->{subnets}}) {
    $subnets->{subnets}{$subnet}=$ref->{subnets}{$subnet};
    #print "Match_string: ".$subnet." subnetinc = ".$subnets->{subnets}{$subnet}{counter}.", rrefinc = ".$ref->{subnets}{$subnet}{counter}."\n"; 
  } 
  $subnet=NetAddr::IP->new($ip,$subnetindex) || die "Could not create NetAddr::IP\n";
  if (!defined $ref->{subnets}{$subnet->network()}) { 
    $ref->{subnets}{$subnet->network()}{counter}=0;
    $subnets->{subnets}{$subnet->network()}={$ref->{subnets}{$subnet->network()}};
    #print "+Subnet:".$subnet->network()."\n";
    $subnets->{addstring}=$subnet->network();
    $ref->{subnettrie}->add_string($subnet->network(), $subnets);
  } else {
    #print "Subnet ".$subnet->network() ." already defined\n";
    $subnets->{subnets}{$subnet->network()}={$ref->{subnets}{$subnet->network()}};
    $subnets->{addstring}=$subnet->network();
  }
  #print Dumper($subnets)."\n"; 
  
  if ($subnetindex == 32) {
    $rref=$ref->{subnettrie}->match_string($ip);
    foreach my $subnet (keys %{$rref->{subnets}}) {
      $ref->{subnets}{$subnet}{counter}++;
      #print "Subnet: ".$subnet." subnetinc increaded to ".$ref->{subnets}{$subnet}{counter}."\n"; 
    }
  } else {
    if ($subnetindex < 28) {
      $subnetindex += $prm_subnettrie_modulo; 
    } else {
      $subnetindex += 2; 
    }
    check_subnettrie($ref,$ip,$subnetindex);
  }
}

sub write_dbreport() {

  foreach my $rule ( 1 .. $#{$fw->{policy}{$prm_fwpolicy}{rules}} ) {

    print "\rWrite fwdata file rule ".$rule."/".$#{$fw->{policy}{$prm_fwpolicy}{rules}};
    if (!defined $dbout->{policy}{$prm_fwpolicy}{rules}[$rule]{srcrule}) {
      $dbout->{policy}{$prm_fwpolicy}{rules}[$rule]{srcrule} = $fw->{policy}{$prm_fwpolicy}{rules}[$rule]{srcrule};
    } elsif ($dbout->{policy}{$prm_fwpolicy}{rules}[$rule]{srcrule} != $fw->{policy}{$prm_fwpolicy}{rules}[$rule]{srcrule}) {
      print "DB Error: firewall rules different! source Rule ".$rule."\n";
    }

    foreach my $src (keys %{$fw->{policy}{$prm_fwpolicy}{rules}[$rule]{src}}) {
      if (!defined $dbout->{policy}{$prm_fwpolicy}{rules}[$rule]{src}{$src}->{counter}) {
        $dbout->{policy}{$prm_fwpolicy}{rules}[$rule]{src}{$src}->{counter}=$fw->{policy}{$prm_fwpolicy}{rules}[$rule]{src}{$src}->{counter};
      } else { 
        $dbout->{policy}{$prm_fwpolicy}{rules}[$rule]{src}{$src}->{counter}=+$fw->{policy}{$prm_fwpolicy}{rules}[$rule]{src}{$src}->{counter};
      }
    }

    if (!defined $dbout->{policy}{$prm_fwpolicy}{rules}[$rule]{dstrule}) {
      $dbout->{policy}{$prm_fwpolicy}{rules}[$rule]{dstrule} = $fw->{policy}{$prm_fwpolicy}{rules}[$rule]{dstrule};
    } elsif ($dbout->{policy}{$prm_fwpolicy}{rules}[$rule]{dstrule} != $fw->{policy}{$prm_fwpolicy}{rules}[$rule]{dstrule}) {
      print "DB Error: firewall rules different! destination Rule ".$rule."\n";
    }

    foreach my $dst (keys %{$fw->{policy}{$prm_fwpolicy}{rules}[$rule]{dst}}) {
      if (!defined $dbout->{policy}{$prm_fwpolicy}{rules}[$rule]{dst}{$dst}->{counter}) {
        $dbout->{policy}{$prm_fwpolicy}{rules}[$rule]{dst}{$dst}->{counter}=$fw->{policy}{$prm_fwpolicy}{rules}[$rule]{dst}{$dst}->{counter};
      } else { 
        $dbout->{policy}{$prm_fwpolicy}{rules}[$rule]{dst}{$dst}->{counter}=+$fw->{policy}{$prm_fwpolicy}{rules}[$rule]{dst}{$dst}->{counter};
      }
    }

    if (defined $fw->{policy}{$prm_fwpolicy}{rules}[$rule]{serviceany} && !defined $dbout->{policy}{$prm_fwpolicy}{rules}[$rule]{serviceany}) {
      %{$dbout->{policy}{$prm_fwpolicy}{rules}[$rule]{serviceany}} = %{$fw->{policy}{$prm_fwpolicy}{rules}[$rule]{serviceany}};
    } elsif (!defined $dbout->{policy}{$prm_fwpolicy}{rules}[$rule]{servicerule}) {
      $dbout->{policy}{$prm_fwpolicy}{rules}[$rule]{servicerule} = $fw->{policy}{$prm_fwpolicy}{rules}[$rule]{servicerule};
    } elsif ($dbout->{policy}{$prm_fwpolicy}{rules}[$rule]{servicerule} != $fw->{policy}{$prm_fwpolicy}{rules}[$rule]{servicerule}) {
      print "DB Error: firewall rules different! service Rule ".$rule."\n";
    }

    foreach my $proto ( ('tcp', 'udp') ) {
      if (defined $fw->{policy}{$prm_fwpolicy}{rules}[$rule]{servicerange}{$proto}{range}) {
        foreach my $srvrange (keys %{$fw->{policy}{$prm_fwpolicy}{rules}[$rule]{servicerange}{$proto}{range}}) {
          foreach my $srvgroup (@{$fw->{policy}{$prm_fwpolicy}{rules}[$rule]{servicerange}{$proto}{range}{$srvrange}}) {
             push @{$dbout->{policy}{$prm_fwpolicy}{rules}[$rule]{servicerange}{$proto}{range}{$srvrange}},
               [ { entry => $srvgroup->{entry}, counter => $srvgroup->{counter} } ];
          }
        }
      }
    } 

    foreach my $proto (keys %{$fw->{policy}{$prm_fwpolicy}{rules}[$rule]{service}}) {
      foreach my $service (keys %{$fw->{policy}{$prm_fwpolicy}{rules}[$rule]{service}{$proto}}) {
        $dbout->{policy}{$prm_fwpolicy}{rules}[$rule]{service}{$proto}{$service}
          =$fw->{policy}{$prm_fwpolicy}{rules}[$rule]{service}{$proto}{$service};
        #foreach my $srvgroup ( @{$fw->{policy}{$prm_fwpolicy}{rules}[$rule]{service}{$proto}{$service}}) {
        #  push @{$dbout->{policy}{$prm_fwpolicy}{rules}[$rule]{service}{$proto}{$service}}, 
        #    [ { entry => $srvgroup->{entry}, counter => $srvgroup->{counter} } ];
        #}
      }
    }

    #foreach my $icmptype (keys %{$fw->{policy}{$prm_fwpolicy}{rules}[$rule]{service}{icmp}}) {
    #  foreach my $srvgroup ( @{$fw->{policy}{$prm_fwpolicy}{rules}[$rule]{service}{icmp}{$icmptype}}) {
    #    foreach my $dbsrvgroup ( @{$dbout->{policy}{$prm_fwpolicy}{rules}[$rule]{service}{icmp}{$icmptype}}) {
    #      if (($srvgroup->{entry} eq $dbsrvgroup->{entry})) {
    #        $dbsrvgroup->{counter}=+$srvgroup->{counter};
    #      }
    #    }
    #  }
    #}
    
  }
  $dbout->export($dbout);
}

sub read_dbreport() {

  foreach my $rule ( 1 .. $#{$db->{policy}{$prm_fwpolicy}{rules}} ) {

    print "\rRead fwdata file rule ".$rule."/".$#{$db->{policy}{$prm_fwpolicy}{rules}};

    if (defined $db->{policy}{$prm_fwpolicy}{rules}[$rule]{srcrule}) {
      if (defined $fw->{policy}{$prm_fwpolicy}{rules}[$rule]{srcrule}) {
        $fw->{policy}{$prm_fwpolicy}{rules}[$rule]{srcrule} = $db->{policy}{$prm_fwpolicy}{rules}[$rule]{srcrule};
        $prm_verbose && print "srcrule:".Dumper($fw->{policy}{$prm_fwpolicy}{rules}[$rule]{srcrule});
      } else {
        print "DB read Error: firewall rules different! srcrule Rule ".$rule."\n";
      }
    }

    foreach my $src (keys %{$db->{policy}{$prm_fwpolicy}{rules}[$rule]{src}}) {
      if (defined $db->{policy}{$prm_fwpolicy}{rules}[$rule]{src}{$src}->{counter}) {
        if (defined $fw->{policy}{$prm_fwpolicy}{rules}[$rule]{src}{$src}->{counter}) {
          $fw->{policy}{$prm_fwpolicy}{rules}[$rule]{src}{$src}->{counter}=$db->{policy}{$prm_fwpolicy}{rules}[$rule]{src}{$src}->{counter};
          $prm_verbose && print "src:".Dumper($fw->{policy}{$prm_fwpolicy}{rules}[$rule]{src}{$src}->{counter});
        } else {
          print "DB read Error: firewall rules different! src Rule ".$rule."\n";
        } 
      }
    }

    if (defined $db->{policy}{$prm_fwpolicy}{rules}[$rule]{dstrule}) {
      if (defined $fw->{policy}{$prm_fwpolicy}{rules}[$rule]{dstrule}) {
        $fw->{policy}{$prm_fwpolicy}{rules}[$rule]{dstrule} = $db->{policy}{$prm_fwpolicy}{rules}[$rule]{dstrule};
        $prm_verbose && print "dstrule:".Dumper($fw->{policy}{$prm_fwpolicy}{rules}[$rule]{dstrule});
      } else {
        print "DB read Error: firewall rules different! dstrule Rule ".$rule."\n";
      }
    }

    foreach my $dst (keys %{$db->{policy}{$prm_fwpolicy}{rules}[$rule]{dst}}) {
      if (defined $db->{policy}{$prm_fwpolicy}{rules}[$rule]{dst}{$dst}->{counter}) {
        if (defined $fw->{policy}{$prm_fwpolicy}{rules}[$rule]{dst}{$dst}->{counter}) {
          $fw->{policy}{$prm_fwpolicy}{rules}[$rule]{dst}{$dst}->{counter}=$db->{policy}{$prm_fwpolicy}{rules}[$rule]{dst}{$dst}->{counter};
          $prm_verbose && print "dst:".Dumper($fw->{policy}{$prm_fwpolicy}{rules}[$rule]{dst}{$dst}->{counter});
        } else {
          print "DB read Error: firewall rules different! dst Rule ".$rule."\n";
        }
      }
    }

    if (defined $db->{policy}{$prm_fwpolicy}{rules}[$rule]{serviceany}) {
      if (defined $fw->{policy}{$prm_fwpolicy}{rules}[$rule]{serviceany}) {
        $fw->{policy}{$prm_fwpolicy}{rules}[$rule]{serviceany}->{counter} = $db->{policy}{$prm_fwpolicy}{rules}[$rule]{serviceany}->{counter};
      } else {
        print "DB read Error: firewall rules different! serviceany Rule ".$rule."\n";
      }
      $prm_verbose && print "serviceany:".Dumper($fw->{policy}{$prm_fwpolicy}{rules}[$rule]{serviceany});
    } elsif (defined $db->{policy}{$prm_fwpolicy}{rules}[$rule]{servicerule}) {
      if (defined $fw->{policy}{$prm_fwpolicy}{rules}[$rule]{servicerule}) {
        $fw->{policy}{$prm_fwpolicy}{rules}[$rule]{servicerule} = $db->{policy}{$prm_fwpolicy}{rules}[$rule]{servicerule};
      } else {
        print "DB read Error: firewall rules different! servicerule Rule ".$rule."\n";
      }
      $prm_verbose && print "servicerule:".Dumper($fw->{policy}{$prm_fwpolicy}{rules}[$rule]{servicerule});
    }

    foreach my $proto (keys %{$db->{policy}{$prm_fwpolicy}{rules}[$rule]{service}}) {
      foreach my $service (keys %{$db->{policy}{$prm_fwpolicy}{rules}[$rule]{service}{$proto}}) {
        if (defined $fw->{policy}{$prm_fwpolicy}{rules}[$rule]{service}{$proto}{$service}) {
          foreach my $srvgroup (@{$fw->{policy}{$prm_fwpolicy}{rules}[$rule]{service}{$proto}{$service}}) {
            foreach my $dbsrvgroup (@{$db->{policy}{$prm_fwpolicy}{rules}[$rule]{service}{$proto}{$service}}) {
              $srvgroup->{counter}=$dbsrvgroup->{counter};          
              $prm_verbose && print "service :".$srvgroup->{entry}."\n";
            }
          }
        } else {
          print "DB read Error: firewall rules different! service Rule ".$rule."\n";
        } 
      }
    }
    #foreach my $icmptype (keys %{$db->{policy}{$prm_fwpolicy}{rules}[$rule]{service}{icmp}}) {
    #  foreach my $dbsrvgroup ( @{$db->{policy}{$prm_fwpolicy}{rules}[$rule]{service}{icmp}{$icmptype}}) {
    #    foreach my $srvgroup ( @{$fw->{policy}{$prm_fwpolicy}{rules}[$rule]{service}{icmp}{$icmptype}}) {
    #      if (($dbsrvgroup->{entry} eq $srvgroup->{entry})) {
    #        $srvgroup->{counter}=$dbsrvgroup->{counter};
    #        $prm_verbose && print "srvgroup:".Dumper($srvgroup->{counter});
    #      }
    #    }
    #  }
    #}
   
    foreach my $proto ( ('tcp', 'udp') ) {
      foreach my $srvrange (keys %{$db->{policy}{$prm_fwpolicy}{rules}[$rule]{servicerange}{$proto}{range}}) {
        if (defined $fw->{policy}{$prm_fwpolicy}{rules}[$rule]{servicerange}{$proto}{range}{$srvrange}) {
          foreach my $dbsrvgroup (@{$db->{policy}{$prm_fwpolicy}{rules}[$rule]{servicerange}{$proto}{range}{$srvrange}}) {
            foreach my $srvgroup (@{$fw->{policy}{$prm_fwpolicy}{rules}[$rule]{servicerange}{$proto}{range}{$srvrange}}) {
              print Dumper($dbsrvgroup);
              print Dumper($srvgroup);
              if ($srvgroup->{entry} eq $dbsrvgroup->{entry}) {
		$srvgroup->{counter}=$dbsrvgroup->{counter};
              }
            }
          }
        } else {
          print "DB read Error: firewall rules different! servicerange Rule ".$rule."\n";
        }
      }
    }
  }
  print "\n";
}

sub do_fwreport() {

  my $table;
  my $row;
  my $action;
  my $source_rule="";
  my $source_result="";
  my $destination_rule="";
  my $destination_result="";
  my $service_rule="";
  my $service_result="";
  my $firewall_list="";

  $table = new HTML::Table; 
  die unless ref($table);
  $table->setBorder(1);
  $table->setCellSpacing(0);
  $table->setCellPadding(3);

  #ow, print out our header stuff into the file
  print FWREPORTFILE "<html>\n";
  print FWREPORTFILE "<head>\n";
  print FWREPORTFILE "<script type=\"text/javascript\" src=\"mktree.js\"></script>\n";
  print FWREPORTFILE "<link rel=\"stylesheet\" href=\"mktree.css\" type=\"text/css\">\n";
  print FWREPORTFILE "</head>\n";
  print FWREPORTFILE "<body bgcolor=\"\#ffffff\">\n<center>\n\n";

  print FWREPORTFILE "Matches:". $rulehit_counter."/".$log_filtered_counter."/".$log_counter."<br>\n";

  $table->setCaption("Firewall Report on ".$prm_fwlogfile,'TOP');


  $row = 1;
  $table->addRow('<b>Rule</b>',
                 '<b>Source Rule</b>',
                 '<b>Source Hits</b>',
                 '<b>Destination Rule</b>',
                 '<b>Destination Hits</b>',
                 '<b>Service Rule</b>',
                 '<b>Service Hits</b>',
                 '<b>Action</b>',
                 '<b>Firewalls</b>');

  $table->setRowBGColor($row, '#B0B0B0'); # Gray
  # Highlight the current column (out is 1 off from in)
  #$table->setCellBGColor($row, $columns{$key} + ('in' eq $direction),'#90ee90'); # light green

  foreach my $rule ( 1 .. $#{$fw->{policy}{$prm_fwpolicy}{rules}} ) {

    $row++;
    $source_rule="";
    $source_result="";
    $destination_rule="";
    $destination_result="";
    $service_rule="";
    $service_result="";
    $firewall_list="";

    #$prm_verbose && print color('yellow')."print rule ".$rule."\n";
    
    foreach my $source_rule_tuple ( split(/\s*;\s*/, $fw->{policy}{$prm_fwpolicy}{rules}[$rule]{srcrule}) ) {
      $source_rule .= $source_rule_tuple."<br>\n";
    }

    foreach my $src (sort keys %{$fw->{policy}{$prm_fwpolicy}{rules}[$rule]{src}}) {
      if ($fw->{policy}{$prm_fwpolicy}{rules}[$rule]{src}{$src}->{counter} != 0) {  
        $source_result .= $fw->{policy}{$prm_fwpolicy}{rules}[$rule]{src}{$src}->{entry}." [".$fw->{policy}{$prm_fwpolicy}{rules}[$rule]{src}{$src}->{counter}."]<br>\n";
        #$source_result .= $fw->{policy}{$prm_fwpolicy}{rules}[$rule]{src}{$src}->{entry}." [".$fw->{policy}{$prm_fwpolicy}{rules}[$rule]{src}{$src}->{counter}."]:".$fw->{policy}{$prm_fwpolicy}{rules}[$rule]{src}{$src}->{rulenr}."<br>\n";
      }
    }
    #print Dumper($fw->{policy}{$prm_fwpolicy}{rules}[$rule]{srcsubnets}{subnets})."\n";
    if (defined $fw->{policy}{$prm_fwpolicy}{rules}[$rule]{srcsubnets}{subnets}) {
      $source_result .= "<ul class=\"mktree\">";
      $source_result .= "<li>\n";
      $source_result .= "Subnets\n";
      $source_result .= "<ul>\n";
      foreach my $subnet (sort keys %{$fw->{policy}{$prm_fwpolicy}{rules}[$rule]{srcsubnets}{subnets}}) {
        #$source_result .= $subnet." [".$fw->{policy}{$prm_fwpolicy}{rules}[$rule]{srcsubnets}{subnets}{$subnet}{counter}."]<br>\n";
        $source_result .= "<li>".$subnet." [".$fw->{policy}{$prm_fwpolicy}{rules}[$rule]{srcsubnets}{subnets}{$subnet}{counter}."]</li>\n";
      }
      $source_result .= "</ul>\n";
      $source_result .= "</li>\n";
      $source_result .= "</ul>\n";
    }

    foreach my $destination_rule_tuple ( split(/\s*;\s*/, $fw->{policy}{$prm_fwpolicy}{rules}[$rule]{dstrule}) ) {
      $destination_rule .= $destination_rule_tuple."<br>\n";
    }

    foreach my $dst (sort keys %{$fw->{policy}{$prm_fwpolicy}{rules}[$rule]{dst}}) {
      if ($fw->{policy}{$prm_fwpolicy}{rules}[$rule]{dst}{$dst}->{counter} != 0) {  
        $destination_result .= $fw->{policy}{$prm_fwpolicy}{rules}[$rule]{dst}{$dst}->{entry}." [".$fw->{policy}{$prm_fwpolicy}{rules}[$rule]{dst}{$dst}->{counter}."]<br>\n";
        #$destination_result .= $fw->{policy}{$prm_fwpolicy}{rules}[$rule]{dst}{$dst}->{entry}." [".$fw->{policy}{$prm_fwpolicy}{rules}[$rule]{dst}{$dst}->{counter}."]:".$fw->{policy}{$prm_fwpolicy}{rules}[$rule]{dst}{$dst}->{rulenr}."<br>\n";
      }
    }
    #print Dumper($fw->{policy}{$prm_fwpolicy}{rules}[$rule])."\n";
    #foreach my $subnet (keys %{$fw->{policy}{$prm_fwpolicy}{rules}[$rule]{srcsubnets}{subnets}}) {
    #  print "Subnet:".$subnet." Counter=".$fw->{policy}{$prm_fwpolicy}{rules}[$rule]{srcsubnets}{subnets}{$subnet}."\n";
    #}
    if (defined $fw->{policy}{$prm_fwpolicy}{rules}[$rule]{dstsubnets}{subnets}) {
      $destination_result .= "<ul class=\"mktree\">";
      $destination_result .= "<li>\n";
      $destination_result .= "Subnets\n";
      $destination_result .= "<ul>\n";
      foreach my $subnet (sort keys %{$fw->{policy}{$prm_fwpolicy}{rules}[$rule]{dstsubnets}{subnets}}) {
        #$destination_result .= $subnet." [".$fw->{policy}{$prm_fwpolicy}{rules}[$rule]{dstsubnets}{subnets}{$subnet}{counter}."]<br>\n";
        $destination_result .= "<li>".$subnet." [".$fw->{policy}{$prm_fwpolicy}{rules}[$rule]{dstsubnets}{subnets}{$subnet}{counter}."]</li>\n";
      }
      $destination_result .= "</ul>\n";
      $destination_result .= "</li>\n";
      $destination_result .= "</ul>\n";
    }
    #foreach my $dst (keys %{$fw->{policy}{$prm_fwpolicy}{rules}[$rule]{dst}}) {
    #  $destination_tuple .= $dst."[".$fw->{policy}{$prm_fwpolicy}{rules}[$rule]{dst}{$dst}."]<br>\n";
    #}
    foreach my $service_rule_tuple ( split(/\s*;\s*/, $fw->{policy}{$prm_fwpolicy}{rules}[$rule]{servicerule}) ) {
      $service_rule .= $service_rule_tuple."<br>\n";
    }

    if (defined $fw->{policy}{$prm_fwpolicy}{rules}[$rule]{serviceany}) {
      $service_result .= "Any [".$fw->{policy}{$prm_fwpolicy}{rules}[$rule]{serviceany}->{counter}."]<br>\n";  
    }

    foreach my $proto (keys %{$fw->{policy}{$prm_fwpolicy}{rules}[$rule]{service}}) {
    
      foreach my $service (keys %{$fw->{policy}{$prm_fwpolicy}{rules}[$rule]{service}{$proto}}) {
        if (defined $fw->{policy}{$prm_fwpolicy}{rules}[$rule]{servicerange}{$proto}{$service}) {
          foreach my $srvgroup ( @{$fw->{policy}{$prm_fwpolicy}{rules}[$rule]{servicerange}{$proto}{$service}}) {
            if ($srvgroup->{counter} != 0) {
              $service_result .= $srvgroup->{entry}." [".$srvgroup->{counter}."]<br>\n";
              #$service_result .= $srvgroup->{entry}." [".$srvgroup->{counter}."]:".$srvgroup->{rulenr}."<br>\n";
            }
          }
        } else {
          foreach my $srvgroup ( @{$fw->{policy}{$prm_fwpolicy}{rules}[$rule]{service}{$proto}{$service}}) {
            if ($srvgroup->{counter} != 0) {
              $service_result .= $srvgroup->{entry}." [".$srvgroup->{counter}."]<br>\n";
              #$service_result .= $srvgroup->{entry}." [".$srvgroup->{counter}."]:".$srvgroup->{rulenr}."<br>\n";
            }
          }
        }
      }
    }

    foreach my $icmptype (keys %{$fw->{policy}{$prm_fwpolicy}{rules}[$rule]{service}{icmp}}) {
      foreach my $srvgroup ( @{$fw->{policy}{$prm_fwpolicy}{rules}[$rule]{service}{icmp}{$icmptype}}) {
        if ($srvgroup->{counter} != 0) {
          $service_result .= $srvgroup->{entry}." [".$srvgroup->{counter}."]<br>\n";
          #$service_result .= $srvgroup->{entry}." [".$srvgroup->{counter}."]:".$srvgroup->{rulenr}."<br>\n";
        }
      }
    }
    
    $action = $fw->{policy}{$prm_fwpolicy}{rules}[$rule]{action}."<br>\n";

    foreach my $firewall_tuple ( split(/\s*;\s*/, $fw->{policy}{$prm_fwpolicy}{rules}[$rule]{firewall}) ) {
      $firewall_list .= $firewall_tuple."<br>\n";
    }

    $table->addRow( 
      sprintf("%d",$rule),
      $source_rule,
      $source_result,
      $destination_rule,
      $destination_result,
      $service_rule,
      $service_result,
      $action,
      $firewall_list
    );
    $table->setRowAlign($row, 'RIGHT');
    if (defined $fw->{policy}{$prm_fwpolicy}{rules}[$rule]{rule_disabled}) {
      $table->setRowBGColor($row, '#c05050'); # Red
    } else {
      $table->setRowBGColor($row, '#fff080'); # pale yellow 
    }
  }
  print FWREPORTFILE "<p>\n$table</p>\n\n";
  print FWREPORTFILE "\n</center>\n</body>\n</html>\n";
  print "\nReporting to ".$prm_fwreportfile." ended.\n";
}
