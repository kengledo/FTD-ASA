#!/usr/bin/perl
#Script by John Groetzinger
#Version 2.3
#
#       Changelog:
#       2.4:
#       Fixed bugs with processing last entry of interval
#
#       2.3:
#       Updated pcres to handle files that have CRLF line terminators
#
#       2.2:
#       Changed threading to use a thread pool (reduces memory use).
#       Added memory test and set max memory consumption to roughly 8-9GB.  If prediced memory use is higher than that, it will hard set the limit to the maximum.
#       Added predicted runtime (very rough estimate).
#       Added option to override max threads. (To use less memory)
#       Added notice if flow-ip was run without 1 sec perfmon.
#       Added debug logging.
#
#       2.1.1:
#       Fixed bug: create report fails if specifying a directory where you don't have write permissions.
#       Report name is asked for at the beginning now, if you don't have write permissions in specified directory it will fail at the start.
#
#       2.1:
#       Added override options for file, source/dest pair output, and top hosts summary
#
#       2.0:
#       Threading added
#
use strict;
use Switch;
use Data::Dumper;
use Config;
use threads;
use threads::shared;
use Thread::Queue;
use Scalar::Util;
use Getopt::Long;
#use Devel::Size qw(size total_size);
use Proc::ProcessTable;

my $version = "2.4"; # Current Version

my $main_dir = `pwd`;
my $de_dir = 0;
chomp($main_dir);
my $s = "/";
my $instance_cnt = 0;
my (@tcp_bt, @udp_bt, @other_bt) : shared;
my $limit = -1;
my ($include_data, $tcp_sort_by, $udp_sort_by, $other_sort_by) = 0;
my %inst_hash;
my ($tcp_key, $udp_key, $other_key) = "";
my (%summary_host_hash,%summary_pair_hash, %thread_hash) = ();
my @test_arr;
my $spec_file = 0;
my $pair_limit = 15;
my $summary_limit = 25;
my $help = 0;
my $reduce_threads = 0;
my $DEBUG = 0;
my $t = new Proc::ProcessTable;
my $writting : shared = 0;
my $written : shared = 1;
my $MAX_THREADS = 5;
my $TERM : shared = 0;
my $IDLE_QUEUE = Thread::Queue->new();
my $username = $ENV{LOGNAME} || $ENV{USER} || getpwuid($<);
#printMemUse();
sub usage{
    print ("\nFlow IP Report - v$version\n\nUsage: flow_ip_report.pl [Options] <parameters>\n\nYou must be in the directory containing csv file(s) when running script.\n".
        "csv files must be in the format: flow-ip-stats-#.csv or you can specify one file to run the report on with the -f option\n".
        "The csv files must be numbered in order properly and should not skip any numbers or the script will exit.\n".
        "If no detection engine directory is specified report will not contain CPU Affinity info.\n\n".
        "This script will generate a report file containing the flow-ip data specified sorted by the selected field.\n\n".

        "Options:\n".
        "\t-d <de_directory>\tSpecify a detection engine directory to get CPU affintiy info\n".
        "\t-f <file.csv>\t\tSpecify a specific csv file\n".
        "\t-p <limit>\t\tOverride the default amount of top source dest pairs to display in the report\n".
        "\t-s <limit>\t\tOverride the default amount of top hosts to display in the summary of the report\n".
        "\t-t <max_threads[1-5]>\t\tUse less threads. This will reduce memory consumtion and CPU use but will take longer to run. \n".
        "\t   \t\tIf you have very large csv files with 1 second perfmon, you may need to reduce the max number of threads to use a higher limit.\n".
        "\t-h --help \t\tDisplay this message\n\n".
        "If you have any questions or need assistance with this script please send an email to tsanalysis-admins\@cisco.com\n\n");
}
# Gracefully terminate application on ^C or command line 'kill'
$SIG{'INT'} = $SIG{'TERM'} =
    sub {
        print(">>> Terminating <<<\n");
        $TERM = 1;
        # Add -1 to head of idle queue to signal termination
        $IDLE_QUEUE->insert(0, -1);
        exit(0);
    };

###Main
my $start;
if($ARGV[0] eq "--help"){
    usage();
    exit(0);
}
GetOptions("d=s" => \$de_dir,
    "f=s" => \$spec_file,
    "p=i" => \$pair_limit,
    "s=i" => \$summary_limit,
    "t=i" => \$reduce_threads,
    "h!" => \$help);
if($ARGV[0] eq "--help" || ($help)){
    usage();
    exit(0);
}
#print "Max threads: $MAX_THREADS\n";
#exit(0);

if($reduce_threads){
    if($reduce_threads > 5 || $reduce_threads < 1){
        print("Invalid argument '$reduce_threads' passed with -t option.\n".
            "Max threads can not be greater than $MAX_THREADS (default).\n".
            "If you want to reduce total memory use, you can specify a number less than $MAX_THREADS.\n");
        usage();
        exit(0);
    }
    else{
        print("-t option passed, reducing max threads from $MAX_THREADS to $reduce_threads.\n");
        $MAX_THREADS = $reduce_threads;
    }
}
my $file_ex = 0;
my $report_file_name;
while($file_ex == 0){
    print "Specify a filename for the report: ";
    $report_file_name = <STDIN>;
    chomp($report_file_name);
    if(-e $report_file_name){
        print "File exists, would you like to overwrite? (Y/N): ";
        my $user_input = <STDIN>;
        chomp($user_input);
        if($user_input eq "y" || $user_input eq "Y"){$file_ex = 1;}
    }
    else {$file_ex = 1;}
}
my $fail_name;
open FILE2, ">$report_file_name" or $fail_name=$!; #print "Couldn't open $report_file_name!\n$!\n";
if($fail_name){
    print "Couldn't open '$report_file_name'!\nError: $fail_name\nAttempting to create file with a different name...\n";
    my $time = time();
    $report_file_name = "flow_report_tmp-$time.txt";
    open FILE2, ">$report_file_name" or die "Report file could not be created!\n$!\n";
    print "Report file '$report_file_name' will be created\n";
}


if($spec_file) {
    print("Only running script for file '$spec_file'\n");
    $instance_cnt = 1;
}
else {
    print("Checking current directory for csv files.\n");
    #Check that current directory contains atleast 1 flow-ip-stats-#.csv file
    $instance_cnt = `ls $main_dir | egrep -v '(top|full)' | egrep -c "^flow-ip-stats-[1-9][0-9]?.csv"`;
}
chomp($instance_cnt);
debug("Got $instance_cnt instances");
#my $num_threads = $instance_cnt;
#my @threads = initThreads();

if($instance_cnt == 0) {
    print "ERROR: There are no flow-ip-stats-#.csv files in your current directory\n\n";
    usage();
    exit(0);
}

else {

    #check if de directory was provided initially
    my $dir_found = 0;
    if($de_dir){
        if(-d "$de_dir"){
            print("Getting de info from '$de_dir'\n");
            $dir_found = 1;
        }
        else {
            print "'$de_dir' does not exists! would you like to enter a different one?(y/n)";
            my $user_input = <STDIN>;
            chomp($user_input);
            if($user_input eq "y" || $user_input eq "Y"){
                $dir_found = 0;
            }
            else{
                $dir_found = 1;
                $de_dir = "skip";
            }
        }
    }
    if($dir_found == 0){
        print("\nIf you would like CPU affinity info enter de directory(or 's' to skip): ");
        $de_dir = <STDIN>;
        chomp($de_dir);
        if($de_dir eq "s" || $de_dir eq "S"){
            print("\nSkipping de info!\n");
            $de_dir = "skip";
        }
    }

    if(!($de_dir eq "skip")){
        print "Getting info from de directory...\n";
        #validate directory
        my $temp_cnt = `ls $de_dir | egrep -c "instance-[1-9][0-9]?"`;
        if($instance_cnt != $temp_cnt) {
            print "\nNumber of csv files: $instance_cnt != Number of instances: $temp_cnt\n";
            print("WARNING: Amount of instances does not match amount of csv files.\n".
                "         Make sure correct de directory was used. CPU affinity info may be incorrect.\n");
        }

        #check if de_dir ends in / and remove it if so
        if(substr($de_dir, length($de_dir)-1) == $s) { $de_dir = substr($de_dir, 0, length($de_dir)-1);}

        #get uuid of de
        my $de_uuid = substr($de_dir, rindex($de_dir, $s)+1);
        my @pmtool_str = `egrep '($de_uuid|CPU)' $de_dir/../../../../../command-outputs/usr-local-sf-bin-pmtool\\ status.output |egrep -v '(detection_engine|react|alert)'`;
        #Get cpu associated with instance

        my @cpu_aff_inst_arr;
        my $i=0;
        my ($tmp1, $tmp2);
        for(my $j=0; $j<=$instance_cnt; $j++) {
            #check to see if strings contain correct info
            if(substr($pmtool_str[$i], 0, 36) == $de_uuid && substr($pmtool_str[$i+1], 0, 12) == "CPU Affinity" ) {
                #$cpu_aff_inst_arr[$i+1] = "instance-" . substr($pmtool_str[$i], 37, 2);
                $tmp1 = substr($pmtool_str[$i], 37, 2);
                $tmp1 =~ tr/0-9//cd;
                $tmp2 = substr($pmtool_str[$i+1], 0, 16);
                #$cpu_aff_inst_arr[$i+1] .= "\n" . substr($pmtool_str[$i+1], 0, 16) . "\n";
                $inst_hash{$tmp1} = $tmp2;
                $i+=2;
            }
        }
    }

    while($include_data < 1){
        print ("\nSelect the data to include in the report:\n".
            "1) tcp         2) udp\n".
            "3) other       4) all \n".
            "Data to include in report: ");
        $include_data = <STDIN>;
        #chomp($include_data);
        $include_data = int($include_data);
        if($include_data < 1 || $include_data > 4){
            print "\nInvalid entry '$include_data'\n";
            $include_data = 0;
        }
    }


    flowstats_tcp();

    ########################################################
    #Begin report output
    #Report includes:
    #Instance# and corresponding CPU
    #Top talkers (Source -> Destination) and amount of packets/bytes/established/closed/created
    ########################################################
    my $end = time();
    my $total_time = $end - $start;
    print "Script took $total_time seconds to analye data\n";
    createReport();
}

sub flowstats_tcp{
    ##Method based off flowstats_tcp.pl script by Mehdi Derdouri

    #Prompt for tcp sort by field
    if($include_data == 1 || $include_data == 4){
        while($tcp_sort_by !~ /[1-4]{1}/){
            print "\nSelect the field to sort tcp stats by:\n".
                "1) tcp_packets       2) tcp_bytes\n".
                "3) tcp_established   4) tcp_closed\n".
                "Field to sort tcp stats by: ";
            $tcp_sort_by = <STDIN>;
            #chomp($tcp_sort_by);
            $tcp_sort_by = int($tcp_sort_by);

        }
        if($tcp_sort_by == 1){ $tcp_key = "tcp_packets";}
        elsif($tcp_sort_by == 2){ $tcp_key = "tcp_bytes";}
        elsif($tcp_sort_by == 3){ $tcp_key = "tcp_established";}
        elsif($tcp_sort_by == 4){ $tcp_key = "tcp_closed";}

    }

    #Prompt for udp sort by field
    if($include_data == 2 || $include_data == 4){
        while($udp_sort_by !~ /[1-3]{1}/){
            print "\nSelect the field to sort udp stats by:\n".
                "1) udp_packets       2) udp_bytes\n".
                "3) udp_created\n".
                "Field to sort udp stats by: ";
            $udp_sort_by = <STDIN>;
            #chomp($udp_sort_by);
            $udp_sort_by = int($udp_sort_by);
        }
        if($udp_sort_by == 1){ $udp_key = "udp_packets";}
        elsif($udp_sort_by == 2){ $udp_key = "udp_bytes";}
        elsif($udp_sort_by == 3){ $udp_key = "udp_created";}
    }

    #Prompt for other sort by field
    if($include_data == 3 || $include_data == 4){
        while($other_sort_by !~ /[1-2]{1}/){
            print "\nSelect the field to sort other stats by:\n".
                "1) other_packets       2) other_bytes\n".
                "Field to sort other stats by: ";
            $other_sort_by = <STDIN>;
            #chomp($other_sort_by);
            $other_sort_by = int($other_sort_by);
        }
        if($other_sort_by == 1){ $other_key = "other_packets";}
        elsif($other_sort_by == 2){ $other_key = "other_bytes";}
    }

    #Prompt for limit to set per time period
    while($limit < 0){
        print "\nSet the limit for the top number of records from each time period to use [press enter for default (15)]\nLimit: ";
        my $temp_lim = <STDIN>;
        chomp($temp_lim);
        if($temp_lim eq "" || $temp_lim == 0){$limit = 15;}
        elsif(Scalar::Util::looks_like_number($temp_lim)){
            $limit = $temp_lim;
        }

        if ($limit < 0){
            print "Limit must be an integer greater than or equal to zero (0 = default(15)).\n";
        }
    }
    if($instance_cnt < $MAX_THREADS){$MAX_THREADS = $instance_cnt;}
    estimateMemUse();
    print "Processing csv files...Depending on amount of data and Limit set, this may take a few moments.\n";

    ##Start threading to process csv files
    my %work_queues;
    $start = time();
    ####NEW THREADING (Smart)####
    for (1..$MAX_THREADS) {
        #Create a work queue for a thread
        my $work_q = Thread::Queue->new();
        # Create the thread, and give it the work queue
        my $thr = threads->create('worker', $work_q);
        # Remember the thread's work queue
        $work_queues{$thr->tid()} = $work_q;
    }

    # Manage the thread pool until signalled to terminate or finished
    for(my $j=1;$j <= $instance_cnt; $j++) {
        #Wait for an available thread
        print("Queueing csv-$written for processing...\n");
        my $tid = $IDLE_QUEUE->dequeue();
        print("Analyzing csv-$written file.\n");
        # Check for termination condition
        last if ($tid < 0);
        # Give the thread some work to do
        $work_queues{$tid}->enqueue($written);
        $written++;
    }
    printMemUse();
    $work_queues{$_}->enqueue(-1) foreach keys(%work_queues);
    # Wait for all the threads to finish
    $_->join() foreach threads->list();

    print "Done processing all csv files!\n";
    sub analyze_csv{
        my $start_time = time();
        #my $id = threads->tid();
        my $avg_p = 0;
        my $x = $_[0];
        my ($tcp_arr, $udp_arr, $other_arr, $all_arr);
        if($spec_file){open FILE, $spec_file or die "Couldn't open $spec_file!\n";}
        else{open FILE, "flow-ip-stats-$x.csv" or die "Couldn't open flow-ip-stats-$x.csv!\n";}
        my $ip_re = qr/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/;
        my $line = <FILE>;
        my $iteration = 1;
        if($tcp_key){$tcp_arr = "$tcp_key\n";} #set values to sort by
        if($udp_key){$udp_arr = "$udp_key\n";}
        if($other_key){$other_arr = "$other_key\n";}
        my $end = 0;
        my $while = 0;
        while (!$end) {
            $while = 0;
            chomp($line);
            #print $line;
            my @records = ();
            while(($line !~ /^\d{10}/)){ #for(my $j = 0; $j < $n_records; $j++){
                $while = 1;
                if ($line =~ /^($ip_re),($ip_re),(\d+),(\d+),(\d+),(\d+),(\d+),(\d+),(\d+),(\d+),(\d+),(\d+),(\d+),(\d+),(\d+),(\d+),(\d+)[\r\n]?$/){
                    my $record = {};
                    $record->{ipA} = $1;
                    $record->{ipB} = $2;
                    $record->{tcp_packets} = $3 + $5;
                    $record->{udp_packets} = $7 + $9;
                    $record->{other_packets} = $11 + $13;
                    $record->{tcp_bytes} = $4 + $6;
                    $record->{udp_bytes} = $8 + $10;
                    $record->{other_bytes} = $12 + $14;
                    $record->{tcp_established} = $15;
                    $record->{tcp_closed} = $16;
                    $record->{udp_created} = $17;
                    push(@records,$record);
                }
                if (!eof FILE) {$line = <FILE>;}
                else {$end = 1; last;}
            }

            $iteration += 1;

            my $size = 0;
            my (@tcp_sorted, @udp_sorted, @other_sorted) = ();
            #Create sorted list for each type
            if($tcp_key){
                @tcp_sorted = sort { if ($tcp_key !~ /^(ipA|ipB)$/) {  $b->{$tcp_key} <=> $a->{$tcp_key} } else { $a->{$tcp_key} cmp $b->{$tcp_key} } } @records;
                $size = $#tcp_sorted+1;
            }
            if($udp_key){
                @udp_sorted = sort { if ($udp_key !~ /^(ipA|ipB)$/) { $b->{$udp_key} <=> $a->{$udp_key} } else { $a->{$udp_key} cmp $b->{$udp_key} } } @records;
                $size = $#udp_sorted+1;
            }
            if($other_key){
                @other_sorted = sort { if ($other_key !~ /^(ipA|ipB)$/) { $b->{$other_key} <=> $a->{$other_key} } else { $a->{$other_key} cmp $b->{$other_key} } } @records;
                $size = $#other_sorted+1;
            }
            my $max = ($limit > $size || $limit == 0) ? $size : $limit;
            #$limit = $max;
            #debug("Number of lines useful data: ".$#records."\n");
            #$avg_p += $#records;
            @records = ();
            for (my $i = 0; $i < $max; $i++){
                if ($tcp_key =~ /^(tcp_packets|tcp_bytes|tcp_established|tcp_closed)$/){
                    my $tcp_record = $tcp_sorted[$i];
                    #original                            $tcp_arr[$x] .=  sprintf("%s,%s,%u\n", $tcp_record->{ipA}, $tcp_record->{ipB}, $tcp_record->{tcp_packets});
                    $tcp_arr .=  sprintf("%s,%s,%u,%u,%u,%u\n", $tcp_record->{ipA}, $tcp_record->{ipB}, $tcp_record->{tcp_packets},
                        $tcp_record->{tcp_bytes}, $tcp_record->{tcp_established}, $tcp_record->{tcp_closed});
                    undef($tcp_record);
                }

                if ($udp_key =~ /^(udp_packets|udp_bytes|udp_created)$/){
                    my $udp_record = $udp_sorted[$i];
                    #original                            $udp_arr[$x] .= sprintf("%2d: [%15s <-> %15s]: %u bytes (%u UDP packets) (%u created)\n",
                    #                                    $i+1, $udp_record->{ipA}, $udp_record->{ipB}, $udp_record->{udp_bytes},
                    #                                    $udp_record->{udp_packets}, $udp_record->{udp_created});
                    $udp_arr .= sprintf("%s,%s,%u,%u,%u\n",
                        $udp_record->{ipA}, $udp_record->{ipB}, $udp_record->{udp_packets},$udp_record->{udp_bytes}, $udp_record->{udp_created});
                    undef($udp_record);
                }


                if ($other_key =~ /^(other_packets|other_bytes)$/){
                    my $other_record = $other_sorted[$i];
                    #original                            $other_arr[$x] .=  sprintf("%2d: [%15s <-> %15s]: %u bytes (%u OTHER packets)\n",
                    #                                    $i+1, $other_record->{ipA}, $other_record->{ipB}, $other_record->{other_bytes}, $other_record->{other_packets});
                    $other_arr .=  sprintf("%s,%s,%u,%u\n",
                        $other_record->{ipA}, $other_record->{ipB}, $other_record->{other_packets}, $other_record->{other_bytes});
                    undef($other_record);
                }
            } #end for loop
            undef(@other_sorted);
            undef(@tcp_sorted);
            undef(@udp_sorted);
            if ($while == 0){
                if (!eof FILE) {$line = <FILE>;}
                else { $end = 1; last;}
            }
        } #end while loop
        if($DEBUG==1){my $time = $start_time - time();
            print("Time to sort and print initial hashes: ".$time."\n");}
        #output string to use for formatting
        $all_arr = $tcp_arr . $udp_arr . $other_arr;
        my $return_string = flow_stat_adder($x, $all_arr);
        undef($all_arr);
        close(FILE);
        if($DEBUG==1){my $end_time = time();
            my $run_time = $start_time - $end_time;
            print "analyze_csv-$x took $run_time\n";}
        writeResults($x, $return_string);
        print "\n*Finished processing csv-$x file.  Found $iteration time periods of data.\n";
        if($DEBUG==1){$avg_p = int($avg_p/$iteration);
            print("Average amount of lines per time period: $avg_p\n");}
        printMemUse();
        return 1;
    }#end analyze_csv
}#end flowstats_tcp

sub flow_stat_adder{
    #Method based off flow_stat_adder.pl by Mehdi Derdouri
    my $start_time = time();
    my %tcp_hash = ();
    my %udp_hash = ();
    my %other_hash = ();

    my ($tcp_string, $udp_string, $other_string) = "";
    my $inst_num = $_[0];
    my $flow_str = $_[1];
    my $switch;
    debug("Do split\n");
    for(split /^/,$flow_str){
        chomp($_);
        if($_ =~ m/^tcp/){ #check if tcp data
            $switch = "tcp";
        }
        elsif($_ =~ m/^udp/){
            $switch = "udp";
        }
        elsif($_ =~ m/^other/){
            $switch = "other";
        }

        switch ($switch){
            case "tcp"{
                if(m/(.*,.*),(\d+),(\d+),(\d+),(\d+)/){
                    if (exists($tcp_hash{$1})){
                        $tcp_hash{$1}->{tcp_packets} = $tcp_hash{$1}->{tcp_packets} + $2;
                        $tcp_hash{$1}->{tcp_bytes} = $tcp_hash{$1}->{tcp_bytes} + $3;
                        $tcp_hash{$1}->{tcp_established} = $tcp_hash{$1}->{tcp_established} + $4;
                        $tcp_hash{$1}->{tcp_closed} = $tcp_hash{$1}->{tcp_closed} + $5;
                    }
                    else{
                        $tcp_hash{$1}->{tcp_packets} = $2;
                        $tcp_hash{$1}->{tcp_bytes} = $3;
                        $tcp_hash{$1}->{tcp_established} = $4;
                        $tcp_hash{$1}->{tcp_closed} = $5;
                    }
                }
            }
            case "udp"{
                if(m/(.*,.*),(\d+),(\d+),(\d+)/){
                    if (exists($udp_hash{$1})){
                        $udp_hash{$1}->{udp_packets} = $udp_hash{$1}->{udp_packets} + $2;
                        $udp_hash{$1}->{udp_bytes} = $udp_hash{$1}->{udp_bytes} + $3;
                        $udp_hash{$1}->{udp_created} = $udp_hash{$1}->{udp_created} + $4;
                    }
                    else{
                        $udp_hash{$1}->{udp_packets} = $2;
                        $udp_hash{$1}->{udp_bytes} = $3;
                        $udp_hash{$1}->{udp_created} = $4;
                    }
                }
            }
            case "other"{
                if(m/(.*,.*),(\d+),(\d+)/){
                    if (exists($other_hash{$1})){
                        $other_hash{$1}->{other_packets} = $other_hash{$1}->{other_packets} + $2;
                        $other_hash{$1}->{other_bytes} = $other_hash{$1}->{other_bytes} + $3;
                    }
                    else{
                        $other_hash{$1}->{other_packets} = $2;
                        $other_hash{$1}->{other_bytes} = $3;
                    }
                }
            }
            else {
                print "ERROR: could not find type\n";
            }
        }
    }
    #debug("Finish split\n");
    #Get biggest talkers and sort by field specified
    #if($DEBUG ==1) {
    #       my $tcp_size = size(\%tcp_hash);
    #       my $udp_size = size(\%udp_hash);
    #       my $other_size = size(\%other_hash);
    #printMemUse();
    #       debug("tcp hash size: $tcp_size\n".
    #             "udp hash size: $udp_size\n".
    #             "other hash size: $other_size");
    #}
    if($tcp_key){
        debug("Got inst_num '$inst_num' before sort\n");
        #debug(print "Sorting tcp");
        #foreach my $key (sort hashValueDescendingNum_tcp (keys(%tcp_hash))) {
        foreach my $key (sort {$tcp_hash{$b}->{$tcp_key} <=> $tcp_hash{$a}->{$tcp_key}} keys(%tcp_hash)){
            $tcp_string .= "$key," . $tcp_hash{$key}->{tcp_packets} .",". $tcp_hash{$key}->{tcp_bytes} .",". $tcp_hash{$key}->{tcp_established} .",". $tcp_hash{$key}->{tcp_closed} . "\n";
        }
    }

    if($udp_key){
        #debug("Sorting udp");
        #foreach my $key (sort hashValueDescendingNum_udp (keys(%udp_hash))) {
        foreach my $key (sort {$udp_hash{$b}->{$udp_key} <=> $udp_hash{$a}->{$udp_key}} keys(%udp_hash)){
            $udp_string .=  "$key," . $udp_hash{$key}->{udp_packets} .",". $udp_hash{$key}->{udp_bytes} .",". $udp_hash{$key}->{udp_created} . "\n";
        }
    }
    if($other_key){
        #debug("Sorting other");
        #foreach my $key (sort hashValueDescendingNum_other (keys(%other_hash))) {
        foreach my $key (sort {$other_hash{$b}->{$other_key} <=> $other_hash{$a}->{$other_key}} keys(%other_hash)){
            $other_string .= "$key," . $other_hash{$key}->{other_packets} .",". $other_hash{$key}->{other_bytes} . "\n";
        }
    }
    #debug("finished sorts");

    sub hashValueDescendingNum_tcp {
        $tcp_hash{$b}->{$tcp_key} <=> $tcp_hash{$a}->{$tcp_key};
    }

    sub hashValueDescendingNum_udp {
        $udp_hash{$b}->{$udp_key} <=> $udp_hash{$a}->{$udp_key};
    }

    sub hashValueDescendingNum_other {
        $other_hash{$b}->{$other_key} <=> $other_hash{$a}->{$other_key};
    }
    if($DEBUG==1){my $end_time = time();
        my $run_time = $end_time - $start_time;
        print "flow_stat_adder took $run_time\n";}
    %tcp_hash = ();
    %udp_hash = ();
    %other_hash = ();
    #debug("Mem use after flowstat_adder: ");
    #printMemUse();
    undef($inst_num);
    return $tcp_string."<1>".$udp_string."<2>".$other_string;
}

sub createReport {
    print "Creating flow_ip_stats report file...\n";
    #debug("tcp_bt: " . Dumper(@tcp_bt));
    my $report_str = "================================\n".
        "=== Report for flow-ip-stats ===\n".
        "================================\n\n";
    for(my $j=1; $j<=$instance_cnt; $j++){
        if($de_dir eq "skip"){ $inst_hash{$j} = "CPU Affinity: de dir was not defined!";}
        $report_str .= "\n- - - - - - - - - - - - - - - - - - - - Results for instance-$j - - - - - - - - - - - - - - - - - - - - - -\n\n" . $inst_hash{$j};

        if($tcp_bt[$j]){
            print "Found instance $j, adding to report\n";
            $report_str .= "\nResults for tcp traffic sorted by $tcp_key\nLimit set: $limit\n\n";
            $report_str .= "\tSource\t\t\tDestination\tPackets\t\tBytes\t\tEstablished\tClosed\n";
            my $tcp_cnt = 0;
            for(split /^/,$tcp_bt[$j], $pair_limit){
                if($_ =~ m/(.*),(.*),(\d+),(\d+),(\d+),(\d+)/){
                    $tcp_cnt += 1;
                    $report_str .= sprintf("[%2d]: %15s <----> %15s\t%12u %12u\t%4u\t\t%4u\n", $tcp_cnt, $1, $2, $3, $4, $5, $6);
                    addToSummary($1, $2, $4, "tcp_bytes");
                }
            }
        }

        if($udp_bt[$j]){
            $report_str .= "\n\nResults for udp traffic sorted by $udp_key\nLimit set: $limit\n\n";
            $report_str .= "\tSource\t\t\tDestination\tPackets\t\tBytes\tCreated\n";
            my $udp_cnt = 0;
            for(split /^/,$udp_bt[$j], $pair_limit){
                if($_ =~ m/(.*),(.*),(\d+),(\d+),(\d+)/){
                    $udp_cnt += 1;
                    $report_str .= sprintf("[%2d]: %15s <----> %15s %12u %12u\t%4u\n", $udp_cnt, $1, $2, $3, $4, $5);
                    addToSummary($1, $2, $4, "udp_bytes");
                }
            }
        }

        if($other_bt[$j]){
            $report_str .= "\n\nResults for other traffic sorted by $other_key\nLimit set: $limit\n\n";
            $report_str .= "\tSource\t\t\tDestination\tPackets\t\tBytes\n";
            my $other_cnt = 0;
            for(split /^/,$other_bt[$j], $pair_limit){
                if($_ =~ m/(.*),(.*),(\d+),(\d+)/){
                    $other_cnt += 1;
                    $report_str .= sprintf("[%2d]: %15s <----> %15s %12u %12u\n", $other_cnt, $1, $2, $3, $4);
                    addToSummary($1, $2, $4, "other_bytes");
                }
            }
        }
        $report_str .= "\n+ + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + +\n";
    }
    ##Print summary of top 25 hosts taken only from the top 15 from each instance (unless overridden).
    my $summary_str = "";
    my $sum_cnt = 0;
    foreach my $key (sort hashValueDescendingNum_summary (keys(%summary_host_hash))) {
        $sum_cnt++;
        #check for stupid 0 values because perl is too dumb to handle divide by zero
        my ($percent_tcp, $percent_udp, $percent_other) = (0);
        if($summary_host_hash{$key}->{total_bytes}){
            $percent_tcp = $summary_host_hash{$key}->{tcp_bytes}/$summary_host_hash{$key}->{total_bytes}*100;
            $percent_udp = $summary_host_hash{$key}->{udp_bytes}/$summary_host_hash{$key}->{total_bytes}*100;
            $percent_other = $summary_host_hash{$key}->{other_bytes}/$summary_host_hash{$key}->{total_bytes}*100;
        }
        if($sum_cnt < $summary_limit + 1){
            $summary_str .= sprintf("[%2d]: %15s\t%10d\t\t%7d\t\t\t%.1f\t\t%.1f\t\t%.1f\n", $sum_cnt, $key, $summary_host_hash{$key}->{total_bytes}/1024,
                $summary_host_hash{$key}->{total_bytes}/1048576,
                $percent_tcp,
                $percent_udp,
                $percent_other);
            #"$key," . $summary_host_hash{$key}->{packets} .",". $summary_host_hash{$key}->{bytes} . "\n";
        }
    }


    $report_str .= "\n*****************************************************************************************************************\n" .
        "                                               SUMMARY\n".
        "*****************************************************************************************************************\n" .
        "Summary contains the top 25 hosts by default, sorted by amount of bytes.\n".
        "Summary data only includes data from what is shown above for each instance (Data shown above).\n".
        "Top 25 hosts:\n".
        "\t   Host\t\tTotal bytes(K)\t\tTotal bytes(M)\t\t%tcp\t\t%udp\t\t%other\n".
        $summary_str;

    print "\nReport complete!\n";
    my $fail_name;
    open FILE2, ">$report_file_name" or $fail_name=$!; #print "Couldn't open $report_file_name!\n$!\n";
    if($fail_name){
        print "Couldn't open '$report_file_name'!\nError: $fail_name\nAttempting to create the file in /var/tmp...\n";
        my $time = time();
        $report_file_name = "/var/tmp/flow_report_tmp-$time.txt";
        open FILE2, ">$report_file_name" or die "Report file could not be created!\n$!\n";
    }
    print FILE2 $report_str;
    print "Report file '$report_file_name' created!\n\n";

    sub hashValueDescendingNum_summary {
        $summary_host_hash{$b}->{total_bytes} <=> $summary_host_hash{$a}->{total_bytes};
    }

    sub addToSummary {
        if(exists($summary_host_hash{$_[0]})){
            $summary_host_hash{$_[0]}->{$_[3]} = $summary_host_hash{$_[0]}->{$_[3]} + $_[2];
            $summary_host_hash{$_[0]}->{total_bytes} = $summary_host_hash{$_[0]}->{total_bytes} + $_[2];
        }
        else {
            $summary_host_hash{$_[0]}->{$_[3]} = $_[2];
            $summary_host_hash{$_[0]}->{total_bytes} = $_[2];
        }
        if(exists($summary_host_hash{$_[1]})){
            $summary_host_hash{$_[1]}->{$_[3]} = $summary_host_hash{$_[1]}->{$_[3]} + $_[2];
            $summary_host_hash{$_[1]}->{total_bytes} = $summary_host_hash{$_[1]}->{total_bytes} + $_[2];
        }
        else {
            $summary_host_hash{$_[1]}->{$_[3]} = $_[2];
            $summary_host_hash{$_[1]}->{total_bytes} = $_[2];
        }

    }

}

sub worker {
    my $done = 0;
    my ($work_q) = @_;
    my $tid = threads->tid();
    while(! $TERM && $done > -1) {
        if($DEBUG==1){printf("Idle     -> %2d\n", $tid);}
        $IDLE_QUEUE->enqueue($tid);
        my $csv = $work_q->dequeue();
        $done = $csv;
        if($csv > 0){
            if($DEBUG==1){printf("            %2d <- Working\n", $tid);}
            analyze_csv($csv);
        }
    }#while(! $TERM && $done > -1);
    if($DEBUG==1){printf("Finished -> %2d\n", $tid);}
}


sub writeResults(){
    my $tmp_inst = $_[0];
    my $tmp_str;
    my @tmp_arr;
    $tmp_str = $_[1];
    debug("In writeResults for instance $tmp_inst");
    #debug("and string: $tmp_str");
    my $index_1 = index($tmp_str, "<1>");
    my $index_2 = index($tmp_str, "<2>");
    my $str1 = substr($tmp_str, 0, $index_1);
    my $str2 = substr($tmp_str, $index_1+3, $index_2 - $index_1-3);
    my $str3 = substr($tmp_str, $index_2+3);
    $tcp_bt[$tmp_inst] = $str1;
    $udp_bt[$tmp_inst] = $str2;
    $other_bt[$tmp_inst] = $str3;
    #debug("tcp_bt: ".Dumper(@tcp_bt));
    #debug("tcp_bt: $tcp_bt");
    #debug("tcp_bt: $tcp_bt");
    #{
    #  lock $writting;
    #  cond_signal($writting);
    #  $writting--;
    #cond_signal($written);
    #$written++;
    #debug("Done writeResults1");
    #}
    debug("Done writeResults");
}

sub estimateMemUse {
    print("Checking csv file(s) and estimating process time...\n");
    my @file_names = ();
    my $csv = 0;
    my $return = 1;
    my $M_L_RATIO = 250;
    my $base_mem = 230834176;
    my $MAX_MEMORY = 11561938944;
    my $hashes = 1;
    my ($total_mem_use, $est_time, $avg_file_size, $total_files_size, $avg_period, $total_periods) = 0;
    my $INT_RATIO = .82;
    my $FLOW_RATIO = .28;
    my $TIME_RATIO = .0000315;
    if($include_data == 4){$hashes = 3;}

    if($spec_file){
        $file_names[0] = $spec_file;
    }
    else{
        for(1..$instance_cnt){
            $file_names[$_-1] = "flow-ip-stats-$_.csv";
        }
    }
    my (@average_time, @average_records, @predicted_tps, @sizes, @perfmon) = ();
    my $S_L_RATIO = 62.7;
    foreach my $file (@file_names){
        open FILE, $file or die "Couldn't open $file!\n";
        debug("Opened file '$file'");
        my $size = -s $file;
        my $i = 1;
        my ($total_records, $total_time, $count , $recs) = 0;
        my ($time1, $time2, $est_lc) = 0;
        my $line = <FILE>;
        $csv++;
        my $end = 0;
        while(!$end  && $count <= 25){ #Get average of first 25 time periods
            #while(!eof FILE ){ #Get average of first 25 time periods
            if ($line =~ /^(\d+),(\d+)[\r\n]?$/) {
                debug("Valid line received");
                $count ++;
                $total_time = $1;
                if($2 != 0){$recs++;}
                if(!eof FILE) {$line = <FILE>;}
                else {$end =1;}
                while(($line !~ /^\d{10}/) && (!$end)){
                    $total_records++;
                    if(!eof FILE) {$line = <FILE>;}
                    else {$end=1;}
                }
                if($count == 1){$time1 = $1;}
                $time2 = $1;
            }
            else{
                debug("The first line didn't match format epoch,num_records, got '$line'");
                if(!eof FILE) {$line = <FILE>;}
                else {$end=1;}
            }
        }
        #print ("$file count $count\n");
        debug("done getting averages");
        $total_time = $time2 - $time1;
        $average_records[$csv] = int($total_records/$count);
        #print("total_records $total_records\n");
        #print("average_records $average_records[$csv]\n");
        if(eof FILE){
            $average_time[$csv] = int($total_time/$count);
            $predicted_tps[$csv] = $recs;
            $est_lc = $total_records;
        }
        else{
            $average_time[$csv] = int($total_time/$count);
            if($average_time[$csv] < 3){
                $S_L_RATIO = 61.5;
            }
            else{
                $S_L_RATIO = 63.7;
            }
            $est_lc = $size/$S_L_RATIO;
            $predicted_tps[$csv] = int($est_lc/$average_records[$csv]);
        }
        if($average_time[$csv] > 3){
            $perfmon[$csv] = $csv;
        }
        $total_periods += $predicted_tps[$csv];

        $total_files_size += $size;
        my $est_mem_use = $limit * $predicted_tps[$csv] * $M_L_RATIO * $hashes;
        $total_mem_use += $est_mem_use;
        #$est_time = ($limit*$predicted_tps[$csv]+2000000)/12100;
        debug("est_lc=$est_lc\npredicted_tps= ".$predicted_tps[$csv]."\nhashes=$hashes\n");
        if($limit < $average_records[$csv]){
            $est_time += int(($INT_RATIO * $est_lc + $FLOW_RATIO * $predicted_tps[$csv] * $hashes *$limit) * $TIME_RATIO);
        }
        else{$est_time += int(($INT_RATIO * $est_lc + $FLOW_RATIO * $predicted_tps[$csv] * $hashes *$average_records[$csv]) * $TIME_RATIO);}
        debug("Mem use for csv-$csv: $est_mem_use\n");
        debug("Est time for csv-$csv: $est_time\n");

    }
    if($#perfmon > 0){
        print("########################### NOTICE ###########################\n");
        foreach my $key(@perfmon){
            if($key){
                print("csv-$key was not run with 1 second perfmon enabled\n");
            }}
        print("To get more accurate data, you may want to use a higher limit.\n".
            "##############################################################\n");
    }

    #Estimate mem use
    $avg_file_size = int($total_files_size/$csv);
    $avg_period = int($total_periods/$csv);
    #debug("Average file size =$avg_file_size\n");
    if($avg_file_size > 104857600){$base_mem += int($avg_file_size*$MAX_THREADS);}
    else{$base_mem += int(104857600*$MAX_THREADS);}
    my $avg_mem_per_thread = int($total_mem_use/$csv);
    my $added_mem = int($avg_mem_per_thread * $MAX_THREADS);
    $total_mem_use = int($base_mem + $added_mem);
    if($total_mem_use > $MAX_MEMORY+10){
        ###The limit set is going to consume too much memory, notify user and hardset max limit

        print("\n!!!!!!!!!!!!!!!!!!!!!!!!!! NOTICE !!!!!!!!!!!!!!!!!!!!!!!!!!\n".
            "Are you trying to crash xbox $username!?\n".
            "The limit you set($limit) is too high for this amount of data!\n".
            "This incident has been reported to the almighty lab manager.\n".
            "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!\n\n");
        my $max_limit = int(($MAX_MEMORY - $base_mem)/$MAX_THREADS/$avg_period/$M_L_RATIO/$hashes);
        $limit = $max_limit;#int($avg_mem_per_thread/$avg_period/$M_L_RATIO/$hashes);
        #print "limit: $limit\n";
        if($limit < 2){
            print("There is too much data per csv file!\n".
                "If you want to process all of this data at once you need to run the script with threading turned off.\n");
            exit(1);
        }
        print("Setting limit to the max value for this data ($limit)\n");
        $total_mem_use = $MAX_MEMORY;
        $return = 2;
    }

    $total_mem_use = int($total_mem_use/1024/1024);
    if($DEBUG==2){print("Predicting high end memuse use of: $total_mem_use MB\n");
        if($total_mem_use > 7000){
            my $likely_mem_use = $total_mem_use - 2000;
            print "Probably more like: ". $likely_mem_use . "\n";
        }}
    if($return == 2){
        print("Time to run unknown now that max limit is being used.\n");
        print("Likely going to be 15-30 minutes\n");
        return $return;
    }
    ##Get estiamted run time
    my $avg_time_per_file = int($est_time/$csv);
    #debug("est_time=$est_time\navg time = $avg_time_per_file\n");
    if($instance_cnt < 6){$est_time = $avg_time_per_file;}
    else{
        $est_time = int($avg_time_per_file * (int($csv/5) + $csv%5));
    }
    $est_time += 2;
    if($est_time < 60){print ("Roughly estimated run time is $est_time seconds.\n");}
    else{
        $est_time = int($est_time/60);
        print ("Roughly estimated run time is $est_time minutes.\n");
    }
    return $return;
}
sub debug {
    if ($DEBUG == 1) {
        #my $return_string = "Debug: ";
        #$return_string .= @_[0];
        #print $return_string;
        print "Debug: @_[0]\n";
    }
}

sub printMemUse() {
    if($DEBUG ==2) {
        foreach my $p (@{$t->table}) {
            if($p->pid() == $$) {
                print "Total script memory use: ", $p->size(), " bytes.\n";
                last;
            }
        }
    }
}
