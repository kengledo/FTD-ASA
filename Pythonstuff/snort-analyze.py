#!/usr/bin/perl

use strict;
use Data::Dumper;
use Syslog;
use Getopt::Long qw(:config no_ignore_case bundling);

my @files = ();
my %opts = {};
#my $pct_limit = 0.005;
#my $nomatch_limit = 100;
#my $match_limit = 1000;
my $pct_limit = 0.0025;
my $nomatch_limit = 50;
my $match_limit = 500;


#my $output_mode = "csv_all";  
#my $output_mode = "csv";  
my $output_mode = "text";  
#my $output_mode = "sql";

my $data;
my $headerPrinted = 0;

### We have bad arguments
sub usage 
{
    warn<<USAGE;
Usage: $0 [OPTIONS] <FILE> [ <FILE> ... ]

Arguments:
    -b, --bytes       display only the bytes
    -u, --udp         UDP ports
    -i, --icmp        ICMP ports
    -t, --tcp         TCP ports
    -p, --performance Rule performance information <default>
    -T, --threshold <INTEGER>   
                      Top <x> statistics
    -m, --min-percent <INTEGER> 
                      Only include data above INTEGER% 

    Example, the following will give you the top 5 UDP and TCP ports:
      $0 -utT 5 <file> 
    

USAGE

    exit 0;
}

### no arguments
if ($#ARGV == -1) 
{
    usage();
}

### add file names to the list
sub process 
{
    push (@files, "$_[0]");
}

### Get the options
GetOptions
(
            'bytes|b' => \$opts{bytes},           
            'udp|u' => \$opts{udp},           
            'tcp|t' => \$opts{tcp},           
            'icmp|i' => \$opts{icmp},           
            'p|performance' => \$opts{performance},           
            'T|threshold=i' => \$opts{threshold},           
            'm|min-percent=i' => \$opts{"min-percent"},          
            '<>' => \&process
);

if ($#files == -1)
{
    usage();
}

### Set performance option by default if nothing else is selected
if (!$opts{bytes} 
 && !$opts{udp} 
 && !$opts{tcp} 
 && !$opts{icmp} 
 && !$opts{performance})
{
    $opts{performance} = 1;
} 


### 
foreach my $file (@files)
{
    my $output = Syslog::ProcessFile($file);
#print "out: " . Dumper($output) . "\n\n\n\n\n";
    
    # Get the Snort data
    my $snort_output = $output->{snort};
#print "Snort out: " . Dumper($snort_output) . "\n\n\n\n\n";
    # Process each Snort pid 
    foreach my $key (keys %$snort_output)
    {
        ProcessOutput($snort_output->{$key});
    }


}

# TODO: Identify a unique key from Snort logs be used to identify the profiling 
# info.  This information can be used to start collecting profiling stats from
# multiple runs
# 
# Possible key set is:
# config_file
# start_time
# PID
#
#

sub ProcessOutput
{
    my ($output) = @_;
    
    my $profiling_data = $output->{profiling_data};
    my $flow_port = $output->{flow_port};
    $headerPrinted = 0;
   
    ### process flow port stuff
    if (defined($flow_port) && $output_mode eq "text")
    { 
        _optionalFilter($flow_port);
        if ($opts{tcp} && $flow_port->{tcp})
        {
            _printHeader($output_mode,$output);            
            print "\tTCP data\n";
            for (sort {$a <=> $b} (keys %{$flow_port->{tcp}}))
            {
                print "\t\tPort $_  \t:\t" .$flow_port->{tcp}{$_}{total} . "%\n" ;
            }
        }
        if ($opts{udp} && $flow_port->{udp})
        {
            _printHeader($output_mode,$output);
            print "\tUDP data\n";
            for (sort {$a <=> $b} (keys %{$flow_port->{udp}}))
            {
                print "\t\tPort $_  \t:\t" .$flow_port->{udp}{$_}{total} . "%\n" ;
            }
        }
        if ($opts{bytes} && $flow_port->{bytes})
        {
            _printHeader($output_mode,$output);
            print "\tBytes data\n";
            for (sort {$a <=> $b} (keys %{$flow_port->{bytes}}))
            {
                print "\t\tSize [$_]  \t:\t" .$flow_port->{bytes}{$_} . "%\n" ;
            }
        }
        if ($opts{icmp} && $flow_port->{icmp})
        {
            _printHeader($output_mode,$output);
            print "\tICMP data\n";
            for (sort {$a <=> $b} (keys %{$flow_port->{icmp}}))
            {
                print "\t\tType $_  \t:\t" .$flow_port->{icmp}{$_} . "%\n" ;
            }
        }
    }

    return 0 if(!defined($profiling_data) || !$opts{performance});
    
    _printHeader($output_mode,$output);

    my $total_preproc = $profiling_data->{preprocessors}->{total};
    my $total_packets = $output->{exit_stats}->{protocol_breakdown}->{Total};

    
    if(!defined($total_preproc))
    {
        print STDERR "No preproc profiling data for $output->{pid}\n";
        return 0;
    }

    my $total_microsecs = $total_preproc->{microsecs};

    # Evaluate all of the rules
    my $rule_profiles = $profiling_data->{rules};

    if(!defined($rule_profiles))
    {
        print STDERR "No rule profiling data for $output->{pid}\n";
        return 0;
    }
    
    my $key = "$output->{pid}, $output->{start}, $output->{config_file}";

    if ($output_mode eq "text")
    {
        print "Output from $output->{pid}\n";
    }
    
    foreach my $rule_profile (@$rule_profiles)
    {
        my $pct_time = $rule_profile->{microsecs} / $total_microsecs;
        my $pct_packets = $total_packets ? ($rule_profile->{checks} / $total_packets) : 1;
        my $disp_pct_packets =  sprintf("%0.2f", ($pct_packets * 100));
        my $disp_pct = sprintf("%0.2f", ($pct_time * 100));
        my $match_time = $rule_profile->{avg_match};
        my $nomatch_time = $rule_profile->{avg_nonmatch};
        my $disp_output = "$disp_pct%, $nomatch_time, $match_time, $disp_pct_packets%, $rule_profile->{avg_check}, $rule_profile->{checks}, $rule_profile->{microsecs}, $rule_profile->{matches}, $rule_profile->{alerts}, $rule_profile->{disabled}";
        my $disp_output2 = "$disp_pct% of Snort's time, $disp_pct_packets% of packets analyzed, $rule_profile->{avg_check} average time per packet, $match_time microsecs/match";
        if($output_mode eq "csv_all")
        {
            print "$key, $rule_profile->{gid}, $rule_profile->{sid}, $disp_output\n";
        }
        elsif($output_mode eq "sql")
        {
            print "REPLACE INTO rule_profile_data VALUES($output->{pid}, $output->{start_tvsec}, '$output->{de_uuid}', $rule_profile->{gid}, $rule_profile->{sid}, $rule_profile->{rev}, $rule_profile->{checks}, $rule_profile->{matches}, $rule_profile->{alerts}, $rule_profile->{microsecs}, $disp_pct, $rule_profile->{avg_check}, $rule_profile->{avg_match}, $rule_profile->{avg_nonmatch}, $rule_profile->{disabled});\n";
        }
        else
        {
            my $expense = undef;
            if($match_time >= $match_limit)
            {
                $expense = "Match usec";
            }
            if($nomatch_time >= $nomatch_limit)
            {
                $expense = "Non-match usec";
            }
            if($pct_time >= $pct_limit)
            {
                $expense = "Percent of CPU";
            }
            if(defined($expense))
            {
                my $rule;
                if($output_mode eq "text")
                {
                    print "$rule_profile->{gid}:$rule_profile->{sid}: $disp_output2\n";
                #    print "Expensive rule $rule_profile->{gid}:$rule_profile->{sid} ($expense): $disp_output\n";
                }
                elsif($output_mode eq "csv")
                {
                    print "$key, $expense, $rule_profile->{gid}, $rule_profile->{sid}, $disp_output\n";
                }   
            }
        }
    }

    return 1;
}

sub _printHeader
{
    my ($output_mode, $output) = @_;
    if($output_mode eq "text" && !$headerPrinted)
    {
        print "Output from $output->{pid}\n";
        $headerPrinted++;
    }
}

sub _optionalFilter
{
    return if (!$opts{threshold} && !$opts{"min-percent"});

    if (!$opts{threshold})
    {
        $opts{threshold} = 100000;
    }

    my $fp = shift;

    if ($opts{threshold})
    {
        for my $i ("tcp","udp")
        {
            if ($opts{$i})
            {
                my $max = $opts{threshold};
                my $portByPercentage = {};
                
                while (my ($k, $v) = each %{$fp->{$i}})
                {
                    $portByPercentage->{$v->{total}} = $k;
                }

                $fp->{$i} = {};
                $max = scalar keys %$portByPercentage if (scalar keys %$portByPercentage < $max);

                my $count = 0;

                for (sort {$b <=> $a} (keys %$portByPercentage))
                {
                    next if ($opts{"min-percent"} && $_ < $opts{"min-percent"} );
                    $fp->{$i}{$portByPercentage->{$_}}{total} = "$_";
                    $count++;
                    last if ($count >= $max);
                }
            }
        }
        for my $i ("icmp","bytes")
        {
            if ($opts{$i})
            {
                my $max = $opts{threshold};
                my $typeByPercentage = {};
                
                while (my ($k, $v) = each  %{$fp->{$i}})
                {
                    $typeByPercentage->{$v} = $k;
                }

                $fp->{$i} = {};
                $max = scalar keys %$typeByPercentage if (scalar keys %$typeByPercentage < $max);

                my $count = 0;

                for (sort {$b <=> $a} (keys %$typeByPercentage))
                {
                    next if ($opts{"min-percent"} && $_ < $opts{"min-percent"} );
                    $fp->{$i}{$typeByPercentage->{$_}} = "$_";
                    $count++;
                    last if ($count >= $max);
                }
            }
        }
    }    
}
