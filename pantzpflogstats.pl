#!/usr/bin/perl -s

# This perl script generates some stats (in html format) for OpenBSD's firewall
# PF. It was made with a home firewall in mind. One that has a default block
# in policy. Which means any packets hitting the firewall inbound that were
# not allowed by other rules or not part of another connection don't belong.
# These are the ones we want to see. Most likely these have malicious intent.

# The stats are generated from the binary formated PF logs. OpenBSD's
# implementation of Tcpdump is the only Tcpdump that can read this log. This
# script was tested on an OpenBSD 4.2 machine with the version of PF and
# Tcpdump that comes with 4.2. The script only does TCP and UDP stats
# currently. Also, it only does stats for block in rules and only for
# destination ports and source IP addresses.

# The external programs needed to run this script are: Tcpdump (OpenBSD's
# version), gzcat, and of course Perl. The "host" program is need if you want
# to do hostname lookups. All programs mentioned come with OpenBSD by default.
# You will also need to run this script as root because the permissions on
# the pflog files can only be read by root.

# I have recently tested this script on FreeBSD 6.3 successfully. The
# only thing to watch out for is FreeBSD compresses it's logfiles using 
# bzip2 by default. You will need to change the gzcat line in the script
# to bzcat for it to work. FreeBSD's Tcpdump was modified to work with PF.

# I welcome any additions or added features to the script just send them to
# webmaster at pantz dot org. This code is free to distribute as long as credit
# is given to the website (pantz.org) in the modified code.

use Time::Local;
use Geo::IP;

################################
# Start Configuration Settings #
################################

# You can set any variable below on the command line in the form of: -[variable]=[value]
# Example:  -interface=em0   would set the $interface variable to 'em0'.
# Arrays (begin with @) can't be set from command line.
# Command line settings overides variables set below.

# Interface to be evaluated (usually the external network interface).
$interface = "vlan" unless $interface;

# Path to output html file.
$pfhtmlfile = "/var/www/htdocs/pfhtmlstats.html" unless $pfhtmlfile;

# Analyze one file in the dir or all files.
# Set to "one" for one file.
# Set to "all" for all pf files (even compressed ones)
# in the /var/log dir that start with  name "pflog".
$oneorallfiles = "all" unless $oneorallfiles;

# Full path to a single pflog file you want analyzed (compressed or uncompressed).
# Used if var above is set to "one". Example: /home/user/pflog.0.gz
$pflogfile = "/var/log/pflog" unless $pflogfile;

# Set to "exclude" to exclude only certain ports in stats output.
# "include" to include only certian ports in stats output.
# "off" to show all ports in stats output.
$exclude_include_ports = "off" unless $exclude_include_ports;

# Port list (array) for the above setting. For ranges use ".." in between the # range.
# Example of ports 1 thru 10 and 22 and 30 would be: 1..10,22,30
@in_ex_clude_ports = (99..100);

# Threshold values. Will not show or count "# of blocks in" totals from a host
# to a port or ip at or below the value set. Ex. Set to 10. No port or ip hit
# count (per host) that totaled 10 or below is counted.
$src_ip_threshold_value = 0 unless $src_ip_threshold_value;
$src_port_threshold_value = 0 unless $src_port_threshold_value;

# Set to "on" to have hostnames instead of ip's in the output. Set to "off" for just ip addresses.
# If this is turned on the script will take longer to run. Depending on the ammout of unique hosts.
$hostname_lookup = "off" unless $hostname_lookup;

# Filter by date? Settings are: Yes or No.
$date_filter = "no" unless $date_filter;

# Type of filter. Specific date range, current date and time run (now) backwards, or end of the current day backwards.
# Settings are: range, now, or curday.
$filter_type = "now" unless $filter_type;

# If now filter then set Units of time. Settings are: sec, min, hour, or day.
$time_unit = "hour" unless $time_unit;

# Amount of time units. How far back from now or end of current day? Whole number.
$time_amount = "12" unless $time_amount;

# If filtering by date range then specify date range. Form: YearMonthDayHourMinSec.
# Pad all single digits with zero. Ex 5 becomes 05.
# December 6th, 2006 20:05:01 would be: 20061206200501.
$lower_date = 20070205000000 unless $lower_date;
$upper_date = 20070206235959 unless $upper_date;

# GeoIP Variables
# 
$geoipdat = "/usr/local/share/GeoIP/GeoIP.dat" unless $geoipdat;

##############################
# End Configuration Settings #
##############################

#####Begin: Assembling date/time code.#####
$curtimeformat = format_epoch(time);
my $gi = Geo::IP->open($geoipdat, GEOIP_STANDARD);

if ($date_filter eq "yes") {
  if ($filter_type eq "range") {
    ($low_year,$low_month,$low_day,$low_hour,$low_min,$low_sec) = ($lower_date =~ /(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})/);
    ($up_year,$up_month,$up_day,$up_hour,$up_min,$up_sec) = ($upper_date =~ /(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})/);
    # timelocal, it expects values with the same range as those which localtime returns.
    # Namely, months start at 0, and years need 1900 subtracted from them.
    $low_year -= 1900;
    $low_month -= 1;
    $up_year -= 1900;
    $up_month -= 1;
    # DMYHMS to epoch seconds corrected for year and month -1900 and -1 respectively.
    $low_epochsec = timelocal($low_sec, $low_min, $low_hour, $low_day, $low_month, $low_year);
    $up_epochsec = timelocal($up_sec,$up_min,$up_hour,$up_day,$up_month,$up_year);
  } elsif ($filter_type eq "now") {
    $up_epochsec = timelocal(localtime(time));
    calc_low_epoch_sec();
  } elsif ($filter_type eq "curday") {
    ($cur_second, $cur_minute,$cur_hour,$cur_Day,$cur_month,$cur_year) = localtime(time);
    $up_epochsec = timelocal(($cur_second, $cur_minute,$cur_hour,$cur_Day,$cur_month,$cur_year) = (59,59,23,$cur_Day,$cur_month,$cur_year));
    calc_low_epoch_sec();
  } else {
    die ("Date filter was requested but no filter type matched. Check your date filter type.");
  }
}

#####End: Assembling date/time code.#####

#####Begin: Get one or all pflog filenames.#####
if ($oneorallfiles eq "all") {
  @pflogfilenames = </var/log/pflog*>;
  if ($date_filter eq "yes") {
    foreach $pflogfilesstat (@pflogfilenames) {
      ($dev,$ino,$mode,$nlink,$uid,$gid,$rdev,$size,$atime,$mtime,$ctime,$blksize,$blocks) = stat $pflogfilesstat;
      # Don't open log files with dates not in our date range. Using last modify time on log file as date.
      if ( $mtime >= $low_epochsec ) {
        push(@newpflogfilenames, "$pflogfilesstat");
      }
    }
    @pflogfilenames = @newpflogfilenames;
  }
  @pflogfilenames = sort { $b cmp $a } @pflogfilenames;
} else {
  push(@pflogfilenames, "$pflogfile");
}
#####End: Get one or all pflog filenames.#####

#####Begin: Reading pflog file(s) and inputing data for sorting and minipulation.#####

foreach $pflogfilename (@pflogfilenames) {
open(IN, "gzcat -f $pflogfilename | tcpdump -nettqr - 2>&1 |") or die ("Can't open file. Permissions?");
  $isfirstline = 0;
  while( <IN> ) {

    ($line_date,$line_points,$line_rulenum,$line_action,$line_interface,$line_src_host,$line_src_port,$line_dst_host,$line_dst_port,$line_remainder)
    = ($_ =~ /(\d+)\.(\d+) rule (\d+).*\(match\)\:?? (\w+ \w+) \w+ (\w+)\: (\d+\.\d+\.\d+\.\d+)\.(\d+) > (\d+\.\d+\.\d+\.\d+)\.(\d+)\:(.*)/);

    # If line had no match with date it is probably no good. Go to next line. When a line finally matches increase by one.
    next unless $line_date;
    $isfirstline++;

    # Get date from first and last line of each file. Put in array.
    if ($isfirstline == "1" || eof(IN)) { push(@date_array, "$line_date"); }

    next unless (/block in/ && /$interface/);
    $exclude_include_port_match = "no";

    # If using date filter go to the next log line if date does not fall within set filters.
    if ($date_filter eq "yes") {
        next unless ($line_date >= $low_epochsec && $line_date <= $up_epochsec)
    }
    if ($line_remainder =~ /tcp/) {
      if ($exclude_include_ports ne "off") {
        foreach $exin_ports (@in_ex_clude_ports) {
          if ($exin_ports eq $line_dst_port) {
            $exclude_include_port_match = "yes";
          }
        }
        if (($exclude_include_port_match eq "yes") && ($exclude_include_ports eq "include")) {
          push_tcp();
          next;
        }
        if (($exclude_include_port_match eq "no") && ($exclude_include_ports eq "exclude")) {
          push_tcp();
          next;
        }
      } else {
        push_tcp();
        next;
      }
    }
    if ($line_remainder =~ /udp/) {
      if ($exclude_include_ports ne "off") {
        foreach $exin_ports (@in_ex_clude_ports) {
          if ($exin_ports eq $line_dst_port) {
            $exclude_include_port_match = "yes";
          }
        }
        if (($exclude_include_port_match eq "yes") && ($exclude_include_ports eq "include")) {
          push_udp();
          next;
        }
        if (($exclude_include_port_match eq "no") && ($exclude_include_ports eq "exclude")) {
          push_udp();
          next;
        }
      } else {
        push_udp();
        next;
      }
    }
    #if ($line_remainder =~ /icmp/) {
    #  push_icmp();
    #}
  }
close(IN);
}

#####End: Reading pflog file(s) and inputing data for sorting and minipulation.#####

#####Begin: Output of HTML file.#####

open(PFHTMLSTATS, ">$pfhtmlfile") or die ("Can't create html file");

print PFHTMLSTATS qq{
<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01//EN" "http://www.w3.org/TR/html4/strict.dtd">
<html><head><title>Pantz PFlog Stats</title>
<meta http-equiv="content-type" content="text/html;charset=utf-8">
</head>
<body style="text-align: center;">
<h2>Pantz PFlog Stats</h2>
};

print PFHTMLSTATS "<p>Log file Data from " . format_epoch($date_array[0]) . " to " . format_epoch($date_array[-1]) . "<br></p>\n";

if ($date_filter eq "yes") {
  print PFHTMLSTATS "<p>Showing data from " . format_epoch($low_epochsec) . " to " . format_epoch($up_epochsec) . "<br></p>\n";
}

print PFHTMLSTATS qq {
<p>Script run on: $curtimeformat <br></p>
<TABLE BORDER="0">
<tr><td valign="top">
<TABLE BORDER="1">
};

# Create host totals. Hash of hash. With threshold evaluation. Lookup host name if set. Sort most to least hits.
for $tcud_src_hstct_key ( keys %tcud_src_hstct ) {
  for $tcud_src_hst_dst_portct_key ( keys %{ $tcud_src_hstct{$tcud_src_hstct_key} } ) {
    # Check if our totals meet the threshold set. If so add it to a total for that ip.
    if ($tcud_src_hstct{$tcud_src_hstct_key}{$tcud_src_hst_dst_portct_key} > $src_ip_threshold_value) {
      $porthitcount += $tcud_src_hstct{$tcud_src_hstct_key}{$tcud_src_hst_dst_portct_key};
    }
  }
  # Lookup hostname if var set. Else set to host's ip.
  if ($hostname_lookup eq "on") {
    hostnamelookup ($tcud_src_hstct_key);
  } else {
    $key_hostname = "$tcud_src_hstct_key";
  }
  # Make hash of arrays. IP, hostname, and hit count. Only if we met thresholds.
  if ($porthitcount != 0) {
    $tcud_src_hst_tot_ct{$tcud_src_hstct_key} = [$key_hostname,$porthitcount];
  }
  $porthitcount = 0;
}

# Print heading line with hostname if var is set. If not just print the ip heading line.
if ($hostname_lookup eq "on") {
  print PFHTMLSTATS "<tr><td><b>Hostname</b></td><td><b>Source IP</b></td>
                     <td><b># of blocks in</b></td><td><b>Country</b></td></tr>\n";
} else {
  print PFHTMLSTATS "<tr><td><b>Source IP</b></td><td><b># of blocks in</b></td>
                    <td><b>Country</b></td></tr>\n";
}

# Print hostname, ip, and count if hostname var is set. Otherwise just print ip and count lines.
for $print_tot_src_ip_key1 ( sort {  $tcud_src_hst_tot_ct{$b}[1] <=> $tcud_src_hst_tot_ct{$a}[1] }  keys %tcud_src_hst_tot_ct ) {
  my $ip = $print_tot_src_ip_key1;
  my $country = $gi->country_name_by_addr($ip);
  my $flag = lc($gi->country_code_by_addr($ip));
  if ($hostname_lookup eq "on") {
    print PFHTMLSTATS "<tr><td>$tcud_src_hst_tot_ct{$print_tot_src_ip_key1}[0]</td>
                       <td><a href=\"#IP:$print_tot_src_ip_key1\">$print_tot_src_ip_key1</a>
                       </td><td>$tcud_src_hst_tot_ct{$print_tot_src_ip_key1}[1]</td>
                       <td><img src='flag/png/$flag.png'>$country</td></tr>\n";
  } else {
    print PFHTMLSTATS "<tr><td><a href=\"#IP:$print_tot_src_ip_key1\">$print_tot_src_ip_key1</a></td>
                       <td>$tcud_src_hst_tot_ct{$print_tot_src_ip_key1}[1]</td>
                       <td><img src='flag/png/$flag.png'>$country</td></tr>\n";
  }
}

print PFHTMLSTATS qq{
</table>
</td> <td></td> <td valign="top">
<TABLE BORDER="1">
<tr><td><b>Destination Port</b></td><td><b># of blocks in</b></td></tr>
};

# Create destination port totals. Hash of hash. With threshold evaluation. Sort most to least hits.
for $tcud_dst_portct_key1 ( keys %tcud_dst_portct ) {
  # Check if our totals meet the threshold set. If so add it to a total for that port.
  for $tcud_dst_portct_key2 ( keys %{ $tcud_dst_portct{$tcud_dst_portct_key1} } ) {
    if ($tcud_dst_portct{$tcud_dst_portct_key1}{$tcud_dst_portct_key2} > $src_port_threshold_value) {
      $iphitperportcount += $tcud_dst_portct{$tcud_dst_portct_key1}{$tcud_dst_portct_key2};
    }
  }
  # Create hash of ip and port count. Only if we met thresholds.
  if ($iphitperportcount != 0) {
    $tcud_dst_port_tot_ct{$tcud_dst_portct_key1} = $iphitperportcount;
  }
  $iphitperportcount = 0;
}

# Print the hash from most to least port hits.
foreach $print_tot_dst_port_key (sort { $tcud_dst_port_tot_ct {$b} <=> $tcud_dst_port_tot_ct {$a} } keys %tcud_dst_port_tot_ct) {
  print PFHTMLSTATS "<tr><td><a href=\"#PORT:$print_tot_dst_port_key\">$print_tot_dst_port_key</a></td>
                     <td>$tcud_dst_port_tot_ct{$print_tot_dst_port_key}</td></tr>\n";
}

print PFHTMLSTATS qq {\n</table>\n</td></tr>\n</table>\n\n<p><br><br></p><hr><p><br><br></p>};

$hostportcount = 4;
$hostporttablerowcount = 4;
$was_anything_printed = 0;

print PFHTMLSTATS "\n\n<TABLE BORDER=\"0\">\n\n";

# Start looping thru hash of hash. Print tables if thresholds were met.
for $tcud_src_hstct_key ( keys %tcud_src_hstct ) {
  # Start a new row if our counter is reset.
  if ($hostportcount == $hostporttablerowcount) {
    print PFHTMLSTATS "<tr valign=\"top\">\n\n";
    $hostportcount = 0;
  }
  for $tcud_src_hst_dst_portct_key (sort { $tcud_src_hstct{$tcud_src_hstct_key}{$b} <=> $tcud_src_hstct{$tcud_src_hstct_key}{$a} } keys %{ 
$tcud_src_hstct{$tcud_src_hstct_key} } ) {
    # Check if threshold is met for total host ip hits to a port.
    if ($tcud_src_hstct{$tcud_src_hstct_key}{$tcud_src_hst_dst_portct_key} > $src_ip_threshold_value) {
      # Trip the counter if threshold was met.
      $was_anything_printed++;
      # If this is our first time through and we met the threshold print the table heading.
      if ($was_anything_printed == 1) {
        my $ip = $tcud_src_hstct_key;
        my $country = $gi->country_name_by_addr($ip);
        my $flag = lc($gi->country_code_by_addr($ip));
        print PFHTMLSTATS "<td><TABLE BORDER=\"1\">\n";
        print PFHTMLSTATS "<tr><td colspan=\"2\"><a name=\"IP:$tcud_src_hstct_key\"></a>
                           <a href=\"https://who.is/whois-ip/ip-address/$tcud_src_hstct_key\" target=\"_new\">
                           <b>$tcud_src_hstct_key</b></a><img src='flag/png/$flag.png'>$country</td></tr>
                           <tr><td><b>Destination Port</b></td><td> <b># of blocks in</b></td></tr>\n";
      }
      # Print a table row.
      print PFHTMLSTATS "<tr><td><a href=\"http://isc.sans.org/port_details.php\?port=$tcud_src_hst_dst_portct_key\">
                         $tcud_src_hst_dst_portct_key</a></td><td>
                         $tcud_src_hstct{$tcud_src_hstct_key}{$tcud_src_hst_dst_portct_key}</td>
                         </tr>\n";
    }
  }

  # If something was printed at least once increase column counter. Close our table.
  if ($was_anything_printed > 0) {
    $hostportcount++;
    print PFHTMLSTATS "</table></td><td> </td>\n\n";
  }
  # If host port counter has it its max (set above) close the whole row.
  if ($hostportcount == $hostporttablerowcount) {
    print PFHTMLSTATS "</tr><tr><td> </td></tr>\n\n";
  }
  $was_anything_printed = 0;
}

# If hash ended before row finished then close it.
if ($hostportcount < $hostporttablerowcount) {
  print PFHTMLSTATS "<td> </td></tr>\n";
}


print PFHTMLSTATS "\n</table>\n\n<p><br><br></p><hr><p><br><br></p>\n";

$porthostcount = 4;
$porthosttablerowcount = 4;
$was_anything_printed = 0;

print PFHTMLSTATS "\n\n<TABLE BORDER=\"0\">\n";

for $tcud_dst_portct_key3 ( keys %tcud_dst_portct ) {
  # Start a new row if our counter is reset
  if ($porthostcount == $porthosttablerowcount) {
    print PFHTMLSTATS "<tr valign=\"top\">\n\n";
    $porthostcount = 0;
  }
  for $tcud_dst_portct_key4 (sort { $tcud_dst_portct{$tcud_dst_portct_key3}{$b} <=> $tcud_dst_portct{$tcud_dst_portct_key3}{$a} } keys 
%{$tcud_dst_portct{$tcud_dst_portct_key3} } ) {
    # Check if threshold is met for total host port hits to a ip.
    if ($tcud_dst_portct{$tcud_dst_portct_key3}{$tcud_dst_portct_key4} > $src_port_threshold_value) {
      # Trip the counter if threshold was met.
      $was_anything_printed++;
      # If this is our first time through and we met the threshold print the table heading.
      if ($was_anything_printed == 1) {
        print PFHTMLSTATS "<td><TABLE BORDER=\"1\">\n";
        print PFHTMLSTATS "<tr><td colspan=\"2\"><b><a name=\"PORT:$tcud_dst_portct_key3\"></a>
                           <a href=\"http://isc.sans.org/port_details.php\?port=$tcud_dst_portct_key3\">
                           $tcud_dst_portct_key3</a></b></td></tr><tr><td><b>Source IP</b></td>
                           <td> <b># of blocks in</b></td></tr>\n";
      }
      # Print a table row.
      print PFHTMLSTATS "<tr><td><a href=\"https://who.is/whois-ip/ip-address/$tcud_dst_portct_key4\" target=\"_new\">
                         $tcud_dst_portct_key4</a></td><td>
                         $tcud_dst_portct{$tcud_dst_portct_key3}{$tcud_dst_portct_key4}</td></tr>\n";
    }
  }
  # If something was printed increase column counter
  if ($was_anything_printed > 0) {
    $porthostcount++;
    print PFHTMLSTATS "</table></td><td> </td>\n\n";
  }
  # If host port counter has it its max (set above) close the whole row.
  if ($porthostcount == $porthosttablerowcount) {
    print PFHTMLSTATS "</tr><tr><td> </td></tr>\n\n";
  }
  $was_anything_printed = 0;
}

# If hash ended before row finished then close it.
if ($porthostcount < $porthosttablerowcount) {
  print PFHTMLSTATS "<td> </td></tr>\n\n";
}

print PFHTMLSTATS "\n</table>\n</body></html>";

close(PFHTMLSTATS);

#####End: Output of HTML file.#####

#####Start: Subroutines.#####
sub push_tcp {
  # Hash of a hash. Value is increasing counter.
  $tcud_src_hstct{$line_src_host}{$line_dst_port}++;
  $tcud_dst_portct{$line_dst_port}{$line_src_host}++;
}
sub push_udp {
  # Hash of a hash. Value is increasing counter.
  $tcud_src_hstct{$line_src_host}{$line_dst_port}++;
  $tcud_dst_portct{$line_dst_port}{$line_src_host}++;
}
sub push_icmp {
  #push(@icmp_src_hst_array, "$line_src_host");
  #push(@icmp_dst_hst_array, "$line_dst_host");
}
sub hostnamelookup {
  # Use the program "host" to do reverse lookups on ip's.
  $key_hostname = $_[0];
  $key_hostname = `host $key_hostname`;
  if ($key_hostname =~ /pointer/) {
    ($key_hostname) = ($key_hostname =~ /pointer (.*)/);
    $key_hostname = substr($key_hostname,0, -1);
  } else {
    $key_hostname = "No PTR Record";
  }
}
sub format_epoch {
  my ($fmt_second, $fmt_minute, $fmt_hour, $fmt_Day, $fmt_month, $fmt_year) = localtime($_[0]);
  $fmt_month += 1;
  $fmt_year += 1900;
  if($fmt_month < 10) { $fmt_month = "0" . $fmt_month; }
  if ($fmt_hour < 10) { $fmt_hour = "0" . $fmt_hour; }
  if ($fmt_minute < 10) { $fmt_minute = "0" . $fmt_minute; }
  if ($fmt_second < 10) { $fmt_second = "0" . $fmt_second; }
  if($fmt_Day < 10) { $fmt_Day = "0" . $fmt_Day; }
  return "$fmt_month-$fmt_Day-$fmt_year $fmt_hour:$fmt_minute:$fmt_second";
}
sub calc_low_epoch_sec {
  if ($time_unit eq "min") { $time_amount *= 60; }
  if ($time_unit eq "hour") { $time_amount *= 3600; }
  if ($time_unit eq "day") { $time_amount *= 86400; }
  return $low_epochsec = $up_epochsec - $time_amount;
}
#####End: Subroutines.#####
