#!/bin/bash
# Developed by Brian Laskowski
# laskowski-tech.com

#create color vars
yell='\e[33m'
gre='\e[32m'
whi='\e[0m'
div1="==========="
div2="==="
month=$(date | awk '{print$2}')
pmonth=$(date '+%b' --date '1 month ago')

#ioccheck () {
#	if [[ -s $(grep 103.53.197.172 /tmp/drupalchk 2> /dev/null) ]]; then echo -e "$gre $div2 positive IOC found $div2 $yell"
			#grep 103.53.197.172 /tmp/drupalchk
		        #echo -e "$gre crypo-jacking campaign "
			#echo -e "https://badpackets.net/large-cryptojacking-campaign-targeting-vulnerable-drupal-websites/"
#		}

#Check for Environment
if [[ -x $(which whmapi1) ]]; then #Cpanel

sleep 1
echo "$div2 Cpanel Detected $div2"
sleep 1

#start menu
	while true
	do 
	clear

	echo $div1$div1$div1$div1
	echo $div2 Drupalgedon Log Scanner $div2
	echo Tool to help analyst find compromises
	echo of Drupal sites vunerable to CVE-2018-7600
	echo $div1$div1$div1$div1
	echo
	echo "Enter 1 to Scan current logs"
	echo
	echo "Enter 2 to Scan Current Montly Logs"
	echo 
	echo "Enter 3 to Scan Prior Month Logs"
	echo
	echo "Enter 4 to exit"

read answer
#start options
case "$answer" in

	1) echo -e "$gre $div2 Scanning Current Apache logs $div2 $yell"
		echo
		grep -R 'system&name' /usr/local/apache/domlogs/ 1> /tmp/drupalchk 2> /dev/null
		grep -R 'q=user%2Fpassword&name%5B%23post_render%5D%5B%5D=passthru&name' /usr/local/apache/domlogs/ 1>> /tmp/drupalchk 2> /dev/null
		cat /tmp/drupalchk | awk '$9 ~ 200 && $6 ~ /POST/ { print }' 
		echo -e "$gre $div2 IP's possibly involved in exploting Drupal sites $div2 $yell"
		cat /tmp/drupalchk | cut -d : -f 2 | sort | uniq -c | sort 
		#Testing Purposes#cat /tmp/drupalchk | cut -d : -f 3 | sort | uniq -c | sort
		echo -e "$gre $div2 Sites thst may have been compromised $div2 $yell"
		cat /tmp/drupalchk | cut -d '/' -f 6 | sort | uniq | cut -d : -f1 | uniq
#		ioccheck
                #Testing Purpsoes#cat /tmp/drupalchk | cut -d '/' -f 11 | sort | uniq | cut -d : -f1 | uniq

	;;

	2) echo -e "$yell $div2 Scanning Current Month logs $div2"
		zgrep 'system&name' /home/*/logs/*-$month-2018.gz 1> /tmp/drupalchk2 2> /dev/null
		zgrep 'q=user%2Fpassword&name%5B%23post_render%5D%5B%5D=passthru&name' /home/*/logs/*-$month-2018.gz 1>> /tmp/drupalchk2 2> /dev/null
                cat /tmp/drupalchk2 | awk '$9 ~ 200 && $6 ~ /POST/ { print }' 
                echo -e "$gre $div2 IP's possibly involved in exploting Drupal sites $div2 $yell"
                cat /tmp/drupalchk2 | cut -d : -f 2 | sort | uniq -c | sort 
                #Testing pursposes#cat /tmp/drupalchk2 | cut -d : -f 3 | sort | uniq -c | sort
                echo -e "$gre $div2 Sites thst may have been compromised $div2 $yell"
                cat /tmp/drupalchk2 | cut -d '/' -f 5 | sort | uniq | cut -d : -f1 | uniq
#                ioccheck
		#Testing purposes#cat /tmp/drupalchk2 | cut -d '/' -f 11 | sort | uniq | cut -d : -f1 | uniq
	;;
	
	3) echo -e "$yell $div2 Scanning Current Month logs $div2"
                zgrep 'system&name' /home/*/logs/*-$pmonth-2018.gz 1> /tmp/drupalchk2 2> /dev/null
		zgrep 'q=user%2Fpassword&name%5B%23post_render%5D%5B%5D=passthru&name' /home/*/logs/*-$pmonth-2018.gz 1>> /tmp/drupalchk2 2> /dev/null
                cat /tmp/drupalchk2 | awk '$9 ~ 200 && $6 ~ /POST/ { print }' 
                echo -e "$gre $div2 IP's possibly involved in exploting Drupal sites $div2 $yell"
                cat /tmp/drupalchk2 | cut -d : -f 2 | sort | uniq -c | sort 
                #Testing Purposes#cat /tmp/drupalchk2 | cut -d : -f 3 | sort | uniq -c | sort
                echo -e "$gre $div2 Sites thst may have been compromised $div2 $yell"
                cat /tmp/drupalchk2 | cut -d '/' -f 5 | sort | uniq | cut -d : -f1 | uniq
#		ioccheck
                #Testing purposes#cat /tmp/drupalchk2 | cut -d '/' -f 11 | sort | uniq | cut -d : -f1 | uniq
 
	;;

	4) rm /tmp/drupalchk  2> /dev/null
	   rm /tmp/drupalchk2 2> /dev/null
		exit ;;

esac
printf "%b" $whi
echo  "Enter to return to the menu"
	read input
done

#Part 2 of Environment check goes to Apache Defaults if cpanel isn't there
else 
sleep 1
echo "$div2 Not Cpanel Assuming Apache Defaults $div2"
sleep 1
while true
do
clear

        echo $div1$div1$div1$div1
        echo $div2 Drupalgedon Log Scanner $div2
        echo Tool to help analyst find compromises
        echo of Drupal sites vunerable to CVE-2018-7600
        echo $div1$div1$div1$div1
        echo
        echo "Enter 1 to Scan current logs"
	echo 
	echo "Enter 2 to exit"
read answer2
#start options
case "$answer2" in
	
	       1) echo -e "$gre $div2 Scanning Current Apache logs $div2 $yell"
                echo
                grep -R 'system&name' /var/log/apache2/access.log* 1> /tmp/drupalchk 2> /dev/null
                cat /tmp/drupalchk | awk '$9 ~ 200 && $6 ~ /POST/ { print }' 
                echo -e "$gre $div2 IP's possibly involved in exploting Drupal sites $div2 $yell"
                cat /tmp/drupalchk | cut -d : -f 2 | sort | uniq -c | sort
#	        ioccheck	
	;;
	
		2) rm /tmp/drupalchk 2> /dev/null
                   rm /tmp/drupalchk2 2> /dev/null
			exit ;;

esac
printf "%b" $whi
echo  "Enter to return to the menu"
        read input
done


fi
