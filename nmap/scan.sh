#!/bin/bash

set -x #(debug output)

#Help Text:
function helptext {
	echo "Usage: scan.sh [file . . .]"
	echo "Requires one argument: a file containing a line-separated list of CIDR addresses"
}

#Make sure a non-empty file is supplied as an argument:
if [ "$#" -ne 1 ]; then
	echo "ERROR: Invalid argument(s)"
	helptext >&2
	exit 1
    elif [ ! -s $1 ]; then
	echo "ERROR: CIDR file is empty"
	helptext >&2
	exit 1
fi

#Check for root privileges:
if [ "$(id -u)" != "0" ]; then
	echo "ERROR: This script must be run as root"
	helptext >&2
	exit 1
fi

#Set timestamp:
export TIMESTAMP="$(date +"%d%m%H%M")"

#Check for required packages:
if [ -z "$(dpkg-query -l | grep 'nmap')" ]; then
	apt -y install nmap
fi
wait
#Through vpn connections such as pptp, this is useless...
#if [ -z "$(dpkg-query -l | grep 'masscan')" ]; then
	#apt -y install masscan
#fi
#wait

#Make temp directory:
mkdir ./temp && chown -R 1000:1000 ./temp

#Install NSE Vulners scripts (subshell):
(
if [ ! -e /usr/share/nmap/scripts/nmap-vulners/vulners.nse ]; then
	cd /usr/share/nmap/scripts/ && git clone https://github.com/vulnersCom/nmap-vulners.git
	else
	exit 0
fi
exit
)

#Read-in list of CIDR networks from input file:
for CIDR in $(cat $1); do
    #Start masscan at host level:
	RESULTS=${CIDR:: -3}
    #masscan --open -p0-65535 --max-rate 5000 -oB ./temp/"$RESULTS".bin $CIDR; masscan --readscan ./temp/"$RESULTS".bin -oL ./temp/"$RESULTS".txt && \
	#Start masscan at docker runtime level (use with virtual adapters):
	docker run --rm -v $(pwd)/temp:/home/scan -it ilyaglow/masscan --open -p0-65535 --max-rate 5000 -oB /home/scan/"$RESULTS".bin $CIDR; docker run --rm -v $(pwd)/temp:/home/scan -it ilyaglow/masscan --readscan /home/scan/"$RESULTS".bin -oL /home/scan/"$RESULTS".txt && \
	#Concatenate results:
	cat ./temp/"$RESULTS".txt >> ./temp/masscan-output.txt
done

#If masscan file is null or empty...
if [ ! -s ./temp/masscan-output.txt ]; then
    echo -e "\nNo IPs are up; skipping nmap\n"; rm -rf ./temp; exit 1
	else
	#Consolidate IPs and open ports for each IP:
	awk '/open/ {print $4,$3,$2,$1}' ./temp/masscan-output.txt |  awk '
    	/.+/{
        	if (!($1 in Val)) { Key[++i] = $1; }
        	Val[$1] = Val[$1] $2 ",";
    		}
    	END{
        	for (j = 1; j <= i; j++) {
          	printf("%s:%s\n%s",  Key[j], Val[Key[j]], (j == i) ? "" : "\n");
        	}
    	}' | sed 's/,$//' > ./temp/discovered_hosts.txt \
    #Run in-depth nmap enumeration against discovered hosts & ports:
	for TARGET in $(cat ./temp/discovered_hosts.txt); do
    	IP=$(echo $TARGET | awk -F: '{print $1}');
        PORT=$(echo $TARGET | awk -F: '{print $2}');
        FILENAME=$(echo $IP | awk '{print "nmap_"$1}')
        nmap -vv --script nmap-vulners,smb-vuln-ms17-010 -sV --version-intensity 5 -sT --max-rate 5000 -Pn -R -T3 -p $PORT -oX ./temp/"$FILENAME".xml --reason $IP
    done
fi

#If none of detected ports are open...
if [ -z "$(cat ./temp/*.xml | grep -i 'open')" ]; then
	echo -e "\nNo ports are open; aborting\n"; rm -rf ./temp; exit 1
	else
	echo -e "\nReporting; at end check on http://localhost:5601\n"
fi

#Make data directory:
if [ ! -d ../docker-elk/_data ]; then
	mkdir -p ../docker-elk/_data/nmap
fi

#Move XML files:
for XML_FILE in `find ./temp -name *.xml`; do
	mv $XML_FILE ../docker-elk/_data/nmap/
done

#Delete all temporary files:
rm -rf ./temp

#Run ELK stack (subshell):
(
if [[ -z "$(docker ps -q -f name='kibana')" || -z "$(docker ps -q -f name='elasticsearch')" ]]; then
	cd ../docker-elk && docker-compose up -d &&	sleep 30
	else
	exit 0
fi
exit
)

#Change ownership of _data directory (subshell):
(
if [ ! "$(stat -c '%u' ../docker-elk/_data)" == "1000" ]; then
	chown -R 1000:1000 ../docker-elk/_data && sleep 30
	else
	exit 0
fi
exit
)

#Create ES index and override ignore_above mapping:
if [ ! "$(curl --write-out '%{http_code}' -s -X GET "localhost:9200/nmap-vuln-to-es" -o /dev/null)" == "200" ]; then
	curl -s -X PUT -H 'Content-Type: application/json' -d @../docker-elk/elasticsearch/template.json -v "localhost:9200/nmap-vuln-to-es"
fi
wait

#Ingest Nmap Results (subshell):
(
	cd ../docker-elk && docker-compose run ingestor ingest \
	wait \
#Delete old XML files to avoid duplications:
	rm _data/nmap/*.xml
	exit
)

#Create Kibana dashboard:
curl -s -X POST -H 'Content-Type: application/json' -H 'kbn-xsrf: true' -d @../docker-elk/kibana/dashboard/dashboard.json "localhost:5601/api/kibana/dashboards/import" && \

#Create Kibana index-pattern:
INDEX_ID="$(grep -B1 'index-pattern' ../docker-elk/kibana/dashboard/dashboard.json | grep '"id"' | sed -e 's/.*: "//' -e 's/",//')" \

generate_post_data()
{
	cat <<EOF
{"value": "$INDEX_ID"}
EOF
}
\
curl -s -X POST -H 'Content-Type: application/json' -H 'kbn-xsrf: true' -d "$(generate_post_data)" "localhost:5601/api/kibana/settings/defaultIndex"

exit
