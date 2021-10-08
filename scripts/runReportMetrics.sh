##############################################################################
#
# Copyright (C) 2012-2017, F5 Networks, Inc. All rights reserved.
#
# reportMetrics.sh
# Logs - reported to /var/log/cloud/aws/aws-metrics.log
#
# This script uses CloudWatch tools to report custom BIG-IP metrics
# to CloudWatch service.
# Cloudwatch service has URLs specific to each region.
# This script determines the region in which given BIG-IP runs,
# constructrs the region specific CloudWatch URL and sends metrics.
#
# Metrics are obtained by calling tmctl.
# Some metrics, like number of currently open connections, are
# reported directly, since they represent the immediate value.
#
#
# Some stats from tmctl represent 'asbolute' values, i.e. values
# which keep accumulating from the start-up time. An example of such
# value is the number of total connections: client_side_traffic.tot_conns.
# We take 2 samples for such values, with 1 second interval, to obtain
# values/per.sec.
#
# This script sets all environment variables needed to make
# a call to CloudWatch.
#
# The dependencies
#     CloudWatch tools - need to installed on the machine.
#     Inside this script AWS_CLOUDWATCH_HOME needs to set to the root of
#     CloudWatch installation directory
#
#     Credential file - set AWS_CREDENTIAL_FILE to point to
#     a file named credential-file-path.template, which contains, on separate lines:
#        AWSAccessKeyId=_your_aws_access_key
#        AWSSecretKey=_your_aws_secret_key
##############################################################################

echo "[start]---------------------------------------------------------------------" | tee /var/log/cloud/aws/aws-metrics.log
function techo () {
   date=$(/bin/date +"%H:%M:%S")
   echo "${date} $@" | tee -a /var/log/cloud/aws/aws-metrics.log
}


techo [Script start] $*

EC2_HOME=$(find /opt/aws -name "ec2-api-tools-*" -type d | sort --version-sort | tail -1)
if [[ $? != 0 ]] || [[ -z $EC2_HOME ]]; then
    logger -p local0.error "$0 : Failed to locate AWS EC2 API tools: $EC2_HOME"
    exit 1
fi
export EC2_HOME
export EC2_JVM_ARGS="-Xss256k -Xms8m -XX:+UseSerialGC"
export SERVICE_JVM_ARGS="-Xss256k -Xms8m -XX:+UseSerialGC -XX:-UseLargePages"
export PATH=$PATH:$EC2_HOME/bin
export JAVA_HOME=/usr/java/openjdk/
export PATH=$PATH:$JAVA_HOME/bin

TOKEN=`curl -sS -X PUT 'http://169.254.169.254/latest/api/token' -H 'X-aws-ec2-metadata-token-ttl-seconds: 120'`

AWS_CLOUDWATCH_HOME=$(find /opt/aws -name "cloudwatch-*" -type d | sort --version-sort | tail -1)
if [[ $? != 0 ]] || [[ -z $AWS_CLOUDWATCH_HOME ]]; then
    logger -p local0.error "$0 : Failed to locate AWS cloudwatch tools: $AWS_CLOUDWATCH_HOME"
    exit 1
fi
export AWS_CLOUDWATCH_HOME

export PATH=$PATH:$AWS_CLOUDWATCH_HOME/bin

export AWS_CREDENTIAL_FILE=$AWS_CLOUDWATCH_HOME/credential-file-path.template

export PATH=$PATH:$AWS_CREDENTIAL_FILE
#export AWS_CLOUDWATCH_URL=http://monitoring.us-east-1.amazonaws.com/
#export PATH=$PATH:$AWS_CLOUDWATCH_URL

###################################################################
# function get_stat
# returns a value of specified statistic
# param1 - name of tmctl table
# param2 name of tmctl column
###################################################################
function get_stat() {
        # param-1 is table name
        # param-2 is column name
        local table_name=$1
        local column_name=$2
        unset stat_result
        #stat_result=$(tmctl -r  $table_name -s  $column_name | grep "[0-9]")
        stat_result=$(tmctl -r -q $table_name -s  $column_name)
        #echo a=$(tmctl -r  $table_name -s  $column_name )

        # take the value of stat_result and + 0. This will evaluate the expression and return its value (same value)
        # but without any spaces.
        techo $stat_result
        stat_result=$(( $stat_result + 0 ))
        export stat_result
        techo "val=$stat_result"
}


##################################################################
# function: get_stat_delta
# description:
# Obtains a statistic from tmctl and computes delta for it over 1 second interval.
# This function is intended to be used over tmctl statistics
#  - which report the total amount of some value
#  - the value increases over time
#
# For example total number of created connections is an absolute value which only increases.
# Computing delta of it over 1 second we obtain the rate/per second.
#
# parameters:
# $1 - tmctl table name
# $2 - tmctl column name
##################################################################
function get_stat_delta() {
   # param-1 is table name
   # param-2 is column name
   local table_name=$1
   local column_name=$2
   unset stat_result1

   stat_result1=$(tmctl -q -r $table_name -s  $column_name)

   # take the value of stat_result and + 0. This will evaluate the expression and return its value (same value)
   # but without any spaces.
   techo $stat_result1
   stat_result1=$(( $stat_result1 + 0 ))
   export stat_result1
   techo "val1=$stat_result1"

   #wait 1 sec
   sleep 1

   # get second value
   unset stat_result2
   stat_result2=$(tmctl -q -r $table_name -s  $column_name)

   techo $stat_result2
   stat_result2=$(( $stat_result2 + 0 ))
   export stat_result2
   techo "val2=$stat_result2"

   unset stat_result_delta
   stat_result_delta=$(( $stat_result2 -  $stat_result1))
   techo "delta=$stat_result_delta"
   export stat_result_delta
}


function set_region() {

   techo [start]:set_region

   local zone=$(curl -s -S -H "X-aws-ec2-metadata-token: ${TOKEN}" http://169.254.169.254/latest/meta-data/placement/availability-zone/)
   #local zone=$(curl http://169.254.169.254/latest/meta-data/placement/availability-zone/)
   techo zone==$zone
   local region=$(echo $zone | sed -e "s:\([0-9][0-9]*\)[a-z]*\$:\\1:")
   techo region==$region
   unset EC2_REGION
   export EC2_REGION=$region
   techo EC2_REGION=$EC2_REGION

   techo [end]:set_region
}

############################################################
# function send_cpu_stat
# param 1 - name of tmctl table
# param 2 - name of column
############################################################

function send_cpu_stat()
{
  techo [start]:send_cpu_stat
  techo [input]$*

  # make sure auto-scale group name is present
  check_auto_scale_group

  total=0
  count=0
  mkfifo tpipe
  tmsh show sys tmm-info|grep "Last 1 Minute" > tpipe &
  while read -r var1 var2 var3 var4
  do
    total=$(($total+$var4))
    count=$((count + 1))
    echo $var4
  done < tpipe

  stat_result=$((total / count))
  echo "Number of TMMs: $count"
  echo "percent: $stat_result"

  f5-rest-node /config/cloud/aws/node_modules/@f5devcentral/f5-cloud-libs-aws/scripts/putMetricData.js --metricName $2 --namespace $VE_AUTO_SCALE_GROUP_NAME --timestamp $(date --iso-8601=seconds) --statisticValues $stat_result --region $EC2_REGION
  #mon-put-data --metric-name $2 --namespace $VE_AUTO_SCALE_GROUP_NAME --timestamp $(date --iso-8601=seconds) --statisticValues --value $stat_result --region $EC2_REGION

  f5-rest-node /config/cloud/aws/node_modules/@f5devcentral/f5-cloud-libs-aws/scripts/putMetricData.js --metricName $2 --namespace $VE_AUTO_SCALE_GROUP_NAME --timestamp $(date --iso-8601=seconds) --statisticValues $stat_result --dimensions "instance-id=$inst_id" --region $EC2_REGION
  #mon-put-data --metric-name $2 --namespace $VE_AUTO_SCALE_GROUP_NAME --timestamp $(date --iso-8601=seconds) --statisticValues --value $stat_result --dimensions "instance-id=$inst_id" --region $EC2_REGION
  techo [end]:send_cpu_stat
}

############################################################
# function send_stat
# param 1 - name of tmctl table
# param 2 - name of column
############################################################
function send_stat()
{
   techo [start]:send_stat
   techo [input]$*

   # make sure auto-scale group name is present
   check_auto_scale_group

   get_stat $1 $2


   f5-rest-node /config/cloud/aws/node_modules/@f5devcentral/f5-cloud-libs-aws/scripts/putMetricData.js --metricName $2 --namespace $VE_AUTO_SCALE_GROUP_NAME --timestamp $(date --iso-8601=seconds) --statisticValues $stat_result --region $EC2_REGION
   #mon-put-data --metric-name $2 --namespace $VE_AUTO_SCALE_GROUP_NAME --timestamp $(date --iso-8601=seconds) --statisticValues --value $stat_result --region $EC2_REGION

   f5-rest-node /config/cloud/aws/node_modules/@f5devcentral/f5-cloud-libs-aws/scripts/putMetricData.js --metricName $2 --namespace $VE_AUTO_SCALE_GROUP_NAME --timestamp $(date --iso-8601=seconds) --statisticValues $stat_result --dimensions "instance-id=$inst_id" --region $EC2_REGION
   #mon-put-data --metric-name $2 --namespace $VE_AUTO_SCALE_GROUP_NAME --timestamp $(date --iso-8601=seconds) --statisticValues --value $stat_result --dimensions "instance-id=$inst_id" --region $EC2_REGION
   techo [end]:send_stat
}

#############################################################
# A 1 second delta will be computed from the specified
# column value and sent to CloudWatch. This provied per second value
# for given statistic.
# param 1 - tmctl column name
# param 2 - tmctl column name
# param 3 - name under which the value will be shown in CloudWatch
#############################################################
function send_stat_delta()
{
   techo [start]:send_stat_delta
   techo [input]$*

   # make sure auto-scale group name is present
   check_auto_scale_group

   get_stat_delta $1 $2

   f5-rest-node /config/cloud/aws/node_modules/@f5devcentral/f5-cloud-libs-aws/scripts/putMetricData.js --metricName $3-per-sec --namespace $VE_AUTO_SCALE_GROUP_NAME --timestamp $(date --iso-8601=seconds) --statisticValues $stat_result_delta --region $EC2_REGION
   #mon-put-data --metric-name $3-per-sec --namespace $VE_AUTO_SCALE_GROUP_NAME --timestamp $(date --iso-8601=seconds) --statisticValues --value $stat_result_delta --region $EC2_REGION

   f5-rest-node /config/cloud/aws/node_modules/@f5devcentral/f5-cloud-libs-aws/scripts/putMetricData.js --metricName $3-per-sec --namespace $VE_AUTO_SCALE_GROUP_NAME --timestamp $(date --iso-8601=seconds) --statisticValues $stat_result_delta --dimensions "instance-id=$inst_id" --region $EC2_REGION
   #mon-put-data --metric-name $3-per-sec --namespace $VE_AUTO_SCALE_GROUP_NAME --timestamp $(date --iso-8601=seconds) --statisticValues --value $stat_result_delta --dimensions "instance-id=$inst_id" --region $EC2_REGION

   techo [end]:send_stat_delta
}

#############################################################
# param 1 - throughput value
# param 2 - name under which the value will be shown in CloudWatch
#############################################################
function send_throughput()
{
   techo [start]:send_throughput
   techo [input]$*

   # make sure auto-scale group name is present
   check_auto_scale_group

   f5-rest-node /config/cloud/aws/node_modules/@f5devcentral/f5-cloud-libs-aws/scripts/putMetricData.js --metricName $2-per-sec --namespace $VE_AUTO_SCALE_GROUP_NAME --timestamp $(date --iso-8601=seconds) --statisticValues $1 --region $EC2_REGION

   f5-rest-node /config/cloud/aws/node_modules/@f5devcentral/f5-cloud-libs-aws/scripts/putMetricData.js --metricName $2-per-sec --namespace $VE_AUTO_SCALE_GROUP_NAME --timestamp $(date --iso-8601=seconds) --statisticValues $1 --dimensions "instance-id=$inst_id" --region $EC2_REGION

   techo [end]:send_throughput
}

#############################################################
# Function get_auto_scale_group_name
# Description:
# Obtains the name of auto-scale group to which given
# big-ip device belongs to. This is done by calling
# the REST api to get the 'sys autoscale-group' setting.
# (tmsh equivalent: 'tmsh list sys autoscale-group').
# If the group ID has not been set, the REST call returns
# an empty string.
#
# Returned name will be used as a Cloudwatch 'namespace' parameter
# passed to mon-put-data, so the user would see all metrics
# related to the auto-scale group reported under a namespace
# having same name as the auto-scale group itself.
#############################################################
function get_ve_auto_scale_group_name() {
    if [ -f /config/cloud/hourly_autoscale_group ]; then
      export VE_AUTO_SCALE_GROUP_NAME=$(cat /config/cloud/hourly_autoscale_group)
    else
      export VE_AUTO_SCALE_GROUP_NAME=$(curl -s -u "admin:" -k http://localhost:8100/mgmt/tm/sys/autoscale-group \
                                        | jq -r 'select(.autoscaleGroupId != null) | .autoscaleGroupId')
    fi
    techo auto-scale-group $VE_AUTO_SCALE_GROUP_NAME
    check_auto_scale_group
}

#############################################################
# Function check_auto_scale_group
# Terminate the whole script if VE_AUTO_SCALE_GROUP_NAME
# is not set.
#############################################################
function check_auto_scale_group() {
   if [ "$VE_AUTO_SCALE_GROUP_NAME" == ""  ]; then
       techo "error: bigip-ve auto-scale group name is not available"
       logger -p local0.notice "$0 : No bigip-ve auto scale group is configured."
       exit 1
   fi
}

get_ve_auto_scale_group_name

#get_stat_delta $1 $2
set_region

export inst_id=$(curl -H "X-aws-ec2-metadata-token: ${TOKEN}" http://169.254.169.254/latest/meta-data/instance-id/ 2>/dev/null)
techo instance_id $inst_id

send_cpu_stat tmm-info tmm-stat

# client_side_traffic.cur_conns
send_stat tmm_stat client_side_traffic.cur_conns

# server_side_traffic.cur_conns
send_stat  tmm_stat server_side_traffic.cur_conns

# client_side_traffic.tot_conns
send_stat_delta tmm_stat client_side_traffic.tot_conns client_side_active_conns

# server_side_traffic.tot_conns
send_stat_delta tmm_stat server_side_traffic.tot_conns server_side_active_conns

# client_side_traffic.bytes_in
send_stat_delta tmm_stat client_side_traffic.bytes_in client_side_traffic.bytes_in
client_side_bytes_in=$stat_result_delta

# client_side_traffic.bytes_out
send_stat_delta tmm_stat client_side_traffic.bytes_out client_side_traffic.bytes_out

# server_side_traffic.bytes_in
send_stat_delta tmm_stat server_side_traffic.bytes_in server_side_traffic.bytes_in
server_side_bytes_in=$stat_result_delta

# server_side_traffic.bytes_out
send_stat_delta tmm_stat server_side_traffic.bytes_out server_side_traffic.bytes_out

echo $client_side_bytes_in
echo $server_side_bytes_in
throughput=$(($client_side_bytes_in+$server_side_bytes_in))
echo $throughput
send_throughput $throughput throughput

#mon-put-data --metric-name $3-per-sec --namespace "MyService" --timestamp $(date --iso-8601=seconds) --statisticValues --value $stat_result_delta --region $EC2_REGION

#mon-put-data --metric-name $3-per-sec --namespace "MyService" --timestamp $(date --iso-8601=seconds) --statisticValues --value $stat_result_delta --dimensions "instance-id=$inst_id" --region $EC2_REGION

techo [end] --------------------------------------------------------

exit 0
