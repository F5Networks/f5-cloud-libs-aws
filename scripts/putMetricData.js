var Aws = require('aws-sdk');
var options = require('commander');


/*
 M A I N  S E C T I O N
 */

options.logLevel = 'info';
options
    .version('0.1.0')

    .option('--metricName [type]', 'MetricName')
    .option('--namespace [type]', 'Namespace')
    .option('--timestamp [type]', 'Timestamp')
    .option('--dimensions [type]', 'Dimensions')
    .option('--statisticValues [type]', 'StatisticValues')
    .option('--region [type]', 'Region')
    // .option('-o, --output <file>', 'Log to file as well as console. This is the default if background process is spawned. Default is ' + DEFAULT_LOG_FILE)
    // .option('--log-level <level>', 'Log level (none, error, warn, info, verbose, debug, silly). Default is info.')
    .parse(process.argv);


// console.log('DEFAULT_LOG_FILE if -o option = ' + DEFAULT_LOG_FILE + '\n.');
// clusterAction = options.cluster_action || 'update';  // set default for clusterAction to "update". The other is "join"

console.log(options.metricName);
console.log(options.namespace);
console.log(options.timestamp);
console.log(options.statisticValues);
console.log(options.region);

// AWS related global settings needed before initiating AWS objects
//Aws.config.update({region: obj.nodeProperties.region});
Aws.config.update({region: options.region});

var cloudwatch = new Aws.CloudWatch();
var params;
var d, dName, dValue;

if (options.dimensions) {
    console.log(options.dimensions);  // debug
    d = options.dimensions.split("=");
    console.log(d[0]);  // debug
    console.log(d[1]);  // debug
    params = {
      MetricData: [ /* required */
        {
          MetricName: options.metricName, /* required */
          Dimensions: [
            {
              Name: d[0], /* required */
              Value: d[1] /* required */
            },
            /* more items */
          ],
          StatisticValues: {
            Maximum: options.statisticValues, /* required */
            Minimum: options.statisticValues, /* required */
            SampleCount: 1, /* required */
            Sum: options.statisticValues /* required */
          }
          // Timestamp: options.timestamp
          // Unit: 'Seconds | Microseconds | Milliseconds | Bytes | Kilobytes | Megabytes | Gigabytes | Terabytes | Bits | Kilobits | Megabits | Gigabits | Terabits | Percent | Count | Bytes/Second | Kilobytes/Second | Megabytes/Second | Gigabytes/Second | Terabytes/Second | Bits/Second | Kilobits/Second | Megabits/Second | Gigabits/Second | Terabits/Second | Count/Second | None',
          // Value: 0.0
        },
        /* more items */
      ],
      Namespace: options.namespace /* required */
    };
} else {
    params = {
      MetricData: [ /* required */
        {
          MetricName: options.metricName, /* required */
          // Dimensions: [
          //   {
          //     Name: 'STRING_VALUE', /* required */
          //     Value: 'STRING_VALUE' /* required */
          //   },
          //   /* more items */
          // ],
          StatisticValues: {
            Maximum: options.statisticValues, /* required */
            Minimum: options.statisticValues, /* required */
            SampleCount: 1, /* required */
            Sum: options.statisticValues /* required */
          }
          // Timestamp: options.timestamp
          // Unit: 'Seconds | Microseconds | Milliseconds | Bytes | Kilobytes | Megabytes | Gigabytes | Terabytes | Bits | Kilobits | Megabits | Gigabits | Terabits | Percent | Count | Bytes/Second | Kilobytes/Second | Megabytes/Second | Gigabytes/Second | Terabytes/Second | Bits/Second | Kilobits/Second | Megabits/Second | Gigabits/Second | Terabits/Second | Count/Second | None',
          // Value: 0.0
        },
        /* more items */
      ],
      Namespace: options.namespace /* required */
    };

}



cloudwatch.putMetricData(params, function(err, data) {
  if (err) console.log(err, err.stack); // an error occurred
  else     console.log('DATA ', data);           // successful response
});


// var params = {
//   MetricData: [ /* required */
//     {
//       MetricName: 'STRING_VALUE', /* required */
//       Dimensions: [
//         {
//           Name: 'STRING_VALUE', /* required */
//           Value: 'STRING_VALUE' /* required */
//         },
//         /* more items */
//       ],
//       StatisticValues: {
//         Maximum: 0.0, /* required */
//         Minimum: 0.0, /* required */
//         SampleCount: 0.0, /* required */
//         Sum: 0.0 /* required */
//       },
//       Timestamp: new Date || 'Wed Dec 31 1969 16:00:00 GMT-0800 (PST)' || 123456789,
//       Unit: 'Seconds | Microseconds | Milliseconds | Bytes | Kilobytes | Megabytes | Gigabytes | Terabytes | Bits | Kilobits | Megabits | Gigabits | Terabits | Percent | Count | Bytes/Second | Kilobytes/Second | Megabytes/Second | Gigabytes/Second | Terabytes/Second | Bits/Second | Kilobits/Second | Megabits/Second | Gigabits/Second | Terabits/Second | Count/Second | None',
//       Value: 0.0
//     },
//     /* more items */
//   ],
//   Namespace: 'STRING_VALUE' /* required */
// };

