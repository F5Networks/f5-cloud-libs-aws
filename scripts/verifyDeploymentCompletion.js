#!/usr/bin/env node

/**
 * Copyright 2018 F5 Networks, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
'use strict';

const options = require('commander');
const f5CloudLibs = require('@f5devcentral/f5-cloud-libs');
const util = f5CloudLibs.util;
const Logger = f5CloudLibs.logger;
const BigIp = f5CloudLibs.bigIp;
const cloudProviderFactory = f5CloudLibs.cloudProviderFactory;

(function run() {
    let logger;
    let instanceId;
    let bigIp;
    const runner = {
        run(argv) {
            const loggerOptions = {};
            const DEFAULT_LOG_FILE = '/var/log/cloud/aws/verifyDeploymentCompletion.log';
            options
                .version('1.0.0')
                .option(
                    '--host <host>',
                    'Hostname for BIGIP device',
                    'localhost'
                )
                .option(
                    '--user <user>',
                    'Username to access BIGIP device',
                    'admin'
                )
                .option(
                    '--password <password>',
                    'Password to access BIGIP device'
                )
                .option(
                    '--password-url <passwordUrl>',
                    'URL to password file'
                )
                .option(
                    '--password-encrypted <passwordEncrypted>',
                    'Flag indicates if password encrypted'
                )
                .option(
                    '--port <port>',
                    'Managment port on BIGIP device',
                    '8443'
                )
                .option(
                    '--solution <solution>',
                    'solution type (i.e. autoscale, faiover, standalone)'
                )
                .option(
                    '--instances-count <instancesCount>',
                    'number of instances provisioned with deployment',
                    '2'
                )
                .option(
                    '--log-level <level>',
                    'Log level (none, error, warn, info, verbose, debug, silly). Default is info.', 'info'
                )
                .option(
                    '-o, --output <file>',
                    `Log to file. Default is ${DEFAULT_LOG_FILE}`, DEFAULT_LOG_FILE
                )
                .parse(argv);

            /* eslint-enable max-len */
            loggerOptions.console = true;
            loggerOptions.logLevel = options.logLevel;
            loggerOptions.module = module;

            if (options.output) {
                loggerOptions.fileName = options.output;
            }

            logger = Logger.getLogger(loggerOptions);
            bigIp = new BigIp({ loggerOptions });
            util.setLoggerOptions(loggerOptions);
            if (!options.password && !options.passwordUrl) {
                Promise.reject(new Error('One of --password or --password-url is required.', 'error', 1));
            }
            logger.info('Starting deployment verification...');
            logger.info('When completed, the script will send signal to Cloud Formation');
            logger.silly(`options: ${JSON.stringify(options)}`);
            return bigIp.init(
                options.host,
                options.user,
                options.password || options.passwordUrl,
                {
                    port: options.port,
                    passwordIsUrl: typeof options.passwordUrl !== 'undefined',
                    passwordEncrypted: options.passwordEncrypted
                }
            )
                .then(() => {
                    logger.info('BIGIP is initialized. Checking if it is ready...');
                    return bigIp.ready();
                })
                .then(() => {
                    logger.info('Instantiating cloud provider');
                    this.provider = cloudProviderFactory.getCloudProvider('aws',
                        { logger });
                    return this.provider.init({}, options);
                })
                .then(() => {
                    logger.info('Getting instanceId');
                    return this.provider.getInstanceId();
                })
                .then((response) => {
                    logger.debug('This instance ID:', response);
                    instanceId = response;
                    logger.silly(`solution: ${options.solution}`);
                    logger.silly(`instance-count: ${options.instancesCount}`);
                    if ((options.solution === 'autoscale' || options.solution === 'failover') &&
                        parseInt(options.instancesCount, 10) !== 1) {
                        logger.info('This solution requires clustering. Verifying ...');
                        return util.tryUntil(this, util.DEFAULT_RETRY, verifySyncIsComplete);
                    } else if (options.solution === 'standalone' ||
                        parseInt(options.instancesCount, 10) === 1) {
                        logger.info('This solution does not require clustering or ' +
                            'less than 2 instances were provisioned with deployment.');
                        return Promise.resolve();
                    }
                    logger.info('Opss. The solution is unknown. Exiting...');
                    return Promise.reject(new Error('This is not known solution. Exiting.'));
                })
                .then(() => {
                    logger.info('Sending DONE signal to CloudFormation.');
                    return this.provider.signalInstanceProvisioned(instanceId);
                })
                .then((signalResponse) => {
                    logger.info(`Signal response: ${JSON.stringify(signalResponse)}`);
                    return Promise.resolve();
                })
                .catch((err) => {
                    logger.error(err.message);
                    logger.error(`Full Error: ${err}`);
                })
                .finally(() => {
                    logger.info('Finally case got executed.');
                    return Promise.resolve();
                });
        }
    };


    /**
     * Verifies that the cluster is created
     */
    function verifySyncIsComplete() {
        logger.info('Checking CM Sync Status');
        return bigIp.cluster.getCmSyncStatus()
            .then((syncStatus) => {
                if (syncStatus.connected.length > 0) {
                    logger.info('Device is in cluster.');
                    return Promise.resolve();
                }
                return Promise.reject(new Error('not connected yet'));
            })
            .catch((err) => {
                logger.error('Error recieved while verifying CM Sync Status');
                logger.error(err.message);
                return Promise.reject(err);
            });
    }
    module.exports = runner;

    if (!module.parent) {
        runner.run(process.argv);
    }
}());
