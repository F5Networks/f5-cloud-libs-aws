/**
 * Copyright 2016-2018 F5 Networks, Inc.
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

process.env.NODE_PATH = `${__dirname}/../../../`;
require('module').Module._initPaths(); // eslint-disable-line no-underscore-dangle

const AutoscaleInstance = require('@f5devcentral/f5-cloud-libs').autoscaleInstance;

let q;
let fsMock;
let awsMock;
let AwsAutoscaleProvider;
let bigIpMock;
let utilMock;
let provider;

const providerOptions = {
    s3Bucket: 'foo',
    sqsUrl: 'bar'
};

const user = 'foo';
const password = 'bar';
const instanceId = '1234';

let fsReadFile;
let fsStat;

let iidDoc;
let instances;
let instance1;
let instance2;

let deletedInstances;

let getObjectParams;
let instanceProtectionParams;

let passedCreateTagsParams;
let deleteTagRequests;
let passedDescribeTagsParams;
let describeTagsResults;

const INSTANCES_FOLDER = 'instances/';

// Our tests cause too many event listeners. Turn off the check.
process.setMaxListeners(0);

module.exports = {
    setUp(callback) {
        /* eslint-disable global-require */
        q = require('q');
        fsMock = require('fs');
        awsMock = require('aws-sdk');
        /* eslint-disable import/no-extraneous-dependencies, import/no-unresolved */
        bigIpMock = require('@f5devcentral/f5-cloud-libs').bigIp;
        utilMock = require('@f5devcentral/f5-cloud-libs').util;
        /* eslint-enable import/no-extraneous-dependencies, import/no-unresolved */

        AwsAutoscaleProvider = require('../../lib/awsAutoscaleProvider');
        /* eslint-enable global-require */

        provider = new AwsAutoscaleProvider({ clOptions: { user, password } });

        fsReadFile = fsMock.readFile;
        fsStat = fsMock.stat;

        awsMock.config = {
            configUpdate: {},
            update(config) {
                Object.assign(this.configUpdate, config);
            }
        };

        fsMock.reset = function reset() {
            iidDoc = undefined;
        };

        fsMock.reset();

        utilMock.DEFAULT_RETRY = utilMock.NO_RETRY;
        utilMock.SHORT_RETRY = utilMock.NO_RETRY;
        utilMock.MEDIUM_RETRY = utilMock.NO_RETRY;

        callback();
    },

    tearDown(callback) {
        fsMock.readFile = fsReadFile;
        fsMock.stat = fsStat;

        Object.keys(require.cache).forEach((key) => {
            delete require.cache[key];
        });
        callback();
    },

    testFeatures(test) {
        test.expect(1);
        test.ok(provider.features.FEATURE_MESSAGING);
        test.done();
    },

    testInit: {
        setUp(callback) {
            iidDoc = '{}';

            awsMock.AutoScaling.prototype.describeAutoScalingInstances =
                function describeAutoScalingInstances() {
                    return {
                        promise() {
                            const deferred = q.defer();
                            deferred.resolve({
                                AutoScalingInstances: [
                                    {
                                        AutoScalingGroupName: 'myAutoscalingGroup'
                                    }
                                ]
                            });
                            return deferred.promise;
                        }
                    };
                };

            awsMock.S3.prototype.listObjectsV2 = function listObjectsV2() {
                return {
                    promise() {
                        return q({ KeyCount: 1 });
                    }
                };
            };

            bigIpMock.prototype.list = function list() {
                return {
                    then(cb) {
                        cb({ hostname: 'myhost' });
                    }
                };
            };

            bigIpMock.prototype.modify = function modify() {
                return {
                    then(cb) {
                        cb();
                    }
                };
            };

            fsMock.readFile = function readFile(filename, cb) {
                let data;

                switch (filename) {
                case '/shared/vadc/aws/iid-document':
                    data = iidDoc;
                    break;
                default:
                    data = undefined;
                }

                cb(null, data);
            };
            fsMock.stat = function stat(filename, cb) {
                cb(null);
            };

            callback();
        },

        testGetIidDoc(test) {
            iidDoc = {
                privateIp: '1.2.3.4',
                instanceId: 'myInstanceId',
                region: 'myRegion'
            };
            iidDoc = JSON.stringify(iidDoc);

            test.expect(4);
            provider.init(providerOptions)
                .then(() => {
                    test.strictEqual(provider.nodeProperties.mgmtIp, '1.2.3.4');
                    test.strictEqual(provider.nodeProperties.privateIp, '1.2.3.4');
                    test.strictEqual(provider.nodeProperties.instanceId, 'myInstanceId');
                    test.strictEqual(provider.nodeProperties.region, 'myRegion');
                })
                .catch((err) => {
                    test.ok(false, err.message);
                })
                .finally(() => {
                    test.done();
                });
        },

        testSetRegion(test) {
            iidDoc = {
                region: 'myRegion'
            };
            iidDoc = JSON.stringify(iidDoc);

            test.expect(1);
            provider.init(providerOptions)
                .then(() => {
                    test.strictEqual(awsMock.config.configUpdate.region, 'myRegion');
                })
                .catch((err) => {
                    test.ok(false, err.message);
                })
                .finally(() => {
                    test.done();
                });
        },

        testCreateBucket: {
            setUp(callback) {
                awsMock.S3.prototype.listObjectsV2 = function listObjectsV2() {
                    return {
                        promise() {
                            return q({ KeyCount: 0 });
                        }
                    };
                };
                providerOptions.region = 'foo';
                callback();
            },

            testCreated(test) {
                let putParams;
                awsMock.S3.prototype.putObject = function putObject(params) {
                    putParams = params;
                    return {
                        promise() {
                            return q();
                        }
                    };
                };

                test.expect(1);
                provider.init(providerOptions)
                    .then(() => {
                        test.strictEqual(putParams.Key, 'backup/');
                    })
                    .catch((err) => {
                        test.ok(false, err.message);
                    })
                    .finally(() => {
                        test.done();
                    });
            },

            testListObjectsError(test) {
                const errorMessage = 'foobar';
                awsMock.S3.prototype.listObjectsV2 = function listObjectsV2() {
                    return {
                        promise() {
                            return q.reject(new Error(errorMessage));
                        }
                    };
                };

                test.expect(1);
                provider.init(providerOptions)
                    .then(() => {
                        test.ok(false, 'Should have had list objects error');
                    })
                    .catch((err) => {
                        test.notStrictEqual(err.message.indexOf(errorMessage), -1);
                    })
                    .finally(() => {
                        test.done();
                    });
            },

            testPutObjectError(test) {
                const errorMessage = 'foobar';
                awsMock.S3.prototype.putObject = function putObject() {
                    return {
                        promise() {
                            return q.reject(new Error(errorMessage));
                        }
                    };
                };

                test.expect(1);
                provider.init(providerOptions)
                    .then(() => {
                        test.ok(false, 'Should have had list objects error');
                    })
                    .catch((err) => {
                        test.notStrictEqual(err.message.indexOf(errorMessage), -1);
                    })
                    .finally(() => {
                        test.done();
                    });
            }
        },

        testAutoscale: {
            testInstanceMaps(test) {
                const nextToken = 'this is the next token';

                const g1Instances = [
                    {
                        InstanceId: 'g1id1',
                        LifecycleState: 'InService',
                        LaunchConfigurationName: 'launchConfig1'
                    },
                    {
                        InstanceId: 'g1id2',
                        LifecycleState: 'InService',
                        LaunchConfigurationName: 'launchConfig1'
                    }
                ];
                const g2Instances = [
                    {
                        InstanceId: 'g2id1',
                        LifecycleState: 'InService',
                        LaunchConfigurationName: 'launchConfig2'
                    },
                    {
                        InstanceId: 'g2id2',
                        LifecycleState: 'InService',
                        LaunchConfigurationName: 'launchConfig2'
                    }
                ];

                awsMock.AutoScaling.prototype.describeAutoScalingGroups
                    = function describeAutoScalingGroups(params, cb) {
                        let data;
                        if (!params.NextToken) {
                            data = {
                                NextToken: nextToken,
                                AutoScalingGroups: [
                                    {
                                        AutoScalingGroupName: 'group1',
                                        Instances: g1Instances,
                                        Tags: [
                                            {
                                                Key: 'aws:cloudformation:stack-id',
                                                Value: 'stack1'
                                            }
                                        ]
                                    }
                                ]
                            };
                        } else if (params.NextToken === nextToken) {
                            data = {
                                AutoScalingGroups: [
                                    {
                                        AutoScalingGroupName: 'group2',
                                        Instances: g2Instances,
                                        Tags: [
                                            {
                                                Key: 'aws:cloudformation:stack-id',
                                                Value: 'stack2'
                                            }
                                        ]
                                    }
                                ]
                            };
                        }

                        cb(null, data);
                    };

                test.expect(3);
                provider.init(providerOptions, { autoscale: true })
                    .then(() => {
                        test.deepEqual(
                            provider.instanceIdToAutoscaleGroupMap,
                            {
                                g1id1: 'group1',
                                g1id2: 'group1',
                                g2id1: 'group2',
                                g2id2: 'group2'
                            }

                        );
                        test.deepEqual(
                            provider.instanceIdToLaunchConfigMap,
                            {
                                g1id1: 'launchConfig1',
                                g1id2: 'launchConfig1',
                                g2id1: 'launchConfig2',
                                g2id2: 'launchConfig2'
                            }
                        );

                        test.deepEqual(
                            provider.stackIdToInstanceMap,
                            {
                                stack1: g1Instances,
                                stack2: g2Instances
                            }
                        );
                    })
                    .catch((err) => {
                        test.ok(false, err.message);
                    })
                    .finally(() => {
                        test.done();
                    });
            }
        }
    },

    testGetDataFromUri: {
        setUp(callback) {
            provider.s3 = {
                getObject(params) {
                    getObjectParams = params;

                    return {
                        promise() {
                            const deferred = q.defer();
                            deferred.resolve({ Body: 'bucket data' });
                            return deferred.promise;
                        }
                    };
                }
            };

            getObjectParams = undefined;
            callback();
        },

        testBasic(test) {
            test.expect(3);
            provider.getDataFromUri('arn:aws:s3:::myBucket/myKey')
                .then((data) => {
                    test.strictEqual(getObjectParams.Bucket, 'myBucket');
                    test.strictEqual(getObjectParams.Key, 'myKey');
                    test.strictEqual(data, 'bucket data');
                })
                .catch((err) => {
                    test.ok(false, err);
                })
                .finally(() => {
                    test.done();
                });
        },

        testComplexKey(test) {
            test.expect(3);
            provider.getDataFromUri('arn:aws:s3:::myBucket/myFolder/myKey')
                .then((data) => {
                    test.strictEqual(getObjectParams.Bucket, 'myBucket');
                    test.strictEqual(getObjectParams.Key, 'myFolder/myKey');
                    test.strictEqual(data, 'bucket data');
                })
                .catch((err) => {
                    test.ok(false, err);
                })
                .finally(() => {
                    test.done();
                });
        },

        testInvalidUri(test) {
            test.expect(1);
            provider.getDataFromUri('https://aws.s3.com/myBucket/myKey')
                .then(() => {
                    test.ok(false, 'Should have thrown invalid URI');
                })
                .catch((err) => {
                    test.notStrictEqual(err.message.indexOf('Invalid URI'), -1);
                })
                .finally(() => {
                    test.done();
                });
        },

        testInvalidArn(test) {
            test.expect(1);
            provider.getDataFromUri('arn:aws:s3:::foo/')
                .then(() => {
                    test.ok(false, 'Should have thrown invalid ARN');
                })
                .catch((err) => {
                    test.notStrictEqual(err.message.indexOf('Invalid ARN'), -1);
                })
                .finally(() => {
                    test.done();
                });
        }
    },

    testGetInstances: {
        setUp(callback) {
            provider.providerOptions = providerOptions;
            provider.initOptions = {};
            provider.instanceIdToLaunchConfigMap = {};
            provider.instanceIdToAutoscaleGroupMap = {};
            provider.autoscaleGroupToLaunchConfigMap = {};
            provider.instancesToRevoke = [];

            provider.nodeProperties = {
                instanceId: 'id1',
                hostname: 'missingHostname1',
                mgmtIp: '7.8.9.0',
                privateIp: '10.11.12.13'
            };

            const Instances = [
                {
                    InstanceId: 'id1',
                    LifecycleState: 'InService'
                },
                {
                    InstanceId: 'id2',
                    LifecycleState: 'InService'
                },
                {
                    InstanceId: 'id3',
                    LifecycleState: 'Terminating'
                }
            ];

            provider.autoscaling = {
                describeAutoScalingGroups(params, cb) {
                    const data = {
                        AutoScalingGroups: [
                            {
                                Instances,
                                Tags: [
                                    {
                                        Key: 'aws:cloudformation:stack-id',
                                        Value: 'mystack'
                                    }
                                ]
                            }
                        ]
                    };

                    cb(null, data);
                }
            };

            provider.stackIdToInstanceMap = {
                mystack: Instances
            };

            provider.s3 = {
                listObjectsV2() {
                    return {
                        promise() {
                            const deferred = q.defer();
                            const data = {
                                Contents: [
                                    {
                                        Key: `${INSTANCES_FOLDER}id1`
                                    },
                                    {
                                        Key: `${INSTANCES_FOLDER}id2`
                                    },
                                    {
                                        Key: `${INSTANCES_FOLDER}goneMissing`
                                    }
                                ]
                            };
                            deferred.resolve(data);
                            return deferred.promise;
                        }
                    };
                },

                getObject(params) {
                    let data;
                    let deferred;
                    instance1 = {
                        isMaster: false,
                        hostname: 'hostname1',
                        mgmtIp: '1.2.3.4',
                        privateIp: '1.2.3.4',
                        publicIp: '123.456.789.1',
                        mgmtPort: 1000,
                        adminUser: 'myAdminUser',
                        adminPassword: 'myAdminPassword',
                        providerVisible: true
                    };
                    instance2 = {
                        isMaster: false,
                        hostname: 'hostname2',
                        mgmtIp: '5.6.7.8',
                        privateIp: '5.6.7.8',
                        publicIp: '123.456.789.2',
                        mgmtPort: 1000,
                        adminUser: 'myAdminUser',
                        adminPassword: 'myAdminPassword',
                        providerVisible: true
                    };

                    switch (params.Key) {
                    case `${INSTANCES_FOLDER}id1`:
                        data = {
                            Body: instance1
                        };
                        break;
                    case `${INSTANCES_FOLDER}id2`:
                        data = {
                            Body: instance2
                        };
                        break;
                    default:
                        data = undefined;
                    }

                    data = data || { Body: {} };
                    data.Body = JSON.stringify(data.Body);

                    return {
                        promise() {
                            deferred = q.defer();
                            deferred.resolve(data);
                            return deferred.promise;
                        }
                    };
                },

                deleteObjects(params) {
                    params.Delete.Objects.forEach((element) => {
                        deletedInstances.push(element.Key);
                    });

                    return {
                        promise() {
                            return q();
                        }
                    };
                }
            };

            provider.ec2 = {
                describeInstances() {
                    return {
                        promise() {
                            return q({});
                        }
                    };
                }
            };

            provider.revokeLicenses = function revokeLicenses() {
                return q();
            };

            deletedInstances = [];

            callback();
        },

        testInstanceMap(test) {
            test.expect(3);
            provider.getInstances()
                .then((returnedInstances) => {
                    const mungedInstances = returnedInstances;
                    delete mungedInstances.id1.lastUpdate;
                    delete mungedInstances.id2.lastUpdate;
                    test.strictEqual(Object.keys(mungedInstances).length, 2);
                    test.deepEqual(mungedInstances.id1, instance1);
                    test.deepEqual(mungedInstances.id2, instance2);
                })
                .catch((err) => {
                    test.ok(false, err.message);
                })
                .finally(() => {
                    test.done();
                });
        },

        testInstanceMapMissingInstanceId(test) {
            // If an instance ID is missing from the db, we should get it from
            // describe instances
            const Instances = [
                {
                    InstanceId: 'id1'
                },
                {
                    InstanceId: 'id2'
                },
                {
                    InstanceId: 'id3'
                }
            ];

            provider.autoscaling.describeAutoScalingGroups = function describeAutoScalingGroups(params, cb) {
                const data = {
                    AutoScalingGroups: [
                        {
                            Instances,
                            Tags: [
                                {
                                    Key: 'aws:cloudformation:stack-id',
                                    Value: 'mystack'
                                }
                            ]
                        }
                    ]
                };

                cb(null, data);
            };

            provider.stackIdToInstanceMap = {
                mystack: Instances
            };

            provider.ec2.describeInstances = function describeInstances() {
                return {
                    promise() {
                        const deferred = q.defer();
                        const data = {
                            Reservations: [
                                {
                                    Instances: [
                                        {
                                            InstanceId: 'id3',
                                            PublicIpAddress: '111.222.333.444',
                                            PrivateIpAddress: '7.8.9.0'
                                        }
                                    ]
                                }
                            ]
                        };
                        deferred.resolve(data);
                        return deferred.promise;
                    }
                };
            };

            provider.getInstances()
                .then((returnedInstances) => {
                    test.strictEqual(returnedInstances.id3.isMaster, false);
                    test.strictEqual(returnedInstances.id3.mgmtIp, '7.8.9.0');
                    test.strictEqual(returnedInstances.id3.privateIp, '7.8.9.0');
                    test.strictEqual(returnedInstances.id3.publicIp, '111.222.333.444');
                    test.strictEqual(returnedInstances.id3.providerVisible, true);
                    test.strictEqual(returnedInstances.id3.external, false);
                    test.strictEqual(returnedInstances.id3.status, AutoscaleInstance.INSTANCE_STATUS_OK);

                    test.deepEqual(returnedInstances.id2, instance2);
                })
                .catch((err) => {
                    test.ok(false, err.message);
                })
                .finally(() => {
                    test.done();
                });
        },

        testInstanceMapWithExternalTag(test) {
            const externalTag = {
                key: 'foo',
                value: 'bar'
            };
            let passedParams;

            provider.ec2 = {
                describeInstances(params) {
                    if (params.Filters) {
                        passedParams = params;
                        return {
                            promise() {
                                return q({
                                    Reservations: [
                                        {
                                            Instances: [
                                                {
                                                    InstanceId: '111',
                                                    State: {
                                                        Name: 'running'
                                                    },
                                                    PrivateIpAddress: '111.112.113.114'
                                                }
                                            ]
                                        }
                                    ]
                                });
                            }
                        };
                    }
                    return {
                        promise() {
                            return q({});
                        }
                    };
                }
            };

            provider.s3 = {
                listObjectsV2() {
                    return {
                        promise() {
                            const deferred = q.defer();
                            const data = {
                                Contents: [
                                    {
                                        Key: `${INSTANCES_FOLDER}111`
                                    }
                                ]
                            };
                            deferred.resolve(data);
                            return deferred.promise;
                        }
                    };
                },

                getObject(params) {
                    let data;
                    instance1 = {
                        isMaster: false,
                        hostname: 'hostname1',
                        mgmtIp: '111.112.113.114',
                        privateIp: '111.112.113.114',
                        mgmtPort: 1000,
                        adminUser: 'myAdminUser',
                        adminPassword: 'myAdminPassword'
                    };

                    switch (params.Key) {
                    case `${INSTANCES_FOLDER}111`:
                        data = {
                            Body: instance1
                        };
                        break;
                    default:
                        data = undefined;
                    }

                    data = data || { Body: {} };
                    data.Body = JSON.stringify(data.Body);

                    return {
                        promise() {
                            return q(data);
                        }
                    };
                }
            };

            test.expect(2);
            provider.getInstances({ externalTag })
                .then((returnedInstances) => {
                    test.strictEqual(returnedInstances['111'].external, true);
                    test.deepEqual(
                        passedParams.Filters[0],
                        {
                            Name: `tag:${externalTag.key}`,
                            Values: [externalTag.value]
                        }
                    );
                })
                .catch((err) => {
                    test.ok(false, err);
                })
                .finally(() => {
                    test.done();
                });
        },

        testNonMastersDeleted(test) {
            test.expect(3);
            provider.getInstances()
                .then(() => {
                    test.strictEqual(deletedInstances.length, 2);
                    test.strictEqual(deletedInstances[0], 'instances/goneMissing');
                    test.strictEqual(deletedInstances[1], 'public_keys/goneMissing');
                })
                .catch((err) => {
                    test.ok(false, err.message);
                })
                .finally(() => {
                    test.done();
                });
        }
    },

    testGetNicsByTag: {
        testBasic(test) {
            const myTag = {
                key: 'foo',
                value: 'bar'
            };
            let passedParams;

            provider.ec2 = {
                describeNetworkInterfaces(params) {
                    passedParams = params;
                    return {
                        promise() {
                            return q({
                                NetworkInterfaces: [
                                    {
                                        NetworkInterfaceId: '1',
                                        PrivateIpAddress: '1.2.3.4'
                                    },
                                    {
                                        NetworkInterfaceId: '2',
                                        PrivateIpAddress: '2.3.4.5',
                                        Association: {
                                            PublicIp: '3.4.5.6'
                                        }
                                    }
                                ]
                            });
                        }
                    };
                }
            };

            test.expect(7);
            provider.getNicsByTag(myTag)
                .then((response) => {
                    test.strictEqual(passedParams.Filters[0].Name, `tag:${myTag.key}`);
                    test.strictEqual(response[0].id, '1');
                    test.strictEqual(response[0].ip.private, '1.2.3.4');
                    test.strictEqual(response[0].ip.public, undefined);
                    test.strictEqual(response[1].id, '2');
                    test.strictEqual(response[1].ip.private, '2.3.4.5');
                    test.strictEqual(response[1].ip.public, '3.4.5.6');
                })
                .catch((err) => {
                    test.ok(false, err.message);
                })
                .finally(() => {
                    test.done();
                });
        },

        testBadTag(test) {
            const myTag = 'foo';

            test.expect(1);
            provider.getNicsByTag(myTag)
                .then(() => {
                    test.ok(false, 'getNicsByTag should have thrown');
                })
                .catch((err) => {
                    test.notStrictEqual(err.message.indexOf('key and value'), -1);
                })
                .finally(() => {
                    test.done();
                });
        },

        testError(test) {
            const myTag = {
                key: 'foo',
                value: 'bar'
            };

            provider.ec2 = {
                describeNetworkInterfaces() {
                    return {
                        promise() {
                            return q.reject(new Error('uh oh'));
                        }
                    };
                }
            };

            test.expect(1);
            provider.getNicsByTag(myTag)
                .then(() => {
                    test.ok(false, 'getNicsByTag should have thrown');
                })
                .catch((err) => {
                    test.strictEqual(err.message, 'uh oh');
                })
                .finally(() => {
                    test.done();
                });
        }
    },

    testGetVmsByTag: {
        testBasic(test) {
            const myTag = {
                key: 'foo',
                value: 'bar'
            };
            let passedParams;

            provider.ec2 = {
                describeInstances(params) {
                    passedParams = params;
                    return {
                        promise() {
                            return q({
                                Reservations: [
                                    {
                                        Instances: [
                                            {
                                                InstanceId: '1',
                                                State: {
                                                    Name: 'running'
                                                },
                                                PrivateIpAddress: '1.2.3.4'
                                            },
                                            {
                                                InstanceId: '2',
                                                State: {
                                                    Name: 'running'
                                                },
                                                PrivateIpAddress: '2.3.4.5',
                                                PublicIpAddress: '3.4.5.6'
                                            },
                                            {
                                                InstanceId: '3',
                                                State: {
                                                    Name: 'pending'
                                                },
                                                PrivateIpAddress: '4.5.6.7',
                                                PublicIpAddress: '5.6.7.8'
                                            }
                                        ]
                                    }
                                ]
                            });
                        }
                    };
                }
            };

            test.expect(7);
            provider.getVmsByTag(myTag)
                .then((response) => {
                    test.strictEqual(passedParams.Filters[0].Name, `tag:${myTag.key}`);
                    test.strictEqual(response.length, 2);
                    test.strictEqual(response[0].id, '1');
                    test.strictEqual(response[0].ip.private, '1.2.3.4');
                    test.strictEqual(response[1].id, '2');
                    test.strictEqual(response[1].ip.private, '2.3.4.5');
                    test.strictEqual(response[1].ip.public, '3.4.5.6');
                })
                .catch((err) => {
                    test.ok(false, err.message);
                })
                .finally(() => {
                    test.done();
                });
        },

        testPending(test) {
            const myTag = {
                key: 'foo',
                value: 'bar'
            };
            let passedParams;

            provider.ec2 = {
                describeInstances(params) {
                    passedParams = params;
                    return {
                        promise() {
                            return q({
                                Reservations: [
                                    {
                                        Instances: [
                                            {
                                                InstanceId: '1',
                                                State: {
                                                    Name: 'running'
                                                },
                                                PrivateIpAddress: '1.2.3.4'
                                            },
                                            {
                                                InstanceId: '2',
                                                State: {
                                                    Name: 'running'
                                                },
                                                PrivateIpAddress: '2.3.4.5',
                                                PublicIpAddress: '3.4.5.6'
                                            },
                                            {
                                                InstanceId: '3',
                                                State: {
                                                    Name: 'pending'
                                                },
                                                PrivateIpAddress: '4.5.6.7',
                                                PublicIpAddress: '5.6.7.8'
                                            }
                                        ]
                                    }
                                ]
                            });
                        }
                    };
                }
            };

            test.expect(5);
            provider.getVmsByTag(myTag, { includePending: true })
                .then((response) => {
                    test.strictEqual(passedParams.Filters[0].Name, `tag:${myTag.key}`);
                    test.strictEqual(response.length, 3);
                    test.strictEqual(response[2].id, '3');
                    test.strictEqual(response[2].ip.private, '4.5.6.7');
                    test.strictEqual(response[2].ip.public, '5.6.7.8');
                })
                .catch((err) => {
                    test.ok(false, err.message);
                })
                .finally(() => {
                    test.done();
                });
        },

        testBadTag(test) {
            const myTag = 'foo';

            test.expect(1);
            provider.getVmsByTag(myTag)
                .then(() => {
                    test.ok(false, 'getVmsByTag should have thrown');
                })
                .catch((err) => {
                    test.notStrictEqual(err.message.indexOf('key and value'), -1);
                })
                .finally(() => {
                    test.done();
                });
        },

        testError(test) {
            const myTag = {
                key: 'foo',
                value: 'bar'
            };

            provider.ec2 = {
                describeInstances() {
                    return {
                        promise() {
                            return q.reject(new Error('uh oh'));
                        }
                    };
                }
            };

            test.expect(1);
            provider.getVmsByTag(myTag)
                .then(() => {
                    test.ok(false, 'getVmsByTag should have thrown');
                })
                .catch((err) => {
                    test.strictEqual(err.message, 'uh oh');
                })
                .finally(() => {
                    test.done();
                });
        }
    },

    testElectMaster: {
        setUp(callback) {
            provider.instanceIdToLaunchConfigMap = {};
            provider.instanceIdToAutoscaleGroupMap = {};
            provider.autoscaleGroupToLaunchConfigMap = {};
            callback();
        },

        testBasic(test) {
            const possibleMasterInstances = {
                id1: {
                    privateIp: '1.2.3.4',
                    versionOk: true,
                    providerVisible: true
                },
                id2: {
                    privateIp: '1.2.4.4',
                    versionOk: true,
                    providerVisible: true
                }
            };

            test.expect(1);
            provider.electMaster(possibleMasterInstances)
                .then((electedMasterId) => {
                    test.strictEqual(electedMasterId, 'id1');
                })
                .catch((err) => {
                    test.ok(false, err.message);
                })
                .finally(() => {
                    test.done();
                });
        },

        testProviderNotVisible(test) {
            const possibleMasterInstances = {
                id1: {
                    privateIp: '1.2.3.4',
                    versionOk: true,
                    providerVisible: false
                },
                id2: {
                    privateIp: '1.2.4.4',
                    versionOk: true,
                    providerVisible: true
                }
            };

            test.expect(1);
            provider.electMaster(possibleMasterInstances)
                .then((electedMasterId) => {
                    test.strictEqual(electedMasterId, 'id2');
                })
                .catch((err) => {
                    test.ok(false, err.message);
                })
                .finally(() => {
                    test.done();
                });
        },

        testLaunchConfigName(test) {
            const possibleMasterInstances = {
                id1: {
                    privateIp: '1.2.3.4',
                    versionOk: true,
                    providerVisible: true,
                },
                id2: {
                    privateIp: '1.2.4.4',
                    versionOk: true,
                    providerVisible: true
                }
            };

            provider.launchConfigName = 'good';
            provider.instanceIdToLaunchConfigMap = {
                id1: 'bad',
                id2: 'good'
            };

            provider.instanceIdToAutoscaleGroupMap = {
                id1: 'myAsg',
                id2: 'myAsg'
            };
            provider.autoscaleGroupToLaunchConfigMap = {
                myAsg: 'good'
            };

            test.expect(1);
            provider.electMaster(possibleMasterInstances)
                .then((electedMasterId) => {
                    test.strictEqual(electedMasterId, 'id2');
                })
                .catch((err) => {
                    test.ok(false, err.message);
                })
                .finally(() => {
                    test.done();
                });
        },

        testExternal(test) {
            const possibleMasterInstances = {
                id1: {
                    privateIp: '1.2.3.4',
                    versionOk: true,
                    providerVisible: true
                },
                id2: {
                    privateIp: '5.6.7.8',
                    external: false,
                    versionOk: true,
                    providerVisible: true
                },
                id3: {
                    privateIp: '7.8.9.10',
                    external: true,
                    versionOk: true,
                    providerVisible: true
                }
            };

            test.expect(1);
            provider.electMaster(possibleMasterInstances)
                .then((electedMasterId) => {
                    test.strictEqual(electedMasterId, 'id3');
                })
                .catch((err) => {
                    test.ok(false, err.message);
                })
                .finally(() => {
                    test.done();
                });
        },

        testVersionOk(test) {
            const possibleMasterInstances = {
                id1: {
                    privateIp: '1.2.3.4',
                    versionOk: true,
                    providerVisible: true
                },
                id2: {
                    privateIp: '1.2.4.4',
                    versionOk: true,
                    providerVisible: true
                },
                id3: {
                    privateIp: '1.2.0.4',
                    versionOk: false,
                    providerVisible: true
                }
            };

            test.expect(1);
            provider.electMaster(possibleMasterInstances)
                .then((electedMasterId) => {
                    test.strictEqual(electedMasterId, 'id1');
                })
                .catch((err) => {
                    test.ok(false, err.message);
                })
                .finally(() => {
                    test.done();
                });
        }
    },

    testIsValidMaster: {
        setUp(callback) {
            instance1 = {
                isMaster: false,
                hostname: 'hostname1',
                mgmtIp: '1.2.3.4',
                privateIp: '1.2.3.4'
            };
            instance2 = {
                isMaster: false,
                hostname: 'hostname2',
                mgmtIp: '5.6.7.8',
                privateIp: '5.6.7.8'
            };

            instances = [instance1, instance2];

            provider.nodeProperties = {
                instanceId: instanceId + 1
            };

            provider.s3 = {
                getObject() {
                    return {
                        promise() {
                            return q({});
                        }
                    };
                }
            };

            callback();
        },

        testIsMaster(test) {
            provider.nodeProperties.instanceId = instanceId;

            test.expect(1);
            provider.isValidMaster(instanceId, instances)
                .then((isValid) => {
                    test.ok(isValid);
                })
                .catch((err) => {
                    test.ok(false, err.message);
                })
                .finally(() => {
                    test.done();
                });
        },

        testNoInstanceInfo(test) {
            provider.s3.getObject = function getObject() {
                return {
                    promise() {
                        return q.reject();
                    }
                };
            };

            test.expect(1);
            provider.isValidMaster(instanceId, instances)
                .then((isValid) => {
                    test.ok(isValid);
                })
                .catch((err) => {
                    test.ok(false, err.message);
                })
                .finally(() => {
                    test.done();
                });
        }
    },

    testMasterElected: {
        setUp(callback) {
            provider.nodeProperties = { instanceId };
            instanceProtectionParams = undefined;

            awsMock = {
                AutoScaling: {
                    setInstanceProtection(params, cb) {
                        instanceProtectionParams = params;
                        cb();
                    }
                },
                S3: {
                    listObjectsV2() {
                        return {
                            promise() {
                                return q(
                                    {
                                        KeyCount: 1,
                                        Contents: []
                                    }
                                );
                            }
                        };
                    }
                }
            };

            provider.autoscaling = awsMock.AutoScaling;
            provider.s3 = awsMock.S3;
            provider.providerOptions = {
                s3Bucket: 'foo'
            };

            callback();
        },

        testInstanceProtectionSetWhenMaster(test) {
            test.expect(3);
            provider.masterElected(instanceId)
                .then(() => {
                    test.strictEqual(instanceProtectionParams.InstanceIds.length, 1);
                    test.strictEqual(instanceProtectionParams.InstanceIds[0], instanceId);
                    test.ok(instanceProtectionParams.ProtectedFromScaleIn);
                })
                .catch((err) => {
                    test.ok(false, err.message);
                })
                .finally(() => {
                    test.done();
                });
        },

        testInstanceProtectionNotSetWhenNotMaster(test) {
            test.expect(1);
            provider.masterElected('foo')
                .then(() => {
                    test.strictEqual(instanceProtectionParams, undefined);
                })
                .catch((err) => {
                    test.ok(false, err.message);
                })
                .finally(() => {
                    test.done();
                });
        },

        testOtherMastersSetToNonMaster(test) {
            let instancePut;
            let instancePutId;

            awsMock.S3.listObjectsV2 = function listObjectsV2() {
                return {
                    promise() {
                        return q(
                            {
                                KeyCount: 1,
                                Contents: [
                                    {
                                        Key: 'instances/5678',
                                        isMaster: true
                                    }
                                ]
                            }
                        );
                    }
                };
            };
            awsMock.S3.getObject = function getObject() {
                return {
                    promise() {
                        return q(
                            {
                                Body: JSON.stringify({
                                    isMaster: true
                                })
                            }
                        );
                    }
                };
            };

            provider.putInstance = function putInstance(instanceIdSent, instance) {
                instancePutId = instanceIdSent;
                instancePut = instance;
                return q();
            };

            test.expect(2);
            provider.masterElected(instanceId)
                .then(() => {
                    test.strictEqual(instancePutId, '5678');
                    test.strictEqual(instancePut.isMaster, false);
                })
                .catch((err) => {
                    test.ok(false, err.message);
                })
                .finally(() => {
                    test.done();
                });
        }
    },
    testTagMaster: {
        setUp(callback) {
            provider.ec2 = {
                describeTags(params) {
                    passedDescribeTagsParams = params;
                    return {
                        promise() {
                            return q(describeTagsResults);
                        }
                    };
                },
                createTags(params) {
                    passedCreateTagsParams = params;
                    return {
                        promise() {
                            return q();
                        }
                    };
                },
                deleteTags(params) {
                    return {
                        promise() {
                            return q(deleteTagRequests.push(params));
                        }
                    };
                }
            };

            deleteTagRequests = [];

            callback();
        },

        testTagMasterWithStackName(test) {
            describeTagsResults = {
                Tags:
                    [{
                        Key: 'aws:cloudformation:stack-name',
                        ResourceId: 'i-06b5bd27acbfa0cc3',
                        ResourceType: 'instance',
                        Value: 'StackName'
                    },
                    ]
            };

            const clusterInstances = {
                1234: {
                    LifecycleState: 'InService'
                },

                5678: {
                    LifecycleState: 'InService'
                }
            };

            const masterId = '1234';

            test.expect(4);
            provider.tagMasterInstance(masterId, clusterInstances)
                .then(() => {
                    test.strictEqual(passedDescribeTagsParams.Filters[0].Values[0], masterId);
                    test.deepEqual(passedCreateTagsParams,
                        {
                            Resources: ['1234'],
                            Tags: [
                                {
                                    Key: 'StackName-master',
                                    Value: 'true'
                                }
                            ]
                        });
                    test.deepEqual(deleteTagRequests[0],
                        {
                            Resources: ['5678'],
                            Tags: [
                                {
                                    Key: 'StackName-master',
                                    Value: 'true'
                                }
                            ]
                        });
                    test.strictEqual(deleteTagRequests.length, 1);
                })
                .catch((err) => {
                    test.ok(false, err.message);
                })
                .finally(() => {
                    test.done();
                });
        }
    }
};
