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

const assert = require('assert');
process.env.NODE_PATH = `${__dirname}/../../../`;
require('module').Module._initPaths(); // eslint-disable-line no-underscore-dangle

const AutoscaleInstance = require('@f5devcentral/f5-cloud-libs').autoscaleInstance;

describe('aws cloud provider tests', () => {
    let q;
    let fsMock;
    let awsMock;
    let AwsCloudProvider;
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

    let passedSignalResourceParams;

    const INSTANCES_FOLDER = 'instances/';

    // Our tests cause too many event listeners. Turn off the check.
    process.setMaxListeners(0);

    beforeEach(() => {
        /* eslint-disable global-require */
        q = require('q');
        fsMock = require('fs');
        awsMock = require('aws-sdk');
        /* eslint-disable import/no-extraneous-dependencies, import/no-unresolved */
        bigIpMock = require('@f5devcentral/f5-cloud-libs').bigIp;
        utilMock = require('@f5devcentral/f5-cloud-libs').util;
        /* eslint-enable import/no-extraneous-dependencies, import/no-unresolved */

        AwsCloudProvider = require('../../lib/awsCloudProvider');
        /* eslint-enable global-require */

        provider = new AwsCloudProvider({ clOptions: { user, password } });

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
    });

    afterEach(() => {
        fsMock.readFile = fsReadFile;
        fsMock.stat = fsStat;

        Object.keys(require.cache).forEach((key) => {
            delete require.cache[key];
        });
    });

    it('features test', (done) => {
        assert.ok(provider.features.FEATURE_MESSAGING);
        done();
    });

    describe('init tests', () => {
        beforeEach(() => {
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
        });

        it('get Iid doc test', (done) => {
            iidDoc = {
                privateIp: '1.2.3.4',
                instanceId: 'myInstanceId',
                region: 'myRegion'
            };
            iidDoc = JSON.stringify(iidDoc);

            provider.init(providerOptions)
                .then(() => {
                    assert.strictEqual(provider.nodeProperties.mgmtIp, '1.2.3.4');
                    assert.strictEqual(provider.nodeProperties.privateIp, '1.2.3.4');
                    assert.strictEqual(provider.nodeProperties.instanceId, 'myInstanceId');
                    assert.strictEqual(provider.nodeProperties.region, 'myRegion');
                })
                .catch((err) => {
                    assert.ok(false, err.message);
                })
                .finally(() => {
                    done();
                });
        });

        it('set region test', (done) => {
            iidDoc = {
                region: 'myRegion'
            };
            iidDoc = JSON.stringify(iidDoc);

            provider.init(providerOptions)
                .then(() => {
                    assert.strictEqual(awsMock.config.configUpdate.region, 'myRegion');
                })
                .catch((err) => {
                    assert.ok(false, err.message);
                })
                .finally(() => {
                    done();
                });
        });

        describe('create bucket tests', () => {
            beforeEach(() => {
                awsMock.S3.prototype.listObjectsV2 = function listObjectsV2() {
                    return {
                        promise() {
                            return q({ KeyCount: 0 });
                        }
                    };
                };
                providerOptions.region = 'foo';
            });

            it('created test', (done) => {
                let putParams;
                awsMock.S3.prototype.putObject = function putObject(params) {
                    putParams = params;
                    return {
                        promise() {
                            return q();
                        }
                    };
                };

                provider.init(providerOptions)
                    .then(() => {
                        assert.strictEqual(putParams.Key, 'backup/');
                    })
                    .catch((err) => {
                        assert.ok(false, err.message);
                    })
                    .finally(() => {
                        done();
                    });
            });

            it('list objects error test', (done) => {
                const errorMessage = 'foobar';
                awsMock.S3.prototype.listObjectsV2 = function listObjectsV2() {
                    return {
                        promise() {
                            return q.reject(new Error(errorMessage));
                        }
                    };
                };

                provider.init(providerOptions)
                    .then(() => {
                        assert.ok(false, 'Should have had list objects error');
                    })
                    .catch((err) => {
                        assert.notStrictEqual(err.message.indexOf(errorMessage), -1);
                    })
                    .finally(() => {
                        done();
                    });
            });

            it('put object error test', (done) => {
                const errorMessage = 'foobar';
                awsMock.S3.prototype.putObject = function putObject() {
                    return {
                        promise() {
                            return q.reject(new Error(errorMessage));
                        }
                    };
                };

                provider.init(providerOptions)
                    .then(() => {
                        assert.ok(false, 'Should have had list objects error');
                    })
                    .catch((err) => {
                        assert.notStrictEqual(err.message.indexOf(errorMessage), -1);
                    })
                    .finally(() => {
                        done();
                    });
            });
        });

        describe('autoscale tests', () => {
            it('instance maps test', (done) => {
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

                provider.init(providerOptions, { autoscale: true })
                    .then(() => {
                        assert.deepEqual(
                            provider.instanceIdToAutoscaleGroupMap,
                            {
                                g1id1: 'group1',
                                g1id2: 'group1',
                                g2id1: 'group2',
                                g2id2: 'group2'
                            }

                        );
                        assert.deepEqual(
                            provider.instanceIdToLaunchConfigMap,
                            {
                                g1id1: 'launchConfig1',
                                g1id2: 'launchConfig1',
                                g2id1: 'launchConfig2',
                                g2id2: 'launchConfig2'
                            }
                        );

                        assert.deepEqual(
                            provider.stackIdToInstanceMap,
                            {
                                stack1: g1Instances,
                                stack2: g2Instances
                            }
                        );
                    })
                    .catch((err) => {
                        assert.ok(false, err.message);
                    })
                    .finally(() => {
                        done();
                    });
            });
        });
    });

    describe('get data from uri tests', () => {
        beforeEach(() => {
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
        });

        it('basic test', (done) => {
            provider.getDataFromUri('arn:aws:s3:::myBucket/myKey')
                .then((data) => {
                    assert.strictEqual(getObjectParams.Bucket, 'myBucket');
                    assert.strictEqual(getObjectParams.Key, 'myKey');
                    assert.strictEqual(data, 'bucket data');
                })
                .catch((err) => {
                    assert.ok(false, err);
                })
                .finally(() => {
                    done();
                });
        });

        it('cn test', (done) => {
            provider.getDataFromUri('arn:aws-cn:s3:::myBucket/myKey')
                .then((data) => {
                    assert.strictEqual(getObjectParams.Bucket, 'myBucket');
                    assert.strictEqual(getObjectParams.Key, 'myKey');
                    assert.strictEqual(data, 'bucket data');
                })
                .catch((err) => {
                    assert.ok(false, err);
                })
                .finally(() => {
                    done();
                });
        });

        it('us gov test', (done) => {
            provider.getDataFromUri('arn:aws-us-gov:s3:::myBucket/myKey')
                .then((data) => {
                    assert.strictEqual(getObjectParams.Bucket, 'myBucket');
                    assert.strictEqual(getObjectParams.Key, 'myKey');
                    assert.strictEqual(data, 'bucket data');
                })
                .catch((err) => {
                    assert.ok(false, err);
                })
                .finally(() => {
                    done();
                });
        });

        it('complex key test', (done) => {
            provider.getDataFromUri('arn:aws:s3:::myBucket/myFolder/myKey')
                .then((data) => {
                    assert.strictEqual(getObjectParams.Bucket, 'myBucket');
                    assert.strictEqual(getObjectParams.Key, 'myFolder/myKey');
                    assert.strictEqual(data, 'bucket data');
                })
                .catch((err) => {
                    assert.ok(false, err);
                })
                .finally(() => {
                    done();
                });
        });

        it('invalid uri test', (done) => {
            provider.getDataFromUri('https://aws.s3.com/myBucket/myKey')
                .then(() => {
                    assert.ok(false, 'Should have thrown invalid URI');
                })
                .catch((err) => {
                    assert.notStrictEqual(err.message.indexOf('Invalid URI'), -1);
                })
                .finally(() => {
                    done();
                });
        });

        it('invalid arn test', (done) => {
            provider.getDataFromUri('arn:aws:s3:::foo/')
                .then(() => {
                    assert.ok(false, 'Should have thrown invalid ARN');
                })
                .catch((err) => {
                    assert.notStrictEqual(err.message.indexOf('Invalid ARN'), -1);
                })
                .finally(() => {
                    done();
                });
        });
    });

    describe('delete stored ucs tests', () => {
        beforeEach(() => {
            provider.s3 = {
                deleteObjects: function() {
                    return {
                        promise() {
                            const deferred = q.defer();
                            deferred.resolve();
                            return deferred.promise;
                        }
                    };
                }
            };
            provider.providerOptions = {
                s3Bucket: 'foo'
            };
        });

        it('exists test', (done) => {
            provider.deleteStoredUcs('foo.ucs')
                .then((response) => {
                    assert.ok(true);
                    assert.strictEqual(response.status, 'OK');
                    assert.notStrictEqual(response.message
                        .indexOf('The following items were successfully deleted'), -1);
                })
                .catch((err) => {
                    assert.ok(false, err.message);
                })
                .finally(() => {
                    done();
                });
        });
    });

    describe('delete stored object tests', () => {
        beforeEach(() => {
            provider.s3 = {
                deleteObjects: function() {
                    return {
                        promise() {
                            const deferred = q.defer();
                            deferred.resolve();
                            return deferred.promise;
                        }
                    };
                }
            };
            provider.providerOptions = {
                s3Bucket: 'foo'
            };
        });

        it('exists test', (done) => {
            provider.deleteStoredObject('credentials/primary')
                .then((response) => {
                    assert.ok(true);
                    assert.strictEqual(response.status, 'OK');
                    assert.notStrictEqual(response.message
                        .indexOf('The following items were successfully deleted'), -1);
                })
                .catch((err) => {
                    assert.ok(false, err.message);
                })
                .finally(() => {
                    done();
                });
        });
    });

    describe('get instances tests', () => {
        beforeEach(() => {
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
                        isPrimary: true,
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
                        isPrimary: false,
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
        });

        it('instance map test', (done) => {
            provider.getInstances()
                .then((returnedInstances) => {
                    const mungedInstances = returnedInstances;
                    delete mungedInstances.id1.lastUpdate;
                    delete mungedInstances.id2.lastUpdate;
                    assert.strictEqual(Object.keys(mungedInstances).length, 2);
                    assert.deepEqual(mungedInstances.id1, instance1);
                    assert.deepEqual(mungedInstances.id2, instance2);
                })
                .catch((err) => {
                    assert.ok(false, err.message);
                })
                .finally(() => {
                    done();
                });
        });

        it('instance map missing instance id test', (done) => {
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
                    assert.strictEqual(returnedInstances.id3.isPrimary, false);
                    assert.strictEqual(returnedInstances.id3.mgmtIp, '7.8.9.0');
                    assert.strictEqual(returnedInstances.id3.privateIp, '7.8.9.0');
                    assert.strictEqual(returnedInstances.id3.publicIp, '111.222.333.444');
                    assert.strictEqual(returnedInstances.id3.providerVisible, true);
                    assert.strictEqual(returnedInstances.id3.external, false);
                    assert.strictEqual(returnedInstances.id3.status, AutoscaleInstance.INSTANCE_STATUS_OK);

                    assert.deepEqual(returnedInstances.id2, instance2);
                })
                .catch((err) => {
                    assert.ok(false, err.message);
                })
                .finally(() => {
                    done();
                });
        });

        it('instance map with external tag test', (done) => {
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
                        isPrimary: true,
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

            provider.getInstances({ externalTag, instanceId: 'id1' })
                .then((returnedInstances) => {
                    assert.strictEqual(returnedInstances['111'].external, true);
                    assert.deepEqual(
                        passedParams.Filters[0],
                        {
                            Name: `tag:${externalTag.key}`,
                            Values: [externalTag.value]
                        }
                    );
                })
                .catch((err) => {
                    assert.ok(false, err);
                })
                .finally(() => {
                    done();
                });
        });

        it('non primaries deleted test', (done) => {
            provider.getInstances({ instanceId: 'id1' })
                .then(() => {
                    assert.strictEqual(deletedInstances.length, 2);
                    assert.strictEqual(deletedInstances[0], 'instances/goneMissing');
                    assert.strictEqual(deletedInstances[1], 'public_keys/goneMissing');
                })
                .catch((err) => {
                    assert.ok(false, err.message);
                })
                .finally(() => {
                    done();
                });
        });
    });

    describe('get nics by tag tests', () => {
        it('basic test', (done) => {
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

            provider.getNicsByTag(myTag)
                .then((response) => {
                    assert.strictEqual(passedParams.Filters[0].Name, `tag:${myTag.key}`);
                    assert.strictEqual(response[0].id, '1');
                    assert.strictEqual(response[0].ip.private, '1.2.3.4');
                    assert.strictEqual(response[0].ip.public, undefined);
                    assert.strictEqual(response[1].id, '2');
                    assert.strictEqual(response[1].ip.private, '2.3.4.5');
                    assert.strictEqual(response[1].ip.public, '3.4.5.6');
                })
                .catch((err) => {
                    assert.ok(false, err.message);
                })
                .finally(() => {
                    done();
                });
        });

        it('bad tag test', (done) => {
            const myTag = 'foo';

            provider.getNicsByTag(myTag)
                .then(() => {
                    assert.ok(false, 'getNicsByTag should have thrown');
                })
                .catch((err) => {
                    assert.notStrictEqual(err.message.indexOf('key and value'), -1);
                })
                .finally(() => {
                    done();
                });
        });

        it('error test', (done) => {
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

            provider.getNicsByTag(myTag)
                .then(() => {
                    assert.ok(false, 'getNicsByTag should have thrown');
                })
                .catch((err) => {
                    assert.strictEqual(err.message, 'uh oh');
                })
                .finally(() => {
                    done();
                });
        });
    });

    describe('get vms by tag tests', () => {
        it('basic test', (done) => {
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

            provider.getVmsByTag(myTag)
                .then((response) => {
                    assert.strictEqual(passedParams.Filters[0].Name, `tag:${myTag.key}`);
                    assert.strictEqual(response.length, 2);
                    assert.strictEqual(response[0].id, '1');
                    assert.strictEqual(response[0].ip.private, '1.2.3.4');
                    assert.strictEqual(response[1].id, '2');
                    assert.strictEqual(response[1].ip.private, '2.3.4.5');
                    assert.strictEqual(response[1].ip.public, '3.4.5.6');
                })
                .catch((err) => {
                    assert.ok(false, err.message);
                })
                .finally(() => {
                    done();
                });
        });

        it('pending test', (done) => {
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

            provider.getVmsByTag(myTag, { includePending: true })
                .then((response) => {
                    assert.strictEqual(passedParams.Filters[0].Name, `tag:${myTag.key}`);
                    assert.strictEqual(response.length, 3);
                    assert.strictEqual(response[2].id, '3');
                    assert.strictEqual(response[2].ip.private, '4.5.6.7');
                    assert.strictEqual(response[2].ip.public, '5.6.7.8');
                })
                .catch((err) => {
                    assert.ok(false, err.message);
                })
                .finally(() => {
                    done();
                });
        });

        it('bad tag test', (done) => {
            const myTag = 'foo';

            provider.getVmsByTag(myTag)
                .then(() => {
                    assert.ok(false, 'getVmsByTag should have thrown');
                })
                .catch((err) => {
                    assert.notStrictEqual(err.message.indexOf('key and value'), -1);
                })
                .finally(() => {
                    done();
                });
        });

        it('error test', (done) => {
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

            provider.getVmsByTag(myTag)
                .then(() => {
                    assert.ok(false, 'getVmsByTag should have thrown');
                })
                .catch((err) => {
                    assert.strictEqual(err.message, 'uh oh');
                })
                .finally(() => {
                    done();
                });
        });
    });

    describe('elect Primary tests', () => {
        beforeEach(() => {
            provider.instanceIdToLaunchConfigMap = {};
            provider.instanceIdToAutoscaleGroupMap = {};
            provider.autoscaleGroupToLaunchConfigMap = {};
        });

        it('basic test', (done) => {
            const possiblePrimaryInstances = {
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

            provider.electPrimary(possiblePrimaryInstances)
                .then((electedPrimaryId) => {
                    assert.strictEqual(electedPrimaryId, 'id1');
                })
                .catch((err) => {
                    assert.ok(false, err.message);
                })
                .finally(() => {
                    done();
                });
        });

        it('provider not visible test', (done) => {
            const possiblePrimaryInstances = {
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

            provider.electPrimary(possiblePrimaryInstances)
                .then((electedPrimaryId) => {
                    assert.strictEqual(electedPrimaryId, 'id2');
                })
                .catch((err) => {
                    assert.ok(false, err.message);
                })
                .finally(() => {
                    done();
                });
        });

        it('launch config name test', (done) => {
            const possiblePrimaryInstances = {
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

            provider.electPrimary(possiblePrimaryInstances)
                .then((electedPrimaryId) => {
                    assert.strictEqual(electedPrimaryId, 'id2');
                })
                .catch((err) => {
                    assert.ok(false, err.message);
                })
                .finally(() => {
                    done();
                });
        });

        it('external test', (done) => {
            const possiblePrimaryInstances = {
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

            provider.electPrimary(possiblePrimaryInstances)
                .then((electedPrimaryId) => {
                    assert.strictEqual(electedPrimaryId, 'id3');
                })
                .catch((err) => {
                    assert.ok(false, err.message);
                })
                .finally(() => {
                    done();
                });
        });

        it('version ok test', (done) => {
            const possiblePrimaryInstances = {
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

            provider.electPrimary(possiblePrimaryInstances)
                .then((electedPrimaryId) => {
                    assert.strictEqual(electedPrimaryId, 'id1');
                })
                .catch((err) => {
                    assert.ok(false, err.message);
                })
                .finally(() => {
                    done();
                });
        });
    });

    describe('is valid Primary tests', () => {
        beforeEach(() => {
            instance1 = {
                isPrimary: false,
                hostname: 'hostname1',
                mgmtIp: '1.2.3.4',
                privateIp: '1.2.3.4'
            };
            instance2 = {
                isPrimary: false,
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
        });

        it('is primary test', (done) => {
            provider.nodeProperties.instanceId = instanceId;

            provider.isValidPrimary(instanceId, instances)
                .then((isValid) => {
                    assert.ok(isValid);
                })
                .catch((err) => {
                    assert.ok(false, err.message);
                })
                .finally(() => {
                    done();
                });
        });

        it('no instance info test', (done) => {
            provider.s3.getObject = function getObject() {
                return {
                    promise() {
                        return q.reject();
                    }
                };
            };

            provider.isValidPrimary(instanceId, instances)
                .then((isValid) => {
                    assert.ok(isValid);
                })
                .catch((err) => {
                    assert.ok(false, err.message);
                })
                .finally(() => {
                    done();
                });
        });
    });

    describe('Primary elected tests', () => {
        beforeEach(() => {
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
        });

        it('instance protection set when primary test', (done) => {
            provider.primaryElected(instanceId)
                .then(() => {
                    assert.strictEqual(instanceProtectionParams.InstanceIds.length, 1);
                    assert.strictEqual(instanceProtectionParams.InstanceIds[0], instanceId);
                    assert.ok(instanceProtectionParams.ProtectedFromScaleIn);
                })
                .catch((err) => {
                    assert.ok(false, err.message);
                })
                .finally(() => {
                    done();
                });
        });

        it('instance protection not set when not primary test', (done) => {
            provider.primaryElected('foo')
                .then(() => {
                    assert.strictEqual(instanceProtectionParams, undefined);
                })
                .catch((err) => {
                    assert.ok(false, err.message);
                })
                .finally(() => {
                    done();
                });
        });

        it('other primaries set to non primary test', (done) => {
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
                                        isPrimary: true
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
                                    isPrimary: true
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

            provider.primaryElected(instanceId)
                .then(() => {
                    assert.strictEqual(instancePutId, '5678');
                    assert.strictEqual(instancePut.isPrimary, false);
                })
                .catch((err) => {
                    assert.ok(false, err.message);
                })
                .finally(() => {
                    done();
                });
        });
    });

    describe('tag Primary tests', () => {
        beforeEach(() => {
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
        });

        it('tag primary with stack name test', (done) => {
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
                },
                9012: {
                    LifecycleState: 'InService'
                }
            };

            const primaryId = '1234';

            const expectedDeleteTagsRequest = [
                {
                    Resources: ['5678'],
                    Tags: [
                        {
                            Key: 'StackName-primary',
                            Value: 'true'
                        }
                    ]
                },
                {
                    Resources: ['9012'],
                    Tags: [
                        {
                            Key: 'StackName-primary',
                            Value: 'true'
                        }
                    ]
                }
            ];

            provider.tagPrimaryInstance(primaryId, clusterInstances)
                .then(() => {
                    assert.strictEqual(passedDescribeTagsParams.Filters[0].Values[0], primaryId);
                    assert.deepEqual(passedCreateTagsParams,
                        {
                            Resources: ['1234'],
                            Tags: [
                                {
                                    Key: 'StackName-primary',
                                    Value: 'true'
                                }
                            ]
                        });
                    assert.deepEqual(deleteTagRequests, expectedDeleteTagsRequest);
                    assert.strictEqual(deleteTagRequests.length, 2);
                })
                .catch((err) => {
                    assert.ok(false, err.message);
                })
                .finally(() => {
                    done();
                });
        });

        it('tag primary single instance test', (done) => {
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
                }
            };

            const primaryId = '1234';

            provider.tagPrimaryInstance(primaryId, clusterInstances)
                .then(() => {
                    assert.strictEqual(deleteTagRequests.length, 0);
                })
                .catch((err) => {
                    assert.ok(false, err.message);
                })
                .finally(() => {
                    done();
                });
        });
    });

    describe('signal Instance Provisioned tests', () => {
        beforeEach(() => {
            provider.ec2 = {
                describeTags() {
                    const response = {
                        Tags: [
                            {
                                Key: 'aws:cloudformation:stack-name',
                                ResourceId: 'i-06b5bd27acbfa0cc3',
                                ResourceType: 'instance',
                                Value: 'StackName'
                            }
                        ]
                    };
                    return {
                        promise() {
                            return q(response);
                        }
                    };
                }
            };

            provider.cloudFormation = {
                listStackResources(params, cb) {
                    const response = {
                        StackResourceSummaries: [
                            {
                                LogicalResourceId: 'BigIpAutoScaleGroup',
                                ResourceType: 'AWS::AutoScaling::AutoScalingGroup'
                            }
                        ]
                    };
                    cb(null, response);
                },
                signalResource(params, cb) {
                    passedSignalResourceParams = params;
                    cb(null, '');
                }
            };
        });

        it('Signal Resource Call Success test', (done) => {
            provider.signalInstanceProvisioned('i-1234')
                .then(() => {
                    assert.deepEqual(passedSignalResourceParams, {
                        LogicalResourceId: 'BigIpAutoScaleGroup',
                        StackName: 'StackName',
                        Status: 'SUCCESS',
                        UniqueId: 'i-1234'
                    });
                })
                .catch((err) => {
                    assert.ok(false, err.message);
                })
                .done(() => {
                    done();
                });
        });

        it('Signal Resource no instance test', (done) => {
            provider.nodeProperties = {
                instanceId: 'i-1234',
                hostname: 'hostname'
            };

            provider.signalInstanceProvisioned()
                .then(() => {
                    assert.deepEqual(passedSignalResourceParams, {
                        LogicalResourceId: 'BigIpAutoScaleGroup',
                        StackName: 'StackName',
                        Status: 'SUCCESS',
                        UniqueId: 'i-1234'
                    });
                })
                .catch((err) => {
                    assert.ok(false, err.message);
                })
                .done(() => {
                    done();
                });
        });

        describe('errors tests', () => {
            it('Signal No Instance Stack Tag test', (done) => {
                provider.ec2 = {
                    describeTags() {
                        const response = {
                            Tags: [
                                {
                                    Key: 'aws:cloudformation:stack-id',
                                    Value: 'stack1'
                                }
                            ]
                        };
                        return {
                            promise() {
                                return q(response);
                            }
                        };
                    }
                };

                provider.signalInstanceProvisioned('i-1234')
                    .then(() => {
                        assert.ok(false, 'signalInstanceProvisioned should have thrown');
                    })
                    .catch((err) => {
                        assert.strictEqual(err.message, 'Cannot find stack-name for instance: i-1234');
                    })
                    .done(() => {
                        done();
                    });
            });

            it('Signal No Instance Tags test', (done) => {
                provider.ec2 = {
                    describeTags() {
                        return {
                            promise() {
                                return q.reject('Unable to get instance tags');
                            }
                        };
                    }
                };

                const expectedError = 'Unable to get stack-name from instance. Unable to get instance tags';

                provider.signalInstanceProvisioned('i-1234')
                    .then(() => {
                        assert.ok(false, 'signalInstanceProvisioned should have thrown');
                    })
                    .catch((err) => {
                        assert.strictEqual(err.message, expectedError);
                    })
                    .done(() => {
                        done();
                    });
            });
        });
    });
});
