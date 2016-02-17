#!/usr/bin/python

#      Licensed to the Apache Software Foundation (ASF) under one
#      or more contributor license agreements.  See the NOTICE file
#      distributed with this work for additional information
#      regarding copyright ownership.  The ASF licenses this file
#      to you under the Apache License, Version 2.0 (the
#      "License"); you may not use this file except in compliance
#      with the License.  You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
#      Unless required by applicable law or agreed to in writing,
#      software distributed under the License is distributed on an
#      "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
#      KIND, either express or implied.  See the License for the
#      specific language governing permissions and limitations
#      under the License.

import ConfigParser
import base64
import argparse
import os
import urllib2
import socket
import time
import pynag
from datetime import datetime, timedelta

try:
    import json
except ImportError:
    import simplejson as json

try:
    import netsnmp
except ImportError:
    pass


class CritError(Exception):
    def __init__(self, message):
        plugin = pynag.Plugins.PluginHelper()
        plugin.exit(exit_code=pynag.Plugins.critical, long_output="CRITICAL: %s" % message)


class NexentaApi:
    # Get the connection info and build the api url.
    def __init__(self, api_user, api_pass, api_ssl, ip, api_port, nms_retry):
        self.nms_retry = nms_retry

        if not api_user or not api_pass:
            raise CritError("No connection info configured for %s" % ip)
        if not self.nms_retry:
            self.nms_retry = 2

        if api_ssl != 'ON':
            protocol = 'http'
        else:
            protocol = 'https'

        if not api_port:
            api_port = 2000

        self.base64_string = base64.encodestring('%s:%s' % (api_user, api_pass))[:-1]
        self.url = "%s://%s:%s/rest/nms/ <%s://%s:%s/rest/nms/>" % (protocol, ip, api_port, protocol, ip, api_port)

    # Build the request and return the response.
    def get_data(self, obj, method, params):
        data = {'object': obj, 'method': method, 'params': params}
        data = json.dumps(data)
        request = urllib2.Request(self.url, data)
        request.add_header('Authorization', "Basic %s" % self.base64_string)
        request.add_header('Content-Type', 'application/json')

        # Try to connect max <nms_retry> times. Sleep 20 seconds if NMS connection error occurs.
        tries = int(self.nms_retry)
        while tries:
            try:
                response = json.loads(urllib2.urlopen(request).read())
                if response['error']:
                    if 'Cannot introspect object com.nexenta.nms' in response['error']['message']:
                        raise Exception('NMS unresponsive')

                    raise CritError("API error occured: %s" % response['error'])

                return response['result']

            except (urllib2.URLError, Exception):
                tries += -1
                time.sleep(20)

        raise CritError("Unable to connect to API at %s" % self.url)


class SnmpRequest:
    # Read config file and build the NDMP session.
    def __init__(self, snmp_user, snmp_pass, snmp_community, ip, snmp_port):
        if not snmp_port:
            snmp_port = 161

        # If username/password use SNMP v3, else use SNMP v2.
        if snmp_user and snmp_pass:
            self.session = netsnmp.Session(DestHost="%s:%s" % (ip, snmp_port), Version=3, SecLevel='authNoPriv',
                                           AuthProto='MD5', AuthPass=snmp_pass, SecName=snmp_user)
        elif snmp_community:
            self.session = netsnmp.Session(DestHost="%s:%s" % (ip, snmp_port), Version=2, Community=snmp_community)
        else:
            raise CritError("Incorrect SNMP info configured for %s" % ip)

    # Return the SNMP get value.
    def get_snmp(self, oid):
        value = netsnmp.VarList(netsnmp.Varbind(oid))

        if not self.session.get(value):
            return None
        else:
            return value[0].val

    # Return the SNMP walk values.
    def walk_snmp(self, oid):
        values = netsnmp.VarList(netsnmp.Varbind(oid))

        if not self.session.walk(values):
            return None
        else:
            return values


class NexentaCheck:
    """
    :type config: ConfigParser.ConfigParser
    :type plugin: pynag.Plugins.PluginHelper
    :type nexenta: Nexenta
    :type api: NexentaApi
    :type snmpRequest: SnmpRequest
    """
    config = None
    plugin = None
    nexenta = None
    api = None
    snmpRequest = None

    def __init__(self, plugin, nexenta, configfile):
        self.nexenta = nexenta
        self.plugin = plugin
        self.plugin.add_status('ok')

        self.open_config(configfile)
        self.api = NexentaApi(
            self.get_option(nexenta['hostname'], 'api_user'),
            self.get_option(nexenta['hostname'], 'api_pass'),
            self.get_option(nexenta['hostname'], 'api_ssl'),
            nexenta['ip'],
            self.get_option(nexenta['hostname'], 'api_port'),
            self.get_option(nexenta['hostname'], 'nms_retry')
        )

        try:
            netsnmp
        except NameError:
            pass
        #     self.plugin.add_status('warning')
        #     self.plugin.add_long_output(
        #         'WARNING: net-snmp-python not available, SNMP Performance Data will be skipped.')
        else:
            snmp_user = self.get_option(nexenta['hostname'], 'snmp_user')
            snmp_pass = self.get_option(nexenta['hostname'], 'snmp_pass')
            snmp_community = self.get_option(nexenta['hostname'], 'snmp_community')
            snmp_port = self.get_option(nexenta['hostname'], 'snmp_port')
            if (snmp_user and snmp_pass) or snmp_community:
                self.snmpRequest = SnmpRequest(snmp_user, snmp_pass, snmp_community, self.nexenta['ip'], snmp_port)

    def critical_error(self, message):
        self.plugin.exit(exit_code=pynag.Plugins.critical, long_output=message)

    def open_config(self, configfile):
        self.config = ConfigParser.ConfigParser()
        try:
            self.config.readfp(open(configfile))
        except IOError:
            self.critical_error("Can not open configuration file: %s" % configfile)

    def get_option(self, section, option):
        try:
            return self.config.get(section, option)
        except ConfigParser.NoOptionError:
            return None
        except ConfigParser.NoSectionError:
            self.critical_error("%s not defined in config file!" % section)

    def known_errors_in_config(self, message):
        for known in self.config.options('known_errors'):
            if known in message.lower():
                return self.config.get('known_errors', known)
        return None

    def known_errors(self, result):
        severity = []
        description = []

        # Check if part of the message matches a string in the config file.
        known_error = self.known_errors_in_config(result['description'])
        if known_error:
            # Match found, return severity/description.
            try:
                severity, description = known_error.split(';')
            except ValueError:
                self.critical_error("Error in config file at [known_errors], line: %s" % known_error)

            if not severity.upper() in ('DEFAULT', 'WARNING', 'CRITICAL', 'UNKNOWN', 'IGNORE'):
                self.critical_error("Invalid severity in config file at [known_errors], line: %s" % known_error)

        if not description:
            # No match found or only severity match found, append default if defined in the config file.
            default = self.get_option('known_errors', 'DEFAULT')
            if default:
                # Get the default description and append it
                try:
                    description = default.split(';')[1]
                except ValueError:
                    self.critical_error("Error in config file at [known_errors], line: %s" % default)

                description = "%s %s" % (result['description'], description)

                # Get the default severity if there was no match in the config file
                if not severity:
                    try:
                        severity = default.split(';')[0]
                    except ValueError:
                        self.critical_error("Error in config file at [known_errors], line: %s" % default)
            else:
                # No default found, pass the original description
                description = result['description']

        # If default or no match, pass the original severity
        if not severity or severity.upper() == 'DEFAULT':
            severity = result['severity']

        return severity.upper(), description

    @staticmethod
    def convert_space(size):
        size_types = {'B': 1, 'K': 1024, 'M': 1048576, 'G': 1073741824, 'T': 1099511627776}
        try:
            return float(size[:-1]) * int(size_types[size[-1:]])
        except (KeyError, ValueError):
            return 0

    # Check volume space usage.
    def check_spaceusage(self):

        # Only check space usage if space thresholds are configured in the config file.
        thresholds = self.get_option(self.nexenta['hostname'], 'space_threshold')
        if thresholds:
            # Get a list of all volumes and add syspool.
            volumes = self.api.get_data(obj='folder', method='get_names', params=[''])
            volumes.extend(["syspool"])

            for vol in volumes:
                # Skip this volume if no match and no default in thresholds.
                if not (vol + ';' in thresholds or 'DEFAULT;' in thresholds):
                    continue

                for threshold in thresholds.split('\n'):
                    if not threshold:
                        continue

                    # Check/extend the thresholds.
                    if len(threshold.split(';')) == 3:
                        threshold += ';IGNORE;IGNORE'
                    elif len(threshold.split(';')) != 5:
                        raise CritError(
                            "Error in config file at [%s]:space_threshold, line %s" % (
                                self.nexenta['hostname'],
                                threshold
                            )
                        )

                    # Get the thresholds, or fall back to the default tresholds.
                    if vol + ';' in thresholds:
                        if threshold.split(';')[0] == vol:
                            volwarn, volcrit, snapwarn, snapcrit = threshold.split(';')[1:]
                    elif 'DEFAULT;' in thresholds:
                        if threshold.split(';')[0] == 'DEFAULT':
                            volwarn, volcrit, snapwarn, snapcrit = threshold.split(';')[1:]

                # Get volume properties.
                volprops = self.api.get_data(obj='folder', method='get_child_props', params=[vol, ''])

                # Get used/available space.
                available = volprops.get('available')
                snapused = volprops.get('usedbysnapshots')
                volused = self.convert_space(volprops.get('used'))

                snapusedprc = (self.convert_space(snapused) / (volused + self.convert_space(available))) * 100
                volusedprc = (volused / (volused + self.convert_space(available))) * 100

                # Check if a snapshot threshold has been met.
                if snapwarn[:-1].isdigit():
                    if '%' in snapwarn:
                        if int(snapwarn[:-1]) <= snapusedprc:
                            self.plugin.add_status('warning')
                            self.plugin.add_long_output(
                                "WARNING: %s%% of %s used by snaphots" % (int(snapusedprc), vol))
                    elif self.convert_space(snapwarn) <= self.convert_space(snapused):
                        self.plugin.add_status('warning')
                        self.plugin.add_long_output("WARNING: %s of %s used by snaphots" % (snapused, vol))

                if snapcrit[:-1].isdigit():
                    if '%' in snapcrit:
                        if int(snapcrit[:-1]) <= snapusedprc:
                            self.plugin.add_status('critical')
                            self.plugin.add_long_output(
                                "CRITICAL: %s%% of %s used by snaphots" % (int(snapusedprc), vol))
                    elif self.convert_space(snapcrit) <= self.convert_space(snapused):
                        self.plugin.add_status('critical')
                        self.plugin.add_long_output("CRITICAL: %s of %s used by snaphots" % (snapused, vol))

                # Check if a folder threshold has been met.
                if volcrit[:-1].isdigit():
                    if '%' in volcrit:
                        if int(volcrit[:-1]) <= volusedprc:
                            self.plugin.add_status('critical')
                            self.plugin.add_long_output("CRITICAL: %s %s%% full!" % (vol, int(volusedprc)))
                            continue
                    elif self.convert_space(volcrit) >= self.convert_space(available):
                        self.plugin.add_status('critical')
                        self.plugin.add_long_output("CRITICAL: %s %s available!" % (vol, available))
                        continue

                if volwarn[:-1].isdigit():
                    if '%' in volwarn:
                        if int(volwarn[:-1]) <= volusedprc:
                            self.plugin.add_status('warning')
                            self.plugin.add_long_output("WARNING: %s %s%% full" % (vol, int(volusedprc)))
                    elif self.convert_space(volwarn) >= self.convert_space(available):
                        self.plugin.add_status('warning')
                        self.plugin.add_long_output("WARNING: %s %s available" % (vol, available))

    # Check Nexenta runners for faults.
    def check_triggers(self):
        # Check all triggers, if skip_triggers is not set to 'on' in the config file.
        skip = self.get_option(self.nexenta['hostname'], 'skip_trigger')
        if skip != 'ON':
            triggers = self.api.get_data(obj='reporter', method='get_names_by_prop', params=['type', 'trigger', ''])
            for trigger in triggers:
                results = self.api.get_data(obj='trigger', method='get_faults', params=[trigger])
                for result in results:
                    result = results[result]

                    # Convert severity/description.
                    severity, description = self.known_errors(result)
                    # Only append if severity is not 'IGNORE'
                    if not severity == 'IGNORE':
                        if severity == 'CRITICAL':
                            self.plugin.add_status('critical')
                        elif severity == 'UNKNOWN':
                            self.plugin.add_status('unknown')
                        else:
                            self.plugin.add_status('warning')

                        self.plugin.add_long_output("%s:%s: %s" % (trigger, severity, description))

    # Get snmp extend data and write to Output and/or Perfdata.
    def collect_extends(self):
        # Collect snmp extend data, if snmp_extend is configured in the config file for this Nexenta.
        extend = self.get_option(self.nexenta['hostname'], 'snmp_extend')
        if extend == 'ON' and self.snmpRequest:
            # Snmp walk through all extends and collect the data.
            extends = self.snmpRequest.walk_snmp('NET-SNMP-EXTEND-MIB::nsExtendOutLine')
            if extends:
                for data in extends:
                    if 'PERFDATA:' in data.val:
                        self.plugin.add_metric(perfdatastring=data.val.split('PERFDATA:')[1])
                    elif 'OUTPUT:' in data.val:
                        self.plugin.add_metric(perfdatastring=data.val.split('OUTPUT:')[1])

                        if 'CRITICAL' in data.val:
                            self.plugin.add_status('critical')
                        elif 'WARNING' in data.val:
                            self.plugin.add_status('warning')

    # Collect Nexenta performance data.
    def collect_perfdata(self):
        # Collect SNMP performance data, if snmp is configured in the config file for this Nexenta.
        if self.snmpRequest:
            # Get CPU usage.
            cpu_info = self.snmpRequest.walk_snmp('HOST-RESOURCES-MIB::hrProcessorLoad')
            if cpu_info:
                for cpu_id, cpu_load in enumerate(cpu_info):
                    self.plugin.add_metric(label="CPU%s used" % cpu_id, value="%s%%" % cpu_load.val)

            # Get Network Traffic.
            interfaces = self.snmpRequest.walk_snmp('IF-MIB::ifName')
            if interfaces:
                for interface in interfaces:
                    intraffic = self.snmpRequest.get_snmp('IF-MIB::ifHCInOctets.%s' % interface.iid)
                    outtraffic = self.snmpRequest.get_snmp('IF-MIB::ifHCOutOctets.%s' % interface.iid)
                    intraffic = int(intraffic) * 8
                    outtraffic = int(outtraffic) * 8

                    self.plugin.add_metric(label="%s Traffic in" % interface.val, value="%sc" % intraffic)
                    self.plugin.add_metric(label="%s Traffic out" % interface.val, value="%sc" % outtraffic)

        # Collect API performance data, if api is configured in the config file for this Nexenta.
        volumes = []

        # Get perfdata for all volumes, or only for syspool if skip_folderperf is set to 'on'.
        skip = self.get_option(self.nexenta['hostname'], 'skip_folderperf')
        if skip != 'ON':
            volumes.extend(self.api.get_data(obj='folder', method='get_names', params=['']))

        volumes.extend(['syspool'])

        for vol in volumes:
            # Get volume properties.
            volprops = self.api.get_data(obj='folder', method='get_child_props', params=[vol, ''])

            # Get volume used, free and snapshot space.
            used = self.convert_space(volprops.get('used')) / 1024
            free = self.convert_space(volprops.get('available')) / 1024
            snap = self.convert_space(volprops.get('usedbysnapshots')) / 1024

            if self.get_option(self.nexenta['hostname'], 'skip_perf_usage') == 'False':
                self.plugin.add_metric(label="/%s used" % vol, value="%sKB" % int(used))
            if self.get_option(self.nexenta['hostname'], 'skip_perf_free') == 'False':
                self.plugin.add_metric(label="/%s free" % vol, value="%sKB" % int(free))
            if self.get_option(self.nexenta['hostname'], 'skip_perf_snapshot') == 'False':
                self.plugin.add_metric(label="/%s snapshot" % vol, value="%sKB" % int(snap))

            # Get compression ratio, if compression is enabled.
            compression = volprops.get('compression')
            if compression == 'on':
                ratio = volprops.get('compressratio')

                self.plugin.add_metric(label="/%s compressratio" % vol, value="%s" % ratio[:-1])

        # Get memory used, free and paging.
        memstats = self.api.get_data(obj='appliance', method='get_memstat', params=[''])

        self.plugin.add_metric(label="Memory free", value="%sMB" % int(memstats.get('ram_free')))
        self.plugin.add_metric(label="Memory used",
                               value="%sMB" % (memstats.get('ram_total') - memstats.get('ram_free')))
        self.plugin.add_metric(label="Memory paging", value="%sMB" % memstats.get('ram_paging'))

    # Check age of AutoSync snapshots
    def check_snapshot_age(self):
        max_age = int(self.get_option(self.nexenta['hostname'], 'snapshot_max_age'))

        # Check all triggers, if skip_triggers is not set to 'on' in the config file.
        threshold_time = datetime.now() - timedelta(hours=max_age)

        snapshots = self.api.get_data(obj='snapshot', method='get_names', params=['AutoSync'])

        if not snapshots:
            self.plugin.add_status('critical')
            self.plugin.add_long_output('CRITICAL: No AutoSync snapshots found')

            return

        newest_snapshot_info = {'timestamp': None, 'name': ''}

        for snapshot in snapshots:
            result = self.api.get_data(obj='snapshot', method='get_child_props', params=[snapshot, ''])

            timestamp = datetime.fromtimestamp(float(result['creation_seconds']))
            if not newest_snapshot_info['timestamp'] or newest_snapshot_info['timestamp'] < timestamp:
                newest_snapshot_info = {'timestamp': timestamp, 'name': result['name']}

        timediff = datetime.now() - newest_snapshot_info['timestamp']
        self.plugin.add_metric(
            label="Snapshot age: %s" % newest_snapshot_info['name'],
            value="%0.1f" % (timediff.total_seconds() / 60 / 60)
        )

        if newest_snapshot_info['timestamp'] < threshold_time:
            self.plugin.add_status('critical')
            self.plugin.add_long_output(
                '%s: Snapshot "%s" is older than %d hours' % ('CRITICAL', newest_snapshot_info['name'], max_age)
            )


def main():
    argument_parser = argparse.ArgumentParser(
        description='Script to provide performance data and monitor the health of Nexenta clusters and nodes.'
    )
    argument_parser.add_argument(
        '-H', '--hostname',
        required=True,
        action='store',
        dest='hostname',
        help='Nexenta to check. Can be hostname or IP address. Must be configured in the config file.'
    )
    argument_parser.add_argument(
        '-D', '--space_usage',
        help='Check space usage of volumes. Thresholds are configured in the config file.',
        action='store_true'
    )
    argument_parser.add_argument(
        '-T', '--triggers',
        help='Check fault triggers.',
        action='store_true'
    )
    argument_parser.add_argument(
        '-P', '--perfdata',
        action='store_true',
        help='Report SNMP performance data. Must be configured in the config file. Reports data for CPU, Disk, ' +
             'Snapshot, Memory and Network.'
    )
    argument_parser.add_argument(
        '-E', '--extend_data',
        action='store_true',
        help='Report SNMP extend data. Must be configured in the config file.'
    )
    argument_parser.add_argument(
        '-f', '--configfile',
        action='store',
        dest='configfile',
        help='Nexenta to check. Can be hostname or IP address. Must be configured in the config file.'
    )
    argument_parser.add_argument(
        '-S', '--autosync',
        action='store_true',
        help='Check age of AutoSync snapshots.'
    )
    argument_parser.add_argument('-V, --version', action='version', version='%(prog)s 2.0.0')
    arguments = argument_parser.parse_args()

    nexenta = arguments.hostname

    try:
        nexenta = {'hostname': nexenta, 'ip': socket.getaddrinfo(nexenta, None)[0][4][0]}
    except NameError:
        raise CritError('Invalid arguments, no hostname specified!')
    except socket.gaierror:
        raise CritError('No IP address found for %s!' % nexenta)

    # check if only hostname was given
    given_arguments = [argument for argument in arguments.__dict__
                       if arguments.__dict__[argument] and argument != 'hostname']
    if not given_arguments:
        arguments.space_usage = True
        arguments.triggers = True

    # Check configfile for path, append script path if no path was given.
    # Default to <scriptname>.cfg if no configfile was given.
    if not arguments.configfile:
        arguments.configfile = os.path.splitext(os.path.abspath(__file__))[0] + '.cfg'
    elif not os.path.dirname(arguments.configfile):
        arguments.configfile = os.path.join(os.path.dirname(__file__), arguments.configfile)

    # Open the configfile for use and start the checks.
    now = datetime.now()

    plugin = pynag.Plugins.PluginHelper()
    plugin.add_summary("Last check: {}".format(now))

    check = NexentaCheck(plugin, nexenta, arguments.configfile)

    if arguments.space_usage:
        check.check_spaceusage()

    if arguments.triggers:
        check.check_triggers()

    if arguments.extend_data:
        check.collect_extends()

    if arguments.perfdata:
        check.collect_perfdata()

    if arguments.autosync:
        check.check_snapshot_age()

    plugin.exit()


if __name__ == '__main__':
    main()
