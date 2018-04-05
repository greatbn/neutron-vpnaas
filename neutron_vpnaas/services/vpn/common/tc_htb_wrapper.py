#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

import re

from oslo_log import log as logging

from neutron.agent.linux import ip_lib
from neutron.agent.linux import tc_lib
from neutron.common import constants
from neutron.common import exceptions
from neutron_lib import constants as lib_constants

LOG = logging.getLogger(__name__)

QDISC_IN_REGEX = re.compile(r"qdisc ingress (\w+:) *")
QDISC_OUT_REGEX = re.compile(r"qdisc htb (\w+:) *")
FILTER_ID_REGEX = re.compile(r"filter protocol ip u32 fh (\w+::\w+) *")
FILTER_STATS_REGEX = re.compile(r"Sent (\w+) bytes (\w+) pkts *")
FILTER_ENTRY_REGEX = re.compile(
    r"filter protocol ip pref (\d+) u32 fh (\d+::\d+) .* "
    r"flowid (\d*:\d+)")
# U32_ENRTY_REGEX = re.compile(r"match IP (\w+) (\w+) (\d+|\d+[\d\.+])")
U32_IP_REGEX = re.compile(r"match IP (src|dst) ((?:\d+\.){3}\d+)/(\d+)")
U32_PROTOCOL_REGEX = re.compile(r"match IP protocol (\w+)")
U32_L4PORT_REGEX = re.compile(r"match (sport|dport) (\d+)")
SUBCLASS_QOS_REGEX = re.compile(
    r"class htb (\d+:(?:\d+)) parent (\d+:(?:\d+)) prio (\d+) rate (\w+) "
    r"ceil (\w+) burst (\w+) *")
MAINCLASS_QOS_REGEX = re.compile(
    r"class htb (\d+:(?:\d+)) root rate (\w+) ceil (\w+) burst (\w+) *")


class TcHTBCommand(ip_lib.IPDevice):

    def _execute_tc_cmd(self, cmd, **kwargs):
        cmd = ['tc'] + cmd
        ip_wrapper = ip_lib.IPWrapper(self.namespace)
        return ip_wrapper.netns.execute(cmd, run_as_root=True, **kwargs)

    def _get_qdiscs(self):
        cmd = ['qdisc', 'show', 'dev', self.name]
        return self._execute_tc_cmd(cmd)

    def _get_qdiscs_details(self):
        cmd = ['-s', '-d', 'qdisc', 'show', 'dev', self.name]
        return self._execute_tc_cmd(cmd)

    def _get_classes(self):
        cmd = ['class', 'show', 'dev', self.name]
        return self._execute_tc_cmd(cmd)

    def _format_the_corrent_unit(self, output):
        #Mbit => Kbit => bit
        output = list(output)
        for index in range(len(output)):
            if 'Mbit' in output[index]:
                value = output[index].split('Mbit')[0]
                value = str(int(value) * 1000 * 1000)
                output[index] = value + 'bit'
            elif 'Kbit' in output[index]:
                value = output[index].split('Kbit')[0]
                value = str(int(value) * 1000)
                output[index] = value + 'bit'
        return output

    def _get_class_by_classid(self, id):
        class_lines = self._get_classes().split('\n')
        for class_line in class_lines:
            m = SUBCLASS_QOS_REGEX.findall(class_line)
            if m and m[0][0] == id:
                actual = m[0]
                format_res = self._format_the_corrent_unit(actual)
                result = {'id': format_res[0],
                          'parent': format_res[1],
                          'prio': format_res[2],
                          'rate': tc_lib.convert_to_kilobits(
                              format_res[3], constants.SI_BASE),
                          'ceil': tc_lib.convert_to_kilobits(
                              format_res[4], constants.SI_BASE),
                          'burst': tc_lib.convert_to_kilobits(
                              format_res[5], constants.IEC_BASE)}
                return result['id'], result

    def _get_main_class_by_mainclassid(self, id):
        class_lines = self._get_classes().split('\n')
        for class_line in class_lines:
            m = MAINCLASS_QOS_REGEX.findall(class_line)
            if m and m[0] == id:
                self._format_the_corrent_unit(m)
            result = {'id': m[0],
                      'rate': tc_lib.convert_to_kilobits(
                          m[1], constants.SI_BASE),
                      'ceil': tc_lib.convert_to_kilobits(
                          m[2], constants.SI_BASE),
                      'burst': tc_lib.convert_to_kilobits(
                          m[3], constants.IEC_BASE)}
            return result['id'], result

    def _get_root_class(self):
        class_lines = self._get_classes().split('\n')
        for class_line in class_lines:
            m = MAINCLASS_QOS_REGEX.findall(class_line)
            if m:
                self._format_the_corrent_unit(m)
                result = {'id': m[0],
                          'rate': tc_lib.convert_to_kilobits(
                              m[1], constants.IEC_BASE),
                          'ceil': tc_lib.convert_to_kilobits(
                              m[2], constants.IEC_BASE),
                          'burst': tc_lib.convert_to_kilobits(
                              m[3], constants.IEC_BASE)}
                return result['id'], result

    def _get_classes_details(self):
        cmd = ['-s', '-d', 'class', 'show', 'dev', self.name]
        return self._execute_tc_cmd(cmd)

    def _get_filters(self, qdisc_id):
        cmd = ['-p', '-s', '-d', 'filter', 'show', 'dev', self.name,
               'parent', qdisc_id]
        return self._execute_tc_cmd(cmd)

    def _get_qdisc_id_for_filter(self, direction):
        qdisc_results = self._get_qdiscs().split('\n')
        for qdisc in qdisc_results:
            pattern = (QDISC_OUT_REGEX
                       if direction == lib_constants.EGRESS_DIRECTION
                       else QDISC_IN_REGEX)
            m = pattern.match(qdisc)
            if m:
                # No chance to get multiple qdiscs
                return m.group(1)

    def _add_root_qdisc(self, direction):
        if direction == lib_constants.EGRESS_DIRECTION:
            # TODO(zhaobo) default flowid should be used if possible
            args = ['root', 'handle', '1:', 'htb', 'default', '100']
        else:
            args = ['ingress']
        cmd = ['qdisc', 'add', 'dev', self.name] + args
        self._execute_tc_cmd(cmd)

    def _add_main_class(self, rate, ceil, burst, parent_qdisc_id='1:0',
                        main_class_id='1:1'):
        # Default main class id is 1:1, priority is 1,
        # why prio is 1, as fip_qos
        # setting the fip prio is 1.
        cmd = ['class', 'replace', 'dev', self.name, 'parent', parent_qdisc_id,
               'classid', main_class_id, 'htb', 'rate',
               str(rate) + 'Kbit', 'ceil', str(ceil) + 'Kbit',
               'burst', str(burst) + 'Kbit', 'prio', '1']
        self._execute_tc_cmd(cmd)

    def _add_sub_class(self, sub_class_id, rate, ceil, burst, prio='2',
                       main_class_id='1:1'):
        cmd = ['class', 'replace', 'dev', self.name, 'parent', main_class_id,
               'classid', sub_class_id, 'htb', 'rate',
               str(rate) + 'Kbit', 'ceil', str(ceil) + 'Kbit',
               'burst', str(burst) + 'Kbit', 'prio', prio]
        self._execute_tc_cmd(cmd)

    def _set_qdisc_scheduling_on_class(self, class_id, handle_id):
        # TODO(zhaobo) the perturb value is default
        cmd = ['qdisc', 'add', 'dev', self.name, 'parent', class_id,
               'handle', handle_id, 'sfq', 'perturb', '10']
        self._execute_tc_cmd(cmd)

    def _add_filter_by_fwmark(self, main_class_id, sub_class_id, fwmark):
        cmd = ['filter', 'replace', 'dev', self.name, 'classid',
               main_class_id, 'prio', '1', 'handle', fwmark, 'fw',
               'flowid', sub_class_id]
        self._execute_tc_cmd(cmd)

    def _add_filter_by_u32(self, qdisc_id, u32_cmd,
                           sub_class_id, filter_id=None):
        filter_cmd = ['handle', filter_id] if filter_id else []
        cmd = ['filter', 'replace', 'dev', self.name, 'parent', qdisc_id,
               'protocol', 'ip', 'prio', '1'] + filter_cmd + ['u32']
        cmd = cmd + u32_cmd + ['flowid', sub_class_id]
        self._execute_tc_cmd(cmd)

    def _get_filterid_for_ip(self, qdisc_id, ip):
        filterids_for_ip = []
        filters_output = self._get_filters(qdisc_id)
        if not filters_output:
            raise exceptions.FilterIDForIPNotFound(ip=ip)
        filter_lines = filters_output.split('\n')
        for line in filter_lines:
            line = line.strip()
            m = FILTER_ID_REGEX.match(line)
            if m:
                filter_id = m.group(1)
                # It matched, so ip/32 is not here. continue
                continue
            elif not line.startswith('match'):
                continue
            parts = line.split(" ")
            if ip + '/32' in parts:
                filterids_for_ip.append(filter_id)
        if len(filterids_for_ip) > 1:
            raise exceptions.MultipleFilterIDForIPFound(ip=ip)
        elif len(filterids_for_ip) == 0:
            raise exceptions.FilterIDForIPNotFound(ip=ip)
        return filterids_for_ip[0]

    def _get_filterid_prio_for_u32(self, qdisc_id, u32):
        # INPUT u32 could be:
        # {
        #     protocol: protocol_num,
        #     src_ipaddress: [src_ip, prefix],
        #     dst_ipaddress: [dst_ip, prefix],
        #     sport: port_num,
        #     dport: port_num
        # }
        # TODO(zhaobo) this function could be extend.
        filters_output = self._get_filters(qdisc_id)
        if not filters_output:
            # TODO(zhaobo) this error is confused
            # raise exceptions.FilterIDForIPNotFound(ip=ip)
            return None, None, None
        filter_lines = filters_output.split('\n')
        result = {}
        for index in range(len(filter_lines)):
            line = filter_lines[index].strip()
            m = FILTER_ENTRY_REGEX.findall(line)
            if m:
                prio, filter_id, class_id = m[0]
                continue
            elif not line.startswith('match'):
                continue
            elif (result and u32 != result and not line.startswith('match') and
                  index < len(filter_lines) - 1 and
                  not filter_lines[index + 1].strip().startswith('match')):
                prio, filter_id, class_id = None, None, None
                result = {}
                continue
            elif (result and u32 == result and
                  index < len(filter_lines) - 1 and
                  not line.startswith('match') and
                  not filter_lines[index + 1].strip().startswith('match')):
                return prio, filter_id, class_id
            (ip_prefixes, ip_protocols,
             l4_ports) = self._find_u32_fields_in_line(line)

            if ip_prefixes and self._match_u32_ip_prefix(ip_prefixes[0], u32):
                if not result:
                    result = {
                        ip_prefixes[0][0] + '_ipaddress': [
                            ip_prefixes[0][1], ip_prefixes[0][2]]}
                else:
                    result[ip_prefixes[0][0] + '_ipaddress'] = [
                            ip_prefixes[0][1], ip_prefixes[0][2]]
            elif ip_protocols and self._match_u32_protocol(
                    ip_protocols[0], u32):
                if not result:
                    result = {'protocol': ip_protocols[0]}
                else:
                    result['protocol'] = ip_protocols[0]
            elif l4_ports and self._match_u32_l4_port(l4_ports[0], u32):
                if not result:
                    result = {l4_ports[0][0]: l4_ports[0][1]}
                else:
                    result[l4_ports[0][0]] = l4_ports[0][1]
            if result and len(result.keys()) < 5:
                for key in ['protocol', 'src_ipaddress', 'dst_ipaddress',
                            'sport', 'dport']:
                    if key not in result.keys():
                        if key in ['src_ipaddress', 'dst_ipaddress']:
                            result[key] = []
                        else:
                            result[key] = None
            if result == u32 and ((index < len(filter_lines) - 1 and
                not filter_lines[index + 1].strip().startswith('match')) or
                index == len(filter_lines) - 1):
                return prio, filter_id, class_id
        return None, None, None

    def _match_u32_l4_port(self, actual, base):
        # INPUT u32 could be:
        # {
        #     protocol: protocol_num,
        #     src_ipaddress: [src_ip, prefix],
        #     dst_ipaddress: [dst_ip, prefix],
        #     sport: port_num,
        #     dport: port_num
        # }
        if not base['sport'] and not base['dport']:
            return False

        if (actual[0] == 'sport' and base['sport']) or (
                        actual[0] == 'dport' and base['dport']):
            return actual[1] == str(base['sport'])

        return False

    def _match_u32_protocol(self, actual, base):
        if not base['protocol']:
            return False

        return actual == str(base['protocol'])

    def _match_u32_ip_prefix(self, actual, base):
        if not base['src_ipaddress'] and not base['dst_ipaddress']:
            return False

        if (actual[0] == 'src' and base['src_ipaddress']) or (
                        actual[0] == 'dst' and base['dst_ipaddress']):
            key = actual[0] + '_ipaddress'
            return (actual[1] == str(base[key][0]) and
                    actual[2] == str(base[key][1]))

        return False

    def _find_u32_fields_in_line(self, input):
        ip_prefixes = U32_IP_REGEX.findall(input)
        ip_protocol_nums = U32_PROTOCOL_REGEX.findall(input)
        l4_ports = U32_L4PORT_REGEX.findall(input)
        return ip_prefixes, ip_protocol_nums, l4_ports

    def _del_filter_by_id(self, qdisc_id, filter_id):
        cmd = ['filter', 'del', 'dev', self.name,
               'parent', qdisc_id,
               'prio', 1, 'handle', filter_id, 'u32']
        self._execute_tc_cmd(cmd, extra_ok_codes=[1])

    def _del_class_by_id(self, id):
        cmd = ['class', 'del', 'dev', self.name, 'classid', id]
        self._execute_tc_cmd(cmd, extra_ok_codes=[1, 2])

    def _del_qdisc(self):
        cmd = ['qdisc', 'del', 'dev', self.name, 'root']
        self._execute_tc_cmd(cmd)

    def _get_qdisc_filters(self, qdisc_id):
        filterids = []
        filters_output = self._get_filters(qdisc_id)
        if not filters_output:
            return filterids
        filter_lines = filters_output.split('\n')
        for line in filter_lines:
            line = line.strip()
            m = FILTER_ID_REGEX.match(line)
            if m:
                filter_id = m.group(1)
                filterids.append(filter_id)
        return filterids

    def _add_filter(self, qdisc_id, direction, ip, rate, burst):
        rate_value = "%s%s" % (rate, tc_lib.BW_LIMIT_UNIT)
        burst_value = "%s%s" % (
            tc_lib.TcCommand.get_ingress_qdisc_burst_value(rate, burst),
            tc_lib.BURST_UNIT
        )
        protocol = ['protocol', 'ip']
        prio = ['prio', 1]
        if direction == lib_constants.EGRESS_DIRECTION:
            _match = 'src'
        else:
            _match = 'dst'
        match = ['u32', 'match', 'ip', _match, ip]
        police = ['police', 'rate', rate_value, 'burst', burst_value,
                  'drop', 'flowid', ':1']
        args = protocol + prio + match + police
        cmd = ['filter', 'replace', 'dev', self.name,
               'parent', qdisc_id] + args
        self._execute_tc_cmd(cmd)

    def _get_or_create_qdisc(self, direction):
        qdisc_id = self._get_qdisc_id_for_filter(direction)
        if not qdisc_id:
            self._add_root_qdisc(direction)
            qdisc_id = self._get_qdisc_id_for_filter(direction)
            if not qdisc_id:
                raise exceptions.FailedToAddQdiscToDevice(direction=direction,
                                                          device=self.name)
        return qdisc_id


class VpnTcCommand(TcHTBCommand):

    def __init__(self, name, namespace=None):
        super(VpnTcCommand, self).__init__(name, namespace=namespace)
        # {filter_id:
        #      {prio: X,
        #       u32:{
        #           protocol: p1,
        #           src_ipaddress: [src_ip, prefix],
        #           dst_ipaddress: [dst_ip, prefix],
        #           sport: port_num,
        #           dport: port_num
        #       }
        # }
        self.managed_filter_u32_mapping = {}
        # qdisc_id: {main_class: {class_id: id,
        #                         rate: rate,
        #                         ceil: ceil},
        #            sub_classes: [{class_id: id,
        #                           rate: rate,
        #                           ceil: ceil}]}
        self.managed_qdisc_class = {}

    def clear_all_filters(self, direction):
        qdisc_id = self._get_qdisc_id_for_filter(direction)
        if not qdisc_id:
            return
        filterids = self._get_qdisc_filters(qdisc_id)
        for filter_id in filterids:
            self._del_filter_by_id(qdisc_id, filter_id)

    def clear_vpn_filters(self):
        qdisc_id = self._get_qdisc_id_for_filter('egress')
        if not qdisc_id:
            return
        for fliter_id in self.managed_filter_u32_mapping.keys():
            self._del_filter_by_id(qdisc_id, fliter_id)
            del self.managed_filter_u32_mapping[fliter_id]

    def get_filter_id_for_u32(self, ip):
        qdisc_id = self._get_qdisc_id_for_filter('egress')
        if not qdisc_id:
            return
        prio, filter_id, class_id = self._get_filterid_for_prio_u32(
            qdisc_id, ip)
        return filter_id

    def get_existing_filter_ids(self, direction):
        qdisc_id = self._get_qdisc_id_for_filter(direction)
        if not qdisc_id:
            return
        current_filters = self._get_qdisc_filters(qdisc_id)
        missed_filters = set(self.managed_filter_u32_mapping.keys()) - set(
            current_filters)
        if (len(set(current_filters) -
            set(self.managed_filter_u32_mapping.keys())) == 0 and
            not missed_filters):
            return current_filters
        if missed_filters:
            for missed_filter in list(missed_filters):
                del self.managed_filter_u32_mapping[missed_filter]

    def delete_filter_ids(self, filterids):
        qdisc_id = self._get_qdisc_id_for_filter('egress')
        if not qdisc_id:
            return
        for filter_id in filterids:
            self._del_filter_by_id(qdisc_id, filter_id)

    def _genarate_request_u32_match_details(self, match_details):
        # match_details
        # {
        #     src_ipaddress: ip/prefix,
        #     protocol: protocol_num
        #  }
        # Backend need mode
        # {
        #     protocol: protocol_num,
        #     src_ipaddress: [src_ip, prefix],
        #     dst_ipaddress: [dst_ip, prefix],
        #     sport: port_num,
        #     dport: port_num
        # }
        if not match_details:
            return None

        m = match_details['src_ipaddress'].split('/')
        ip_address = m[0]
        prefix = m[1]
        protocol = match_details['protocol']
        return {
            'protocol': protocol,
            'src_ipaddress': [ip_address, prefix],
            'dst_ipaddress': [],
            'sport': None,
            'dport': None
        }

    def _genarate_u32_cmd(self, u32_req):
        # match_details
        # {
        #     src_ipaddress: ip/prefix,
        #     protocol: protocol_num
        #  }
        # Backend need mode
        # {
        #     protocol: protocol_num,
        #     src_ipaddress: [src_ip, prefix],
        #     dst_ipaddress: [dst_ip, prefix],
        #     sport: port_num,
        #     dport: port_num
        # }
        cmd = []
        for key in ['protocol', 'src_ipaddress', 'dst_ipaddress',
                    'sport', 'dport']:
            # As we had filled all of the value with None or []
            if u32_req[key]:
                if key == 'protocol':
                    cmd = cmd + ['match', 'ip', 'protocol', str(u32_req[key]),
                                 '0xff']
                elif 'ipaddress' in key:
                    direction = key.split('_')[0]
                    cmd = cmd + ['match', 'ip', direction,
                                 u32_req[key][0] + '/' + u32_req[key][1]]
                elif 'port' in key:
                    port_direction = key[0]
                    cmd = cmd + ['match', 'ip', port_direction + 'port',
                                 u32_req[key], '0xffff']
        return cmd

    def set_u32_rate_limit(self, match_details, rate,
                           burst, direction='egress'):
        # TODO(zhaobo) need to covert the rate/burst value to kilobits, as the
        qdisc_id = self._get_or_create_qdisc(direction)
        u32_req = self._genarate_request_u32_match_details(match_details)
        prio, filter_id, class_id = self._get_filterid_prio_for_u32(
            qdisc_id, u32_req)
        #burst = self._get_tbf_burst_value(rate, burst)
        if filter_id:
            LOG.debug("Filter %(filter)s for matching VPN "
                      "%(match_details)s in %(direction)s "
                      "qdisc already existed, checking class "
                      "configuration.",
                      {'filter': filter_id,
                       'match_details': match_details,
                       'direction': direction})
            subclass_id, subclass_details = self._get_class_by_classid(
                class_id)
            if subclass_details['rate'] == rate and subclass_details[
                'burst'] == burst:
                # As normalize, the subclass had matched
                # the request rate/burst,
                # so the mainclass could be not check.
                return
            else:
                # means there is a same filter configuration in current Router
                # qg interface.
                # Then we could create new main class with same u32, but the
                # ordered filter may let this configuration not available.
                # Check the priotity first, to check whether we can set the new
                # classifier.
                if prio <= 1:
                    # This will be failure, as the prio of subclass is 2. We
                    # could not override the configuration.
                    raise
                else:
                    # check the conflict mainclass ID.
                    mainclass_id = subclass_details['parent']
                    if mainclass_id != '1:1':
                        self._add_main_class(rate, rate, burst)
                        self._add_sub_class('1:100', rate, rate, burst)
                        u32_cmd = self._genarate_u32_cmd(u32_req)
                        self._add_filter_by_u32('1:', u32_cmd, '1:100')
                    else:
                        self._add_main_class(rate, rate, burst)
                        self._add_sub_class('1:100', rate, rate, burst)
                        u32_cmd = self._genarate_u32_cmd(u32_req)
                        self._add_filter_by_u32('1:', u32_cmd, '1:100',
                                                filter_id=filter_id)
        else:
            self._add_main_class(rate, rate, burst)
            self._add_sub_class('1:100', rate, rate, burst)
            u32_cmd = self._genarate_u32_cmd(u32_req)
            self._add_filter_by_u32('1:', u32_cmd, '1:100')
        LOG.debug("Filter %(filter)s for matching VPN "
                  "%(match_details)s in %(direction)s "
                  "qdisc is Done.",
                  {'filter': filter_id,
                   'match_details': match_details,
                   'direction': direction})

    def clear_u32_rate_limit(self, match_details, direction='egress'):
        qdisc_id = self._get_qdisc_id_for_filter(direction)
        if not qdisc_id:
            return
        u32_req = self._genarate_request_u32_match_details(match_details)
        prio, filter_id, class_id = self._get_filterid_prio_for_u32(
            qdisc_id, u32_req)
        if not filter_id:
            LOG.debug("No filter found for u32 %(u32_match)s in "
                      "%(direction)s, skipping deletion.",
                      {'u32_match': match_details,
                       'direction': direction})
        self._del_filter_by_id(qdisc_id, filter_id)
        if class_id:
            _, subclass_details = self._get_class_by_classid(class_id)
            self._del_class_by_id(class_id)
            self._del_class_by_id(subclass_details['parent'])
            self._del_qdisc()
