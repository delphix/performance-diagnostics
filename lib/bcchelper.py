#
# Copyright 2018, 2020 Delphix. All rights reserved.
#
# SPDX-License-Identifier: GPL-2.0-or-later
#

from time import time
from enum import Enum
import logging
import re
import signal
import subprocess

""" BCC Helper
This module contains the BCCHelper class to aid in writing BCC Tracing
scripts using a python front end and bpf C code.  See the bcc Reference
Guide.
https://github.com/iovisor/bcc/blob/master/docs/reference_guide.md#1-bpf

Defitions for C helper routines and macros are in
lib/bcc_helper.h

BCC Helper focuses are printing out data from a set of tracing aggregations.
There are three supported scalar types of aggregations(count, sum, and
aversum(which requires a separate count aggregation)), two histogram
aggregations(log histogram or linear log histogram), and a stand alone
average aggegation.  It is required that for each aggregation in the
helper there is BPF_HASH in the C code that uses a common hash key.
The key is defined as a C struct with a required first member of timestamp(t)
and a required last member of cpuid.  Other key members can be added for the
key types needed for that collector.  For example the structure for the
default nfs collector has an op value to keep separate reads and write
statistics.

typedef struct {
    u64  t;
    char op[OP_NAME_LEN];
    u32  cpuid;
} nfs_key_t;

The C HIST_KEY macro defines histogram key that is derived from the
base aggregation key and adds a slot elemtent.  For example, the
nfs_hist_key_t is define with the following macro:

HIST_KEY(nfs_hist_key_t, nfs_key_t);

This is the structure that is defined:

typedef struct {
    nfs_key_t agg_key;
    u64       slot;
} nfs_hist_key_t;

See appliance/server/core/src/main/resources/analytics/nfs_layer_linux.st
for an example of how to structure C bcc code.  In the python code a
BPF object and an equality function for the key structure are required
to initialize a bcc Helper.  The equality function should return true
for keys that match in all member fields except the cpuid.  Aggregation
and key type objects are added to the helper that describe what is being
traced.  With this initialization, the helper printall method can be called
repeatedly.  Each call will clear all the aggregation items since
the last one and output the data.  The values for each timestamp are
kept separate.  Within each timestamp the values from different
cpus(cpuid) are combined for matching keys for each aggregation.
IF ANALYTICS_PRINT_MODE is specified json objects are generated with
the value of each aggregation for each timestamp suitable to be used
by the appliance analytics system such as:

{"t":"1565031672", "op":"write", "count":"92", "throughput":"645120", \
"avgLatency":"609497", "latency":" \
{500000,17},{600000,38},{700000,21},{800000,6},{900000,9},{2000000,1},"}

The default output mode produces human readable output showing for the
purpose of debugging:

count[1565031672, write] = 92

throughput[1565031672, write] = 645120

avgLatency[1565031672, write] = 609497

latency[1565031672, write] =
500000		17
600000		38
700000		21
800000		6
900000		9
2000000		1
"""


class BCCHelper:
    SUM_AGGREGATION = 0
    COUNT_AGGREGATION = 1
    AVERAGE_AGGREGATION = 2
    AVERSUM_AGGREGATION = 3
    STDDEV_AGGREGATION = 4
    # Logic in isHistogram() requires Histogram values > other aggregations
    LOG_HISTOGRAM_AGGREGATION = 5
    LL_HISTOGRAM_AGGREGATION = 6
    DEFAULT_PRINT_MODE = 0
    ANALYTICS_PRINT_MODE = 1
    ESTAT_PRINT_MODE = 2
    #
    # For each key type, python string post-processing can be added in
    # key_type_string(); much easier than in the bcc C code.
    #
    DEFAULT_KEY_TYPE = 0
    IP_KEY_TYPE = 1
    CUSTOM_KEY_TYPE = 2
    MAP_INDEX_TYPE = 3
    # Format string for print histograms
    ESTAT_HIST_FORMAT = '{:<16} {:>16} {:<41}'
    ESTAT_HEADER_FORMAT = '   {:<20}{:>49}'
    ESTAT_SCALAR_FORMAT = '{:>17}'
    ESTAT_TITLE_FORMAT = '{:<30}'
    HISTOGRAM_AMPERSAND_WIDTH = 40

    def __init__(self, b, mode=DEFAULT_PRINT_MODE):
        """ Initialize a bcchelper for a specific bpf instance given a
        key equality functions.
        """
        self.b = b
        self.mode = mode
        self.epoch_time_delta = 0
        self.aggregations = []
        self.key_types = []
        self.normalize_aggregations = []
        logging.basicConfig(level=logging.CRITICAL,
                            format='%(asctime)s - %(levelname)s - %(message)s')
        self.logger = logging.getLogger()

        #
        # Try to run atexit handlers if we are killed by a signal. BCC
        # registers handlers to detach kprobes, and if these aren't run the
        # probes are leaked.
        #
        def _handler(signum, frame):
            exit(1)
        signal.signal(signal.SIGTERM, _handler)

    @staticmethod
    def isHistogram(agg):
        return (agg[1] >= BCCHelper.LOG_HISTOGRAM_AGGREGATION)

    def key_equals(self, key1, key2):
        """ Compare two keys, checking the timestamp item and
        all key types in the helper.
        """
        if key1.t != key2.t:
            return False

        for keyt in self.key_types:
            if getattr(key1, keyt[0]) != getattr(key2, keyt[0]):
                return False

        return True

    def next_key(self, agg_items):
        """ Look at the head item of each aggregation's list and
        return the aggregation key for the earliest entry
        """
        key = None
        iagg = 0
        for agglist in agg_items:
            if len(agglist) > 0:
                head = agglist[0]
                if self.isHistogram(self.aggregations[iagg]):
                    nkey = head[0].agg_key
                else:
                    nkey = head[0]
                if key is None or nkey.t < key.t:
                    key = nkey
            iagg += 1
        return key

    def add_aggregation(self, name, type, display_name=None):
        """ Add an aggregatation to print out. """

        if type == self.AVERSUM_AGGREGATION:
            #
            # An aversum can only be added if there is a count aggregation
            # that can be used to calculate the average
            #
            hascount = False
            for v in self.aggregations:
                hascount = hascount or (v[1] == self.COUNT_AGGREGATION)
            if not hascount:
                self.logger.error(
                        "Error: Aversum aggregation requires a count")
                return
        if type == self.STDDEV_AGGREGATION:
            #
            # An aversum can only be added if there is an aversum aggregation
            # that can be used to calculate the average
            #
            hasaver = False
            for v in self.aggregations:
                hasaver = hasaver or (v[1] == self.AVERSUM_AGGREGATION)
            if not hasaver:
                self.logger.error(
                        "Error: Stddev aggregation requires an aversum")
                return

        try:
            if display_name is None:
                display_name = name
            self.aggregations.append([name, type, self.b.get_table(name),
                                     display_name])
        except KeyError:
            print("Error : " + name + " aggregation not found in BPF object")
            raise

    def normalize(self, name, norm_factor):
        """Normalize an aggregation using the supplied factor."""
        agg_found = False
        for a in self.aggregations:
            if a[0] == name:
                agg_found = True
        if not agg_found:
            print("Error : " + name +
                  " aggregation not found in BPF object, can't be normalized")
            raise

        # Remove existing normalization entry before adding a new one
        for n in self.normalize_aggregations:
            if n[0] == name:
                self.normalize_aggregations.remove(n)
                break
        self.normalize_aggregations.append((name, norm_factor))

    def apply_normalization(self, name, value):
        """Apply normalization if specified."""
        for n in self.normalize_aggregations:
            if n[0] == name:
                value = value // n[1]
        return value

    def add_key_type(self, name, type=None, display_function=None):
        """This key type expected in all aggregation keys."""
        if type is None:
            type = self.DEFAULT_KEY_TYPE
        self.key_types.append([name, type, display_function])

    def walltime(self, ktime):
        """Convert to an epoch timestamp."""
        if self.epoch_time_delta == 0:
            self.epoch_time_delta = int(time()) - ktime

        return (ktime + self.epoch_time_delta)

    def log_lin_hist_value(self, slot):
        """
        The C code log_lin_hist_slot(<latency value>), returns a "slot value"
        that indicates the histogram bucket for the given <latency value>.
        Consider example range: 10000ns (10 microsecs) to 10000000000ns (10
        seconds), that is: [10000, 100000, 1000000, 10000000, 100000000,
        1000000000, 10000000000].  The "slot" values 0-8 => bucket 10000,
        values 9-18 => bucket 100000, values 19-28 => bucket 1000000 and so on
        upto slot=59-68 for bucket 10000000000

        This method, given the "slot value", maps it back to
        equivalent histogram buckets
        Example:
        Input "slot values" 4, 19 will return: 50000, 1000000
        (indicating buckets 10000, 1000000 these belong to)
        So, corresponding latency histogram would be:
        "latency":"{{50000,2},{1000000,1}}"  (latency bucket, I/O count)
        """
        mag_values = [10000, 100000, 1000000, 10000000, 100000000,
                      1000000000, 10000000000]
        idx = slot // 10
        if idx >= len(mag_values):
            self.logger.debug("log_lin_hist_value slot: %d out of range", slot)
            return -1
        else:
            value = mag_values[idx]
            value += value * (slot % 10)

        return value

    @staticmethod
    def log_hist_value_str(slot):
        if slot < 10:
            return str(pow(2, slot))
        elif slot < 20:
            return str(pow(2, slot-10)) + "K"
        elif slot < 30:
            return str(pow(2, slot-20)) + "M"
        elif slot < 40:
            return str(pow(2, slot-30)) + "G"
        elif slot < 50:
            return str(pow(2, slot-40)) + "T"
        elif slot < 60:
            return str(pow(2, slot-50)) + "P"

        return str(pow(2, slot-60)) + "E"

    @staticmethod
    def get_ampersand_string(value, total):
        retstr = "|"
        for i in range(((value-1) *
                       BCCHelper.HISTOGRAM_AMPERSAND_WIDTH // total) + 1):
            retstr += "@"
        return retstr

    def histogram_entry(self, hist_type, slot, value, total):
        """ Generate the text for one entry in a histogram"""
        if self.mode == self.ANALYTICS_PRINT_MODE:
            if hist_type == BCCHelper.LOG_HISTOGRAM_AGGREGATION:
                return "{" + str(pow(2, slot) - 1) + "," + \
                      str(value) + "}"
            else:
                return "{" + str(self.log_lin_hist_value(slot)) + \
                         "," + str(value) + "}"
        else:
            rangestr = "["
            if hist_type == BCCHelper.LOG_HISTOGRAM_AGGREGATION:
                if (slot > 0):
                    rangestr += BCCHelper.log_hist_value_str(slot-1)
                else:
                    rangestr += "0"
                rangestr += ", "
                rangestr += BCCHelper.log_hist_value_str(slot) + ")"
            else:
                #
                # latency histograms are captured in nanosecs
                # using log_lin_hist_slot(), so convert to microseconds
                #
                if (slot > 0):
                    rangestr += str(self.log_lin_hist_value(slot - 1)//1000)
                else:
                    rangestr += "0"
                rangestr += ", "
                rangestr += str(self.log_lin_hist_value(slot)//1000) + ")"
            return "\n" + self.ESTAT_HIST_FORMAT.format(
                rangestr, str(value),
                BCCHelper.get_ampersand_string(value, total))

    def output_histogram(self, hist_items, hist_type):
        """ Output a histogram
        The hist_items all have the same key values but different cpu
        ids and slots.  Sort the items by slot and then sum up the hit
        count values for all the items for each slot as the list is
        traversed.  When a new slot is encountered, add an entry to the
        output for the old slot.
        """
        if len(hist_items) == 0:
            if self.mode == self.ANALYTICS_PRINT_MODE:
                return "{ }"
            return ""

        h = ""

        total = 0
        if self.mode != self.ANALYTICS_PRINT_MODE:
            h += '\n'
            h += self.ESTAT_HIST_FORMAT.format(
                "value range", "count",
                "------------- Distribution -------------")
            for k, v in hist_items:
                total += v.value

        hist_items.sort(key=lambda x: x[0].slot)
        slot = -1
        value = 0
        for k, v in hist_items:
            if slot != k.slot and slot != -1:
                h += self.histogram_entry(hist_type, slot, value, total)
                if self.mode == self.ANALYTICS_PRINT_MODE:
                    h += ","
                value = 0
            slot = k.slot
            value += v.value
        h += self.histogram_entry(hist_type, slot, value, total)
        return h

    def aggregation_lookup(self, items, key):
        """ Search key-value list for items that match a key"""
        agg_items = []
        for item in items:
            if self.key_equals(item[0], key):
                agg_items.append(item)

        return agg_items

    def histogram_lookup(self, items, key):
        """ Search histogram list for items that match the aggregation key.
        The top level key has two parts: agg_key and slot.  All items that
        match the agg_key go into one histogram.
        """
        hist_items = []
        for item in items:
            if self.key_equals(item[0].agg_key, key):
                hist_items.append(item)

        return hist_items

    def key_type_string(self, key, key_type):
        """
        Generate the output string for a member of a key.  The value collected
        is post-processed based on the key type:
          DEFAULT_KEY_TYPE - no post-processing needed
          IP_KEY_TYPE - strips unwanted symbols from IPV4 literal address
        """
        attr = getattr(key, key_type[0])
        if type(attr) is bytes:
            keystr = attr.decode('utf-8', errors='backslashreplace')
        else:
            keystr = str(attr)

        # Extract IPv4 literal address, often preceded by "*," or ","
        if key_type[1] == self.IP_KEY_TYPE:
            match = re.search(r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", keystr)
            #
            # Update key if IP match was found, if there is no match return
            # the raw key back unchanged
            #
            if match:
                keystr = str(match.group())
        elif key_type[1] == self.CUSTOM_KEY_TYPE:
            keystr = key_type[2](keystr)
        elif key_type[1] == self.MAP_INDEX_TYPE:
            keystr = key_type[2].displayName(int(keystr))

        return keystr

    def combined_average(self, agg_items):
        """ combine values from a list of average aggregations items"""
        sum = 0
        count = 0
        for item in agg_items:
            sum += item[1].sum
            count += item[1].count

        if count:
            return sum // count
        else:
            return 0

    def combined_scalar_value(self, agg_items):
        """ combine values from a list of scalar aggregations items"""
        value = 0
        if len(agg_items) == 0:
            return value

        for item in agg_items:
            value += item[1].value
        return value

    def get_ordered_items(self, clear):
        """ clear all data items from aggregations in the helper and sort them
        so that items with the same key signatures are together.  The items are
        key-value pairs.  For the scalar aggregations the key will be made of
        of key types corresponding to the key structure used in bcc collection
        code(see module comment).  The aggregation type determines the type of
        value.  For example, the items for the count aggregation might look
        like this for the default nfs collector.  The key is a tuple with a
        timestamp, an operation string and a cpuid.
        { (1565031673, "read", 342) : 1}
        { (1565031672, "write", 342) : 40}
        { (1565031672, "read", 342) : 2}
        { (1565031672, "write", 76) : 52}
        The items are sorted so by the key signature (all items except the
        cpu id) that items with the same signature can be easily combined.
        { (1565031672, "read", 342) : 2}
        { (1565031672, "write", 342) : 40}
        { (1565031672, "write", 76) : 52}
        { (1565031673, "read", 342) : 1}
        """
        agg_items = []

        # Copy the data out of the aggregation tables and clear them
        for agg in self.aggregations:
            table = agg[2]
            items = table.items()
            if clear:
                table.clear()
            #
            # Sort aggregation items so datapoints with the same key signatures
            # but different cpu ids with be grouped together
            #
            if self.isHistogram(agg):
                for key in self.key_types:
                    items.sort(key=lambda x: getattr(x[0].agg_key, key[0]))
                items.sort(key=lambda x: x[0].agg_key.t)
            else:
                for key in self.key_types:
                    items.sort(key=lambda x: getattr(x[0], key[0]))
                items.sort(key=lambda x: x[0].t)
            agg_items.append(items)

        return agg_items

    def get_key_output_string(self, key):
        """ Generate a string to output a key in the specified mode.
        For analytics mode generate json with key value pairs for
        the time stamp and each element, such as:
            {"t":"1565031672", "op":"write"
        For default mode output the values as an associative array index:
            [1565031672, write]"""
        if self.mode == self.ANALYTICS_PRINT_MODE:
            keystr = "{\"t\":\"" + str(self.walltime(key.t)) + "\""
            for key_type in self.key_types:
                keystr += ", \"" + key_type[0] + "\":\"" + \
                        self.key_type_string(key, key_type) + "\""
        else:
            keystr = "[" + str(self.walltime(key.t))
            for key_type in self.key_types:
                keystr += ", "
                keystr += self.key_type_string(key, key_type)
            keystr += "]"
        return keystr

    def get_matching_items(self, agg, agg_items, key):
        """ Get a list of items that match a key. There are multiple
        items as there can be one for each running cpu.
        """
        if self.isHistogram(agg):
            items = self.histogram_lookup(agg_items, key)
        else:
            items = self.aggregation_lookup(agg_items, key)
        return items

    def combine_items(self, agg, items, count_val, aversum_val):
        """ Combine items with the same key to produce one value.  The
        aggregation type determines what is needed to combine values.
        """
        if self.isHistogram(agg):
            com_val = self.output_histogram(items, agg[1])
        else:
            if len(items) == 0:
                com_val = 0
            elif agg[1] == self.AVERAGE_AGGREGATION:
                com_val = self.combined_average(items)
            else:
                com_val = self.combined_scalar_value(items)
                if agg[1] == self.AVERSUM_AGGREGATION:
                    if count_val:
                        com_val = com_val // count_val
                    else:
                        com_val = 0
                elif agg[1] == self.STDDEV_AGGREGATION:
                    if count_val and aversum_val:
                        com_val = com_val // count_val - (
                            aversum_val * aversum_val)
                    else:
                        com_val = 0
        return com_val

    def remove_items(self, agg_items, items):
        """ Remove items already processed from the agg_items list.
        """
        for item in items:
            agg_items.remove(item)

    def items_to_string(self, agg_items):
        """ The output string for the agg_items contains records for each
        key signature in agg_items.  Each record will include the values of
        the key types and a value from each aggregation.  Not all aggregations
        are guaranteed to have a item for each key signature due to race
        conditions around the edge of collection interval boundaries.  Some
        aggregations with have multiple items with the same signature from
        different cpus.  These items will be combined into one value.  The
        records are ordered by timestamps.
        """
        outstr = ""
        #
        # During the body of the loop a record for each base_key will be added
        # to outstr.  The record contains a value for each aggregation that is
        # produces by combining the values from all that aggregation's items
        # that match base_key.  Note that a value doesn't mean a scalar value,
        # e.g. a value for a histogram aggregation is a single histogram.
        # Those matching items will also be removed from agg_items so that the
        # calls to next_key() will iterate through all keys leaving agg_items
        # empty.
        #
        base_key = self.next_key(agg_items)
        estat_scalar_header = self.ESTAT_TITLE_FORMAT.format("")
        estat_scalar_table = ""
        while base_key is not None:
            keystr = self.get_key_output_string(base_key)
            stripped_key = ""
            try:
                stripped_key = keystr[keystr.index(',')+1:len(keystr)-1]
                stripped_key = stripped_key.strip()
                if stripped_key[-1:] == ",":
                    stripped_key = stripped_key[:-1]
            except ValueError:
                pass

            estat_header_line = self.ESTAT_TITLE_FORMAT.format("")
            estat_scalar_line = self.ESTAT_TITLE_FORMAT.format(stripped_key)
            estat_has_scalar = False
            # analytic records include the keystr at the begginning of json
            if self.mode == self.ANALYTICS_PRINT_MODE:
                outstr += keystr

            # add the value from each aggregation to this record
            count_val = 0
            aversum_val = 0
            iagg = 0
            for agg in self.aggregations:
                items = self.get_matching_items(agg, agg_items[iagg], base_key)
                val = self.combine_items(agg, items, count_val, aversum_val)
                self.remove_items(agg_items[iagg], items)
                #
                # save the value from COUNT aggregations to be used by any
                # following AVERSUM aggregations, see add_aggregation()
                #
                if agg[1] == self.COUNT_AGGREGATION:
                    count_val = val
                elif agg[1] == self.AVERSUM_AGGREGATION:
                    aversum_val = val
                iagg = iagg + 1

                val = self.apply_normalization(agg[0], val)
                if self.mode == self.ANALYTICS_PRINT_MODE:
                    outstr += ", \"" + agg[3] + "\":\""
                    outstr += str(val)
                    outstr += "\""
                elif self.mode == self.ESTAT_PRINT_MODE:
                    if self.isHistogram(agg):
                        #        keystr[2:len(keystr)-1])
                        outstr += self.ESTAT_HEADER_FORMAT.format(agg[3],
                                                                  stripped_key)
                        outstr += str(val)
                        outstr += "\n\n"
                    else:
                        estat_has_scalar = True
                        estat_header_line += \
                            self.ESTAT_SCALAR_FORMAT.format(agg[3])
                        estat_scalar_line += \
                            self.ESTAT_SCALAR_FORMAT.format(val)

                else:
                    outstr += agg[3] + keystr + " = "
                    outstr += str(val)
                    outstr += "\n\n"

            # close the json for analytic records
            if self.mode == self.ANALYTICS_PRINT_MODE:
                outstr += "}\n\n"
            elif self.mode == self.ESTAT_PRINT_MODE and estat_has_scalar:
                estat_scalar_table += estat_scalar_line + "\n"
                estat_scalar_header = estat_header_line

            base_key = self.next_key(agg_items)

        if self.mode == self.ESTAT_PRINT_MODE:
            if estat_scalar_table != "":
                outstr += estat_scalar_header + "\n"
                outstr += estat_scalar_table + "\n\n"

        return outstr

    def printall(self, clear=True):
        """ Print and clear all data from aggregations in the helper."""
        agg_items = self.get_ordered_items(clear)
        outstr = self.items_to_string(agg_items)
        print(outstr, end='', flush=True)


class BCCMapIndex(Enum):
    """Provides index constants for bcc map keys"""
    def __init__(self, index, csymbol, display):
        self.index = index
        self.csymbol = csymbol
        self.display = display

    def index(self):
        """The int value for this index."""
        return self.index

    def display(self):
        """The display string for this index"""
        return self.display

    def definition(self):
        """The CPP definition for this index"""
        return "-D" + self.csymbol + "=" + str(self.index) + ""

    @classmethod
    def list(cls):
        """List all indices in a subclass"""
        return list(map(lambda c: c.value, cls))

    @classmethod
    def displayName(cls, i):
        """The display name for a subclass index"""
        return list(map(lambda c: c.value, cls))[i][2]

    @classmethod
    def getCDefinitions(cls):
        """Definitions for bcc C code"""
        defs = []
        for index in cls:
            defs.append(index.definition())
        return defs


class BCCPerCPUIntArray:
    """Provide output support for a PerCPU Array indexed by a BCCMapIndex"""
    def __init__(self, b, name, mapindex):
        self.table = b[name]
        self.name = name
        self.mapindex = mapindex

    def printall(self, clear=True):
        """ Print and clear all data from aggregations in the helper."""
        items = self.table.items()
        if (clear):
            self.table.clear()

        for item in items:
            key = item[0]
            value = item[1]
            sum = 0
            # sum the values for each cpu
            for v in value:
                sum += v
            if sum > 0:
                print('{:20}'.format(self.mapindex.displayName(key.value)) +
                      ' : ' + str(sum))


class BCCPoolCompare:
    """Provide code to test for a zfs pool instance"""
    def __init__(self, pool_name):
        """leverage sdb to get a pointer for a pool name"""
        self.pool_name = pool_name
        pool_match = re.search(r'0x\w+', subprocess.getoutput(
                               "sudo sdb -e \'spa " + self.pool_name + "\'"))
        if pool_match:
            self.pool_pointer = pool_match.group(0)
        else:
            self.pool_pointer = None

    def get_pool_pointer(self):
        """Return the kernel address for the spa_t object"""
        return self.pool_pointer

    def get_pool_compare_code(self):
        """Generate C POOL_COMPARE macro"""
        if not self.pool_pointer:
            return "#define POOL_COMPARE(spa) 1"
        return str("#define POOL_COMPARE(spa) ((ulong)spa == " +
                   self.pool_pointer + ")")
