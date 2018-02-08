# -*- coding: utf8 -*-
"""
check_checkpoint
Paraidomat

Check if your Check Point Firewalls feel great!

Resources:
    * CheckPoint SNMP Best Practices:
        * http://downloads.checkpoint.com/dc/download.htm?ID=31396
    * Nagios-Plugins Development Guidelines:
        * https://nagios-plugins.org/doc/guidelines.html#AEN200
"""

import sys, getopt, ipaddress
from pysnmp.hlapi import *
from pysnmp.entity.rfc3413.oneliner import cmdgen

# Global Variabled
EXITMESSAGES_D = {0: "OK", 1: "WARNING", 2: "CRITICAL", 3: "UNKOWN"}
IF_MIB_D = {
    "ifDescr": {
        "oid": "1.3.6.1.2.1.2.2.1.2",
        "description": "Returns a list of all known interfaces"
    },
    "ifType": {
        "oid": "1.3.6.1.2.1.2.2.1.3",
        "description": "Returns a list of the interface Type"
    },
    "ifMtu": {
        "oid": "1.3.6.1.2.1.2.2.1.4",
        "description": "Returns a list of the Interface MTUs"
    },
    "ifSpeed": {
        "oid": "1.3.6.1.2.1.2.2.1.5",
        "description": "Returns a list of interface Speed"
    },
    "ifPhysAddress": {
        "oid": "1.3.6.1.2.1.2.2.1.6",
        "description": "Returns a list of interface Speed"
    },
    "ifAdminStatus": {
        "oid": "1.3.6.1.2.1.2.2.1.7",
        "description": "Returns a list of interface admin status"
    },
    "ifOperStatus": {
        "oid": "1.3.6.1.2.1.2.2.1.8",
        "description": "Returns a list of interface operational status"
    },
    "ifInDiscards": {
        "oid": "1.3.6.1.2.1.2.2.1.13",
        "description": "Input Discards"
    },
    "ifInErrors": {
        "oid": "1.3.6.1.2.1.2.2.1.14",
        "description": "Input Errors"
    },
    "ifOutDiscards": {
        "oid": "1.3.6.1.2.1.2.2.1.15",
        "description": "Output Discards"
    },
    "ifOutErrors": {
        "oid": "1.3.6.1.2.1.2.2.1.20",
        "description": "Output Errors"
    },
    "ifOutQLen": {
        "oid": "1.3.6.1.2.1.2.2.1.21",
        "description": "Output queue"
    },
}
CHECKPOINT_MIB_D = {
    "CPU": {
        "procUsage": {
            "oid": "1.3.6.1.4.1.2620.1.6.7.2.4",
            "description": "Overall percentage of CPU utilization",
            "warning": 80,
            "critical": 90
        },
        "multiProcUsage": {
            "oid": "1.3.6.1.4.1.2620.1.6.7.5.1.5",
            "description": "Usage of each CPU",
            "warning": 80,
            "critical": 90
        }
    },
    "Memory": {
        "TotalReal64": {
            "oid": "1.3.6.1.4.1.2620.1.6.7.4.3",
            "description":
                "Total real memory in bytes. Memory used by applications"
        },
        "FreeReal64": {
            "oid": "1.3.6.1.4.1.2620.1.6.7.4.5",
            "description": "Free memory available for applications in bytes.",
            "warning": 80,
            "critical": 90
        },
    },
    "Disk": {
        "Name": {
            "oid": "1.3.6.1.4.1.2620.1.6.7.6.1.2",
            "description": "Partition Name"
        },
        "FreeAvailablePercent": {
            "oid": "1.3.6.1.4.1.2620.1.6.7.6.1.8",
            "description": "Percentage of available free disk in partition",
            "warning": 75,
            "critical": 85
        },
        "raidDiskState": {
            "oid": "1.3.6.1.4.1.2620.1.6.7.7..1.9",
            "description": "RAID disk status"
        }
    },
    "Hardware": {
        "PSU": {
            "Index": {
                "oid": "1.3.6.1.4.1.2620.1.6.7.9.1.1.1",
                "description": "Power Supply Index"
            },
            "powerSupplyInfoStatus": {
                "oid": "1.3.6.1.4.1.2620.1.6.7.9.1.1.2"
            }
        },
        "Fan": {
            "Index": {
                "oid": "1.3.6.1.4.1.2620.1.6.7.8.2.1.1",
                "description": "Fan Index"
            },
            "Name": {
                "oid": "1.3.6.1.4.1.2620.1.6.7.8.2.1.2",
                "description": "Fan Name"
            },
            "Speed": {
                "oid": "1.3.6.1.4.1.2620.1.6.7.8.2.1.3",
                "description": "rotations per minute"
            },
            "Status": {
                "oid": "1.3.6.1.4.1.2620.1.6.7.8.2.1.6",
                "description": "0= OK, Otherwise=Problem"
            }
        },
        "Temperature": {
            "Index": {
                "oid": "1.3.6.1.4.1.2620.1.6.7.8.1.1.1",
                "description": "Sensor Index"
            },
            "Name": {
                "oid": "1.3.6.1.4.1.2620.1.6.7.8.1.1.2",
                "description": "Sensor Name"
            },
            "Temperature": {
                "oid": "1.3.6.1.4.1.2620.1.6.7.8.1.1.3",
                "description": "Temperature in °C"
            },
            "Status": {
                "oid": "1.3.6.1.4.1.2620.1.6.7.8.1.1.6",
                "descroption": "0= OK, Otherwise=Problem"
            }
        }
    },
    "Network": {
        "fwPacketsRate": {
            "oid": "1.3.6.1.4.1.2620.1.1.25.6",
            "description": "Accepted packets per second"
        },
        "fwDroppedTotalRate": {
            "oid": "1.3.6.1.4.1.2620.1.1.25.16",
            "description": "Dropped packets per second"
        },
        "fwNumConn": {
            "oid": "1.3.6.1.4.1.2620.1.1.25.3",
            "description": "Number of concurrent IPv6 and IPv4 connections",
            "warning": 400000,
            "critical": 500000
        },
        "fwAccepted": {
            "oid": "1.3.6.1.4.1.2620.1.1.4",
            "description": "The number of accepted packets."
        },
        "fwDropped": {
            "oid": "1.3.6.1.4.1.2620.1.1.6",
            "description": "The number of dropped packets."
        }
    },
    "Cluster": {
        "haState": {
            "oid": "1.3.6.1.4.1.2620.1.5.6",
            "description":
                "Member HA-State (string) - active / standby / active attention / down"
        }
    }

}
MODE_L = ["cpu", "memory", "disk", "hardware", "network", "cluster"]
HA_STATES = ["active", "standby"]
IP_ADDRESS_S = ""
COMMUNITY_STRING_S = ""
CLUSTER_S = ""

def opt_error(err=None):
    """ Return an error message, print the script's usage, and return 3 to the
    OS.

    Keyword arguments:
    err -- the error message to be printed (default None)
    """

    if err:
        print(err)
    print("check_checkpoint -i <ip_address> -c <community-strig> -m <mode>")
    # Print all available modes
    print("Available modes: ".join(MODE_L))

    sys.exit(3)  # Return Code 3, um "UNKOWN" zu signalisieren.

def snmp_get(oid_s):
    """ Get data via SNMP using an OID.

    Keyword arguments:
    oid_s -- string which contains the OID.
    """

    cmd_gen = cmdgen.CommandGenerator()  # initialize CommandGenerator

    error_indication, error_status, error_index, var_bind_table = cmd_gen.nextCmd(
        cmdgen.CommunityData(COMMUNITY_STRING_S),
        cmdgen.UdpTransportTarget((IP_ADDRESS_S, 161)),
        oid_s,
        lookupNames=True,
        lookupValues=True
    )

    if error_index:  # should there be an error
        opt_error("SNMP Error: %s" % error_indication)
    elif error_status:  # different case of error
        opt_error("SNMP Error: %s at %s" % (
            error_status.prettyPrint(),
            error_index and varBinds[int(error_index) - 1][0] or "?"))
    else:  # wenn alles in Ordnung ist gebe die Tabelle zurück.
        return var_bind_table

def generate_performance_data(label="", value="", uom="", warning="", critical="", minimum="", maximum=""):
    """ return a performance data string

    Keyword arguments:
    label -- The label for the performance data
    value -- The actual measured value
    uom -- unit of measurement
    warning -- the warning threshold
    critical -- the critical threshold
    minimum -- the minium value
    maximum -- the maximum value
    """

    return "%s=%s%s;%s;%s;%s;%s" % (str(label), str(value), str(uom), str(warning),
                                    str(critical), str(minimum), str(maximum))


def cpu():
    """ Analyze the current cpu usage. """

    cpu_usage_l = []
    critical = CHECKPOINT_MIB_D["CPU"]["procUsage"]["critical"]
    warning = CHECKPOINT_MIB_D["CPU"]["procUsage"]["warning"]

    procUsage_table = snmp_get(CHECKPOINT_MIB_D["CPU"]["procUsage"]["oid"])
    procUsage = procUsage_table[0][0][-1]
    cpu_usage_l.append(procUsage)
    performance_data_s = generate_performance_data("overall", procUsage, "%", warning, critical)

    multiProcUsage_table = snmp_get(
        CHECKPOINT_MIB_D["CPU"]["multiProcUsage"]["oid"])
    for multiProcUsage_table_row in multiProcUsage_table:
        for key, value in multiProcUsage_table_row:
            cpu_usage_l.append(value)
            performance_data_s = "%s %s" % (
                performance_data_s,
                generate_performance_data(str(key).split(".")[-2],
                                          value, "%",
                                          warning, critical))

    if all(values < warning for values in cpu_usage_l):
        print(EXITMESSAGES_D[0], "- CPU load is", procUsage,
              "% |", performance_data_s)
        return 0
    elif any(values < critical for values in cpu_usage_l):
        print(EXITMESSAGES_D[1], "- CPU load is", max(cpu_usage_l),
              "% |", performance_data_s)
        return 1
    elif any(values > critical for values in cpu_usage_l):
        print(EXITMESSAGE_D[2], "- CPU load is ", max(cpu_usage_l),
              "% |", performance_data_s)
        return 2
    else:
        print(EXITMESSAGE_D[3], " - Error while analyzing values")
        return 3

    pass


def memory():
    """ Analyze the current memory usage"""

    critical = CHECKPOINT_MIB_D["Memory"]["FreeReal64"]["critical"]
    warning = CHECKPOINT_MIB_D["Memory"]["FreeReal64"]["warning"]

    total_memory_table = snmp_get(
        CHECKPOINT_MIB_D["Memory"]["TotalReal64"]["oid"])
    total_memory = int(total_memory_table[0][0][-1])

    free_memory_table = snmp_get(
        CHECKPOINT_MIB_D["Memory"]["FreeReal64"]["oid"])
    free_memory = int(free_memory_table[0][0][-1])

    memory_used = total_memory - free_memory

    performance_data_s = generate_performance_data(
        label="memory_usage",
        value=str(int(memory_used / (1000 ** 2))),
        uom="MB",
        warning=str(int(total_memory * warning / 100 / (1000 ** 2))),
        critical=str(int(total_memory * critical / 100 / (1000 ** 2))),
        maximum=str(int(total_memory / (1000 ** 2))))

    if memory_used < int(total_memory * warning / 100):
        print(EXITMESSAGES_D[0], "- Memory Usage is",
              int((memory_used / total_memory) * 100),
              "% |", performance_data_s)
        return 0
    elif memory_used < int(total_memory * critical / 100):
        print(EXITMESSAGES_D[1], "- Memory Usage is",
              int((memory_used / total_memory) * 100),
              "% |", performance_data_s)
        return 1
    elif memory_used > int(total_memory * critical / 100):
        print(EXITMESSAGES_D[2], "- Memory Usage is",
              int((memory_used / total_memory) * 100),
              "% |", performance_data_s)
        return 2
    else:
        print(EXITMESSAGE_D[3], " - Error while analyzing values")
        return 3


def disk():
    """ Analyze currecnt disk usage """

    critical = CHECKPOINT_MIB_D["Disk"]["FreeAvailablePercent"]["critical"]
    warning = CHECKPOINT_MIB_D["Disk"]["FreeAvailablePercent"]["warning"]

    partition_name_l = []
    partition_used_l = []
    performance_data_s = ""

    name_table = snmp_get(CHECKPOINT_MIB_D["Disk"]["Name"]["oid"])
    for name_table_row in name_table:
        for key, value in name_table_row:
            partition_name_l.append(str(value))

    free_available_percent = snmp_get(
        CHECKPOINT_MIB_D["Disk"]["FreeAvailablePercent"]["oid"])
    for free_available_percent_row in free_available_percent:
        for key, value in free_available_percent_row:
            partition_used_l.append(100 - int(value))

    disk_data_l = zip(partition_name_l, partition_used_l)

    for name, value in disk_data_l:
        performance_data_s = "%s %s" % (
            performance_data_s,
            generate_performance_data(name, value, "%", warning, critical))

    if all(values < warning for names, values in disk_data_l):
        print(EXITMESSAGES_D[0], "- Disk load is okay |", performance_data_s)
        return 0
    elif any(values < critical for names, values in disk_data_l):
        print(EXITMESSAGES_D[1], "- Disk load is high |", performance_data_s)
        return 1
    elif any(values > critical for names, values in disk_data_l):
        print(EXITMESSAGES_D[2], "- Disk load is dangerously high |",
              performance_data_s)
        return 2
    else:
        print(EXITMESSAGE_D[3], " - Error while analyzing values")
        return 3


def hardware():
    """ Analyze the health of the hardware components. """
    exitstatus_l = []

    # PSUs: (no Performance-Data):
    broken_psus_l = []
    working_psus_l = []
    psu_table = snmp_get(
        CHECKPOINT_MIB_D["Hardware"]["PSU"]["powerSupplyInfoStatus"]["oid"])
    for psu_table_row in psu_table:
        for key, value in psu_table_row:
            if str(value) != "Up":
                exitstatus_l.append(2)
                broken_psus_l.append(str(key).split(".")[-2])
            else:
                exitstatus_l.append(0)
                working_psus_l.append(str(key).split(".")[-2])

    # FANs: (no Performance-Data)
    broken_fans_l = []
    working_fans_l = []
    fan_name_table = snmp_get(
        CHECKPOINT_MIB_D["Hardware"]["Fan"]["Name"]["oid"])
    fan_status_table = snmp_get(
        CHECKPOINT_MIB_D["Hardware"]["Fan"]["Status"]["oid"])

    for fan_status_table_row in fan_status_table:
        for key, value in fan_status_table_row:
            key = int(str(key).split(".")[-2]) - 1
            fan_name = str(fan_name_table[key][0][-1]).replace(" ", "_")
            fan_name = str(nam_name).replace("\t", "_")
            if value != 0:
                exitstatus_l.append(2)
                broken_fans_l.append(fan_name)
            else:
                exitstatus_l.append(0)
                working_fans_l.append(fan_name)

    # Temperature: (with! Performance-Data)
    broken_sensors_l = []
    working_sensors_l = []
    performance_data_s = ""

    sensor_name_table = snmp_get(
        CHECKPOINT_MIB_D["Hardware"]["Temperature"]["Name"]["oid"])
    sensor_status_table = snmp_get(
        CHECKPOINT_MIB_D["Hardware"]["Temperature"]["Status"]["oid"])
    sensor_value_table = snmp_get(
        CHECKPOINT_MIB_D["Hardware"]["Temperature"]["Temperature"]["oid"])

    for sensor_status_table_row in sensor_status_table:
        for key, value in sensor_status_table_row:
            key = int(str(key).split(".")[-2]) - 1
            sensor_name = str(sensor_name_table[key][0][-1]).replace(" ", "_")
            sensor_name = str(sensor_name).replace("\t", "_")
            if value != 0:
                exitstatus_l.append(2)
                broken_sensors_l.append(sensor_name)
            else:
                exitstatus_l.append(0)
                working_sensors_l.append(sensor_name)

            performance_data_s = "%s %s" % (
                performance_data_s,
                generate_performance_data(
                    str(sensor_name_table[key][0][-1]).replace(" ", "_"),
                    sensor_value_table[key][0][-1]))

    if any(value == 2 for value in exitstatus_l):
        exitmessage = EXITMESSAGES_D[0]
        if len(broken_psus_l) != 0:
            exitmessage = "%s %s" % (exitmessage, "Broken PSUs: ")
            for psu in broken_psus_l:
                exitmessage = "%s %s" % (exitmessage, str(psu))
        if len(broken_fans_l) != 0:
            exitmessage = "%s %s" % (exitmessage, "Broken FANs: ")
            for fan in broken_fans_l:
                exitmessage = "%s %s" % (exitmessage, str(fan))
        if len(broken_sensors_l) != 0:
            exitmessage = "%s %s" % (exitmessage, "Temperature critical: ")
            for sensor in broken_sensors_l:
                exitmessage = "%s %s" % (exitmessage, str(sensor))
        exitmessage = "%s|%s" % (exitmessage, performance_data_s)
        print(exitmessage)
    else:
        print(EXITMESSAGES_D[0], "PSUs, FANs and Temperature is okay |",
              performance_data_s)

    return max(exitstatus_l)


def network():
    """ Analyze Network Traffic.

    This only is used to generate performance data """

    fw_packet_rate_table = snmp_get(
        CHECKPOINT_MIB_D["Network"]["fwPacketsRate"]["oid"])
    fw_dropped_total_rate_table = snmp_get(
        CHECKPOINT_MIB_D["Network"]["fwDroppedTotalRate"]["oid"])
    fw_number_of_connections_table = snmp_get(
        CHECKPOINT_MIB_D["Network"]["fwNumConn"]["oid"])
    fw_accepted_packets_table = snmp_get(
        CHECKPOINT_MIB_D["Network"]["fwAccepted"]["oid"])
    fw_dropped_packets_table = snmp_get(
        CHECKPOINT_MIB_D["Network"]["fwDropped"]["oid"])
    warning = CHECKPOINT_MIB_D["Network"]["fwNumConn"]["warning"]
    critical = CHECKPOINT_MIB_D["Network"]["fwNumConn"]["warning"]

    fw_packet_rate = fw_packet_rate_table[0][0][-1]
    fw_dropped_total_rate = fw_dropped_total_rate_table[0][0][-1]
    fw_number_of_connections = fw_number_of_connections_table[0][0][-1]
    fw_accepted_packets = fw_accepted_packets_table[0][0][-1]
    fw_dropped_packets = fw_dropped_total_rate_table[0][0][-1]

    performance_data_s = "%s %s %s" % (
        generate_performance_data(label="Number_of_accepted_packets",
                                  value=str(int(fw_accepted_packets))),
        generate_performance_data(label="Number_of_dropped_packets",
                                  value=str(int(fw_dropped_packets))),
        generate_performance_data(label="Number_of_concurrent_connections",
                                  value=str(int(fw_number_of_connections))))

    if fw_number_of_connections > critical:
        print(EXITMESSAGES_D[2], fw_number_of_connections,
              "concurrent Sessions! |", performance_data_s)
        return 2
    elif fw_number_of_connections >= warning:
        print(EXITMESSAGES_D[1], fw_number_of_connections,
              "concurrent Sessions! |", performance_data_s)
        return 1
    elif fw_number_of_connections < warning:
        print(EXITMESSAGES_D[0], fw_number_of_connections,
              "concurrent Sessions |", performance_data_s)
        return 0
    else:
        print(EXITMESSAGES_D[3], "Something went wrong!")
        return 3


def cluster():
    """ Get Information about the cluster state """

    ha_state_table = snmp_get(CHECKPOINT_MIB_D["Cluster"]["haState"]["oid"])

    ha_state = ha_state_table[0][0][-1]

    if str(ha_state).lower() == str(CLUSTER_S).lower():
        print(EXITMESSAGES_D[0], "Member is ", ha_state)
        return 0
    else:
        print(EXITMESSAGES_D[2], "Member is", ha_state,
                                 "but should be", CLUSTER_S)
        return 2


def main(argv):
    """ Main function for method dispatching and argument relay.

    Keyword arguments:
    argv -- The array of arguments
    """

    # import global variables
    global IP_ADDRESS_S
    global COMMUNITY_STRING_S
    global CLUSTER_S
    mode_s = "error"  # Set Mode = Error, if arguments couldn't be read.

    # Check if argument cout is correct
    if len(sys.argv) < 5:
        opt_error("Wrong parameter count. Paramteres given:" + sys.argv)

    # Get parameters
    try:
        opts, args = getopt.getopt(argv, "hi:c:m:s::")

        for opt, arg in opts:
            if opt == "-h":
                # User is asking for help.
                opt_error(None)
            elif opt == "-i":
                # -i as in IP Address
                try:
                    IP_ADDRESS_S = ipaddress.ip_address(arg)  # ip valid?
                    IP_ADDRESS_S = arg
                except ValueError:
                    opt_error("%s is not a valid IP Address!" % arg)
            elif opt == "-c":
                # -c as in community
                COMMUNITY_STRING_S = arg
            elif opt == "-m":
                # -m as in mode
                if arg in MODE_L:
                    mode_s = arg
                else:
                    opt_error("Mode %s is not supported" % arg)
            elif opt == "-s":
                # -s as in cluster state
                if arg in HA_STATES:
                    CLUSTER_S = arg

    except getopt.GetoptError as err:
        opt_error(err)

    # Method dispatching
    dispatch = {
        "cpu": cpu,
        "memory": memory,
        "disk": disk,
        "hardware": hardware,
        "network": network,
        "cluster": cluster,
        "error": opt_error
    }

    sys.exit(dispatch[mode_s]())

# calling main function
if __name__ == "__main__":
    main(sys.argv[1:])
