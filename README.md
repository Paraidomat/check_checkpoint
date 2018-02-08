# check_checkpoint
A Nagios compliant check for Check Point Firewalls

# Setup

Just download the `.py` file from this repository and save it to a folder where your monitoring system can access it.

## Requirements

The script uses the following Python 3 Modules:
* `sys`
* `getopt`
* `ipaddress`
* `re`
* `pysnmp`

# Usage

Simply call the Python-Skript:

```
check_checkpoint -i <ipv4Address> -c <communityString> -m <mode> [-s <cluster-state>]
```

## Available Modes:

* `cpu`
* `memory`
* `disk`
* `hardware`
* `network` 
* `cluster`

## Example Implementation for Icinga 2

### CheckCommand

```
object CheckCommand "check_checkpoint" {
    import "plugin-check-command"
    command = [ PluginDir + "check_checkpoint" ]
    arguments = {
        "-i" = "$check_checkpoint_address$"
        "-c" = "$check_checkpoint_community$"
        "-m" = "$check_checkpoint_mode$"
        "-s" = "$check_checkpoint_status$"
    }

    vars.check_checkpoint_address = "$address$"
    vars.check_checkpoint_community = "public"
}

```
### Service object

```
apply Service "check_checkpoint_cpu" {
    import "normal-service"

    check_command = "check_checkpoint"
    vars.check_checkpoint_mode = "cpu"

    assign where host.vars.vendor == "Checkpoint"
}
```
