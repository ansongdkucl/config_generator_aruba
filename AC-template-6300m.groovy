!
! === USER ACCOUNTS ===
user admin group administrators password plaintext *****
!
! === HOSTNAME ===
hostname %_sys_hostname%
!
vsf member 1 
    type s0e91a
! === NTP CONFIGURATION ===
ntp server 144.82.250.8
ntp server 144.82.251.3
ntp server 193.60.251.3
ntp enable
!
! === AAA CONFIGURATION ===
tacacs-server host 10.28.50.99 key plaintext *****
tacacs-server host 10.36.50.99 key plaintext *****
!
aaa authentication login console group tacacs local
aaa authentication login ssh group tacacs local
aaa authorization commands console group local
aaa authorization commands ssh group tacacs local
aaa accounting all-mgmt console start-stop group tacacs local
aaa accounting all-mgmt ssh start-stop group tacacs local
!
logging 10.28.12.1 severity notice
logging 10.28.50.60 severity notice
logging 10.36.12.1 severity notice
logging 10.36.50.60 severity notice
! === SSH SERVER ===
ssh server vrf default
!
! === ACCESS LISTS ===
access-list ip 23SNMP
    10 permit any 10.28.12.0/255.255.255.0 any
    20 permit any 10.36.12.0/255.255.255.0 any
    30 permit any 10.28.50.0/255.255.255.0 any
    40 permit any 10.36.50.0/255.255.255.0 any
    50 permit any 10.29.50.0/255.255.255.0 any
    60 permit any 10.37.50.0/255.255.255.0 any
    70 permit any 128.40.19.0/255.255.255.0 any
!
! === LOGGING ===

!
! === VLAN DEFINITIONS ===
vlan %_sys_data_vlan_id%
    name %_sys_data_vlan_name%
!
vlan %_sys_voice_vlan_id%
    name %_sys_voice_vlan_name%
!
vlan 487
    name %_sys_487_vlan_name%
!
vlan 885
    name Switch-Management
!
vlan 915
    name %_sys_915_vlan_name%
!
vlan 990
    name %_sys_990_vlan_name%
!
vlan 1001
    name Blackhole
!
! === ACCESS PORTS (1/1/1 - 1/1/47) ===
interface 1/1/1
    no shutdown
    no routing
    vlan access %_sys_data_vlan_id%
    spanning-tree bpdu-guard
    spanning-tree port-type admin-edge
    loop-protect
    port-access port-security
        enable
    client-limit 50
!
interface 1/1/2
    no shutdown
    no routing
    vlan access %_sys_data_vlan_id%
    spanning-tree bpdu-guard
    spanning-tree port-type admin-edge
    loop-protect
    port-access port-security
        enable
    client-limit 50
!
interface 1/1/3
    no shutdown
    no routing
    vlan access %_sys_data_vlan_id%
    spanning-tree bpdu-guard
    spanning-tree port-type admin-edge
    loop-protect
    port-access port-security
        enable
    client-limit 50
!
interface 1/1/4
    no shutdown
    no routing
    vlan access %_sys_data_vlan_id%
    spanning-tree bpdu-guard
    spanning-tree port-type admin-edge
    loop-protect
    port-access port-security
        enable
    client-limit 50
!
interface 1/1/5
    no shutdown
    no routing
    vlan access %_sys_data_vlan_id%
    spanning-tree bpdu-guard
    spanning-tree port-type admin-edge
    loop-protect
    port-access port-security
        enable
    client-limit 50
!
interface 1/1/6
    no shutdown
    no routing
    vlan access %_sys_data_vlan_id%
    spanning-tree bpdu-guard
    spanning-tree port-type admin-edge
    loop-protect
    port-access port-security
        enable
    client-limit 50
!
interface 1/1/7
    no shutdown
    no routing
    vlan access %_sys_data_vlan_id%
    spanning-tree bpdu-guard
    spanning-tree port-type admin-edge
    loop-protect
    port-access port-security
        enable
    client-limit 50
!
interface 1/1/8
    no shutdown
    no routing
    vlan access %_sys_data_vlan_id%
    spanning-tree bpdu-guard
    spanning-tree port-type admin-edge
    loop-protect
    port-access port-security
        enable
    client-limit 50
!
interface 1/1/9
    no shutdown
    no routing
    vlan access %_sys_data_vlan_id%
    spanning-tree bpdu-guard
    spanning-tree port-type admin-edge
    loop-protect
    port-access port-security
        enable
    client-limit 50
!
interface 1/1/10
    no shutdown
    no routing
    vlan access %_sys_data_vlan_id%
    spanning-tree bpdu-guard
    spanning-tree port-type admin-edge
    loop-protect
    port-access port-security
        enable
    client-limit 50
!
interface 1/1/11
    no shutdown
    no routing
    vlan access %_sys_data_vlan_id%
    spanning-tree bpdu-guard
    spanning-tree port-type admin-edge
    loop-protect
    port-access port-security
        enable
    client-limit 50
!
interface 1/1/12
    no shutdown
    no routing
    vlan access %_sys_data_vlan_id%
    spanning-tree bpdu-guard
    spanning-tree port-type admin-edge
    loop-protect
    port-access port-security
        enable
    client-limit 50
!
interface 1/1/13
    no shutdown
    no routing
    vlan access %_sys_data_vlan_id%
    spanning-tree bpdu-guard
    spanning-tree port-type admin-edge
    loop-protect
    port-access port-security
        enable
    client-limit 50
!
interface 1/1/14
    no shutdown
    no routing
    vlan access %_sys_data_vlan_id%
    spanning-tree bpdu-guard
    spanning-tree port-type admin-edge
    loop-protect
    port-access port-security
        enable
    client-limit 50
!
interface 1/1/15
    no shutdown
    no routing
    vlan access %_sys_data_vlan_id%
    spanning-tree bpdu-guard
    spanning-tree port-type admin-edge
    loop-protect
    port-access port-security
        enable
    client-limit 50
!
interface 1/1/16
    no shutdown
    no routing
    vlan access %_sys_data_vlan_id%
    spanning-tree bpdu-guard
    spanning-tree port-type admin-edge
    loop-protect
    port-access port-security
        enable
    client-limit 50
!
interface 1/1/17
    no shutdown
    no routing
    vlan access %_sys_data_vlan_id%
    spanning-tree bpdu-guard
    spanning-tree port-type admin-edge
    loop-protect
    port-access port-security
        enable
    client-limit 50
!
interface 1/1/18
    no shutdown
    no routing
    vlan access %_sys_data_vlan_id%
    spanning-tree bpdu-guard
    spanning-tree port-type admin-edge
    loop-protect
    port-access port-security
        enable
    client-limit 50
!
interface 1/1/19
    no shutdown
    no routing
    vlan access %_sys_data_vlan_id%
    spanning-tree bpdu-guard
    spanning-tree port-type admin-edge
    loop-protect
    port-access port-security
        enable
    client-limit 50
!
interface 1/1/20
    no shutdown
    no routing
    vlan access %_sys_data_vlan_id%
    spanning-tree bpdu-guard
    spanning-tree port-type admin-edge
    loop-protect
    port-access port-security
        enable
    client-limit 50
!
interface 1/1/21
    no shutdown
    no routing
    vlan access %_sys_data_vlan_id%
    spanning-tree bpdu-guard
    spanning-tree port-type admin-edge
    loop-protect
    port-access port-security
        enable
    client-limit 50
!
interface 1/1/22
    no shutdown
    no routing
    vlan access %_sys_data_vlan_id%
    spanning-tree bpdu-guard
    spanning-tree port-type admin-edge
    loop-protect
    port-access port-security
        enable
    client-limit 50
!
interface 1/1/23
    no shutdown
    no routing
    vlan access %_sys_data_vlan_id%
    spanning-tree bpdu-guard
    spanning-tree port-type admin-edge
    loop-protect
    port-access port-security
        enable
    client-limit 50
!
interface 1/1/24
    no shutdown
    no routing
    vlan access %_sys_data_vlan_id%
    spanning-tree bpdu-guard
    spanning-tree port-type admin-edge
    loop-protect
    port-access port-security
        enable
    client-limit 50
!
interface 1/1/25
    no shutdown
    no routing
    vlan access %_sys_data_vlan_id%
    spanning-tree bpdu-guard
    spanning-tree port-type admin-edge
    loop-protect
    port-access port-security
        enable
    client-limit 50
!
interface 1/1/26
    no shutdown
    no routing
    vlan access %_sys_data_vlan_id%
    spanning-tree bpdu-guard
    spanning-tree port-type admin-edge
    loop-protect
    port-access port-security
        enable
    client-limit 50
!
interface 1/1/27
    no shutdown
    no routing
    vlan access %_sys_data_vlan_id%
    spanning-tree bpdu-guard
    spanning-tree port-type admin-edge
    loop-protect
    port-access port-security
        enable
    client-limit 50
!
interface 1/1/28
    no shutdown
    no routing
    vlan access %_sys_data_vlan_id%
    spanning-tree bpdu-guard
    spanning-tree port-type admin-edge
    loop-protect
    port-access port-security
        enable
    client-limit 50
!
interface 1/1/29
    no shutdown
    no routing
    vlan access %_sys_data_vlan_id%
    spanning-tree bpdu-guard
    spanning-tree port-type admin-edge
    loop-protect
    port-access port-security
        enable
    client-limit 50
!
interface 1/1/30
    no shutdown
    no routing
    vlan access %_sys_data_vlan_id%
    spanning-tree bpdu-guard
    spanning-tree port-type admin-edge
    loop-protect
    port-access port-security
        enable
    client-limit 50
!
interface 1/1/31
    no shutdown
    no routing
    vlan access %_sys_data_vlan_id%
    spanning-tree bpdu-guard
    spanning-tree port-type admin-edge
    loop-protect
    port-access port-security
        enable
    client-limit 50
!
interface 1/1/32
    no shutdown
    no routing
    vlan access %_sys_data_vlan_id%
    spanning-tree bpdu-guard
    spanning-tree port-type admin-edge
    loop-protect
    port-access port-security
        enable
    client-limit 50
!
interface 1/1/33
    no shutdown
    no routing
    vlan access %_sys_data_vlan_id%
    spanning-tree bpdu-guard
    spanning-tree port-type admin-edge
    loop-protect
    port-access port-security
        enable
    client-limit 50
!
interface 1/1/34
    no shutdown
    no routing
    vlan access %_sys_data_vlan_id%
    spanning-tree bpdu-guard
    spanning-tree port-type admin-edge
    loop-protect
    port-access port-security
        enable
    client-limit 50
!
interface 1/1/35
    no shutdown
    no routing
    vlan access %_sys_data_vlan_id%
    spanning-tree bpdu-guard
    spanning-tree port-type admin-edge
    loop-protect
    port-access port-security
        enable
    client-limit 50
!
interface 1/1/36
    no shutdown
    no routing
    vlan access %_sys_data_vlan_id%
    spanning-tree bpdu-guard
    spanning-tree port-type admin-edge
    loop-protect
    port-access port-security
        enable
    client-limit 50
!
interface 1/1/37
    no shutdown
    no routing
    vlan access %_sys_data_vlan_id%
    spanning-tree bpdu-guard
    spanning-tree port-type admin-edge
    loop-protect
    port-access port-security
        enable
    client-limit 50
!
interface 1/1/38
    no shutdown
    no routing
    vlan access %_sys_data_vlan_id%
    spanning-tree bpdu-guard
    spanning-tree port-type admin-edge
    loop-protect
    port-access port-security
        enable
    client-limit 50
!
interface 1/1/39
    no shutdown
    no routing
    vlan access %_sys_data_vlan_id%
    spanning-tree bpdu-guard
    spanning-tree port-type admin-edge
    loop-protect
    port-access port-security
        enable
    client-limit 50
!
interface 1/1/40
    no shutdown
    no routing
    vlan access %_sys_data_vlan_id%
    spanning-tree bpdu-guard
    spanning-tree port-type admin-edge
    loop-protect
    port-access port-security
        enable
    client-limit 50
!
interface 1/1/41
    no shutdown
    no routing
    vlan access %_sys_data_vlan_id%
    spanning-tree bpdu-guard
    spanning-tree port-type admin-edge
    loop-protect
    port-access port-security
        enable
    client-limit 50
!
interface 1/1/42
    no shutdown
    no routing
    vlan access %_sys_data_vlan_id%
    spanning-tree bpdu-guard
    spanning-tree port-type admin-edge
    loop-protect
    port-access port-security
        enable
    client-limit 50
!
interface 1/1/43
    no shutdown
    no routing
    vlan access %_sys_data_vlan_id%
    spanning-tree bpdu-guard
    spanning-tree port-type admin-edge
    loop-protect
    port-access port-security
        enable
    client-limit 50
!
interface 1/1/44
    no shutdown
    no routing
    vlan access %_sys_data_vlan_id%
    spanning-tree bpdu-guard
    spanning-tree port-type admin-edge
    loop-protect
    port-access port-security
        enable
    client-limit 50
!
interface 1/1/45
    no shutdown
    no routing
    vlan access %_sys_data_vlan_id%
    spanning-tree bpdu-guard
    spanning-tree port-type admin-edge
    loop-protect
    port-access port-security
        enable
    client-limit 50
!
interface 1/1/46
    no shutdown
    no routing
    vlan access %_sys_data_vlan_id%
    spanning-tree bpdu-guard
    spanning-tree port-type admin-edge
    loop-protect
    port-access port-security
        enable
    client-limit 50
!
interface 1/1/47
    no shutdown
    no routing
    vlan access %_sys_data_vlan_id%
    spanning-tree bpdu-guard
    spanning-tree port-type admin-edge
    loop-protect
    port-access port-security
        enable
    client-limit 50
!
! === TRUNK PORTS (1/1/48 - 1/1/52) ===
interface 1/1/48
    description Switch-Uplink
    no shutdown
    no routing
    vlan trunk native 1001
    vlan trunk allowed %_sys_data_vlan_id%,%_sys_voice_vlan_id%,487,915,990
!
interface 1/1/49
    description Switch-Uplink
    no shutdown
    no routing
    vlan trunk native 1001
    vlan trunk allowed %_sys_data_vlan_id%,%_sys_voice_vlan_id%,487,885,915,990
!
interface 1/1/50
    description Switch-Uplink
    no shutdown
    no routing
    vlan trunk native 1001
    vlan trunk allowed %_sys_data_vlan_id%,%_sys_voice_vlan_id%,487,885,915,990
!
interface 1/1/51
    description Switch-Uplink
    no shutdown
    no routing
    vlan trunk native 1001
    vlan trunk allowed %_sys_data_vlan_id%,%_sys_voice_vlan_id%,487,885,915,990
!
interface 1/1/52
    description Switch-Uplink
    no shutdown
    no routing
    vlan trunk native 1001
    vlan trunk allowed %_sys_data_vlan_id%,%_sys_voice_vlan_id%,487,885,915,990
!
! === VLAN INTERFACES (SVIs) ===
interface vlan 885
    description Switch-Management
    ip address %_sys_mgnt_ip%/24
!
! === SNMP CONFIGURATION ===
snmp-server community blooming
snmp-server system-location %_sys_location%
!
! === ROUTING ===
ip route 0.0.0.0/0 %_sys_gateway%
!
! === DNS ===
ip dns server-address 144.82.250.1
ip dns server-address 193.60.250.1
!