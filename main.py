
# Imports necessary modules

import sys
import re
import logging
import random
import socket
import binascii

try:
    from PySide.QtCore import *
    from PySide.QtGui import *
except:
    print "PySide module is not installed on your system."
    print "To install it: apt-get install python-pyside"
    sys.exit()

from subprocess import check_output


#Imports Scapy and handling the ImportError exception
try:
    from scapy.all import *

except ImportError:
    print "Scapy package is not installed on your system."
    sys.exit()

# Import GUI
from ui_files import pyMainWindow

__appname__ = "ScapyG"
__module__ = "main"

# class Main will inherit QMainWindow and PyMainWindow(all widgets creates in QT Designer)
class Main(QMainWindow, pyMainWindow.Ui_mainWindow):


    def __init__(self, parent=None):
        super(Main, self).__init__(parent)
        self.setupUi(self)

        #This will suppress all messages that have a lower level of seriousness than error messages.
        logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
        logging.getLogger("scapy.interactive").setLevel(logging.ERROR)
        logging.getLogger("scapy.loading").setLevel(logging.ERROR)

        # Gets the list of available network interfaces
        self.interfaces_list = get_if_list()
        # Sort the interfaces_list
        self.interfaces_list.sort()
        # Deletes lo interfaces from interfaces_list
        self.interfaces_list.pop(self.interfaces_list.index('lo'))
        # Inserts lo interface in the offset 0 of interfaces_list
        self.interfaces_list.insert(0, 'lo')

        # Creates empty list mac_address_list
        self.mac_addresses_list = []

        # Populates mac_address_list with MAC addresses of available network interfaces
        for interface in self.interfaces_list:
            if interface == 'lo':
                self.mac_addresses_list.append('No MAC')
                continue
            mac_address = get_if_hwaddr(interface)
            self.mac_addresses_list.append(mac_address)

        # Adds source MAC addresses to Src MAC tab
        self.etherMacSrcComboBox.addItems(self.mac_addresses_list)
  
        # ARP Table
        arp_table = self.arp_table_function()
        # Creates empty ip_list
        self.ip_list = []
        # Creates empty
        self.mac_to_ip_list = []
        
        for i in arp_table:
            # Populates ip_list with IP addresses from ARP mappings
            if self.validate_ip_address(i):
                self.ip_list.append(i)
            # Populates mac_to_ip_list with MAC addresses from ARP mappings
            if self.validate_mac_address(i):
                self.mac_to_ip_list.append(i)
        
        # Checks whether ip_list is not empty
        if self.ip_list:
            # Add IP addresses to widget
            self.etherArpComboBox.addItems(self.ip_list)
            # Add MAC addresses to widget
            self.etherMacDstComboBox.addItems(self.mac_to_ip_list)
        else:
            # In case ip_list is empty
            self.ip_list.append("No ARP Map")
            self.mac_to_ip_list.append("No ARP Map")
            # Adds ip_list to widget
            self.etherArpComboBox.addItems(self.ip_list)
            # Adds mac_to_ip_list to widget
            self.etherMacDstComboBox.addItems(self.mac_to_ip_list)

        # NDP Table
        ndp_table = check_output(['ip', '-6', 'neigh'])
        ndp_table = ndp_table.split()
        self.ipv6_list = []
        self.mac_to_ipv6_list = []
        for i in ndp_table:
            if self.validate_ipv6_address(i):
                self.ipv6_list.append(i)
            if self.validate_mac_address(i):
                self.mac_to_ipv6_list.append(i)

        # Checks whether ipv6_list is not empty
        if self.ipv6_list:
            # Add IPv6 addresses to widget
            self.etherNdpComboBox.addItems(self.ipv6_list)
            # Add MAC addresses to widget
            self.etherMacDstNdpComboBox.addItems(self.mac_to_ipv6_list)
        else:
            # In case ipv6_list is empty
            self.ipv6_list.append("No NDP Entries")
            self.mac_to_ipv6_list.append("No NDP Entries")
            # Adds ip_list to widget
            self.etherNdpComboBox.addItems(self.ipv6_list)
            # Adds mac_to_ip_list to widget
            self.etherMacDstNdpComboBox.addItems(self.mac_to_ipv6_list)

        # Adds network interfaces to tabs
        self.etherIntComboBox.addItems(self.interfaces_list)
        self.arpRequestInterface.addItems(self.interfaces_list)
        self.arpResponseInterface.addItems(self.interfaces_list)
        self.dhcpClientInterface.addItems(self.interfaces_list)
        self.dhcpServerInterface.addItems(self.interfaces_list)
        self.ipInterace.addItems(self.interfaces_list)
        self.ipv6Interace.addItems(self.interfaces_list)
        self.tcpInterace.addItems(self.interfaces_list)
        self.udpInterace.addItems(self.interfaces_list)
        self.icmpv6EchoRequestInterace.addItems(self.interfaces_list)
        self.icmpv6EchoReplyInterace.addItems(self.interfaces_list)
        self.icmpEchoRequestInterface.addItems(self.interfaces_list)
        self.icmpEchoReplyInterface.addItems(self.interfaces_list)
        self.dnsQueryInterface.addItems(self.interfaces_list)
        self.dnsResponseInterface.addItems(self.interfaces_list)

        # Hides IPv6 tables
        self.tcpIPv6TableWidget.setHidden(True)
        self.udpIPv6Table.setHidden(True)
        self.dnsQueryIPv6Table.setHidden(True)
        self.dnsResponseIPv6Table.setHidden(True)

        self.dns_response_query_default = ['www.itb.ie.', 'www.itb.ie.', 'itb.ie.', 'itb.ie.', 'itb.ie.', '24.36.1.193.in-addr.arpa.']
        self.dns_response_answer_default = ['193.1.36.24', '2001::3', 'hss-dns-01.heanet.ie.', 'itbdns01.itb.ie. administrator.itb.ie.', 'itb-ie.mail.protection.outlook.com.', 'www.itb.ie.']
        
        # Set Ethernet tab MAC src interface to 1 (eth0)
        self.etherIntComboBox.setCurrentIndex(1)

        # Connects Exit button with method exit_action_triggered (When clicked)
        self.actionExit.triggered.connect(self.exit_action_triggered)
        # Connects Forward button with method forward_button_triggered (When clicked)
        self.actionForward.triggered.connect(self.forward_button_triggered)
        # Connects Forward button with method forward_button_triggered (When clicked)
        self.macDstArpTableButton.clicked.connect(self.arp_table_com_fun)
        # Connects Forward button with method forward_button_triggered (When clicked)
        self.macDstNdpTableButton.clicked.connect(self.ndp_table_com_fun) 
        # List IPv4 Routing Table
        self.macDstRouteButton.clicked.connect(self.route_table_ipv4)
        # List IPv6 Routing Table
        self.macDstRouteIpv6Button.clicked.connect(self.route_table_ipv6)
        # List Interface Setting
        self.macSrcInterfaceButton.clicked.connect(self.interface_settings)
        
        # Set signal IPv4 and IPv6 source IP
        self.etherIntComboBox.currentIndexChanged.connect(self.auto_ip_src_address)
        # Set signal IPv4 destination IP and destination MAc address
        self.etherArpComboBox.currentIndexChanged.connect(self.auto_ip_dst_and_mac_dst)
        # Set signal IPv6 destination IP and destination MAC address
        self.etherNdpComboBox.currentIndexChanged.connect(self.auto_ipv6_dst_and_mac_dst)
        # Set signal source MAC address
        self.etherIntComboBox.currentIndexChanged.connect(self.auto_src_mac)
        # Set signal DNS Response Query and Answer
        self.dnsResponseTypeComboBox.currentIndexChanged.connect(self.auto_dns_response)
        # Set signal DNS Response Set Query
        self.dnsResponseNameTextSet.toggled.connect(self.auto_dns_response_query)
        # Set signal DNS Response Set Answer
        self.dnsResponseIPSet.toggled.connect(self.auto_dns_response_answer)
        # Set signal DNS Query default values
        self.dnsQueryTypeComboBox.currentIndexChanged.connect(self.auto_dns_query)
        # Set signal DNS Query default values when set is unchecked
        self.dnsQueryNameTextSet.toggled.connect(self.auto_dns_query_name)
        # Set signal ARP Request default MAC dst value "ff:ff:ff:ff:ff:ff"
        self.arpRequestDstMacManual.toggled.connect(self.auto_arp_requst_dst_mac_addr_default)
        # Set signal ARP Request default opcode default
        self.arpRequestOpCodeManual.toggled.connect(self.auto_arp_requst_op_code_default)
        # Set signal ARP Reply default opcode default
        self.arpResponseOpCodeManual.toggled.connect(self.auto_arp_response_op_code_default)
        # Set signal TCP Window size default value
        self.tcpWinSizeCheckBox.toggled.connect(self.auto_tcp_window_size_default)
        # Set signal TCP Seq num default value
        self.tcpSeqNumCheckBox.toggled.connect(self.auto_tcp_seq_number_default)
        # Set signal TCP Ack num default value
        self.tcpAckNumCheckBox.toggled.connect(self.auto_tcp_ack_number_default)
        # Set signal IP upper protocol default value
        self.ipProtocolCheckBox.toggled.connect(self.auto_ip_protocol_number_default)
        # Set signal IP TTL default value
        self.ipTTLCheckBox.toggled.connect(self.auto_ip_ttl_number_default)
        # Set signal IP Version default value
        self.ipVersionCheckBox.toggled.connect(self.auto_ip_version_number_default)
        # Set signal IP Tos default value
        self.ipTosCheckBox.toggled.connect(self.auto_ip_tos_number_default)
        # Set signal ID Tos default value
        self.ipIDCheckBox.toggled.connect(self.auto_ip_id_number_default)
        # Set signal Frag offset default value
        self.ipFragOffsetCheckBox.toggled.connect(self.auto_ip_frag_number_default)
        # IPv6 default values
        # Set signal ipv6 Next Header default value
        self.ipv6NextHeaderCheckBox.toggled.connect(self.auto_ipv6_next_header_default)
        # Set signal ipv6 Next Header default value
        self.ipv6VersionCheckBox.toggled.connect(self.auto_ipv6_version_default)
        # Set signal ipv6 Hop Limit default value
        self.ipv6HopLimitCheckBox.toggled.connect(self.auto_ipv6_hop_limit_default)
        # Set signal ipv6 ToS default value
        self.ipv6TosCheckBox.toggled.connect(self.auto_ipv6_tos_default)
        # Set signal ipv6 Flow Label default value
        self.ipv6FlowLabelCheckBox.toggled.connect(self.auto_ipv6_flow_label_default)
        # ICMP Default
        # ICMP Request Type Code
        self.icmpEchoRequestSetTypeCode.toggled.connect(self.auto_icmp_req_type_code_default)
        # ICMP Request ID Seq
        self.icmpEchoRequestSetIdSeq.toggled.connect(self.auto_icmp_req_id_seq_default)
        # ICMP Reply Type Code
        self.icmpEchoReplySetTypeCode.toggled.connect(self.auto_icmp_rep_type_code_default)
        # ICMP Reply ID Seq
        self.icmpEchoReplySetIdSeq.toggled.connect(self.auto_icmp_rep_id_seq_default)
        # ICMPv6 Default
        # ICMPv6 Request Type Code
        self.icmpv6EchoRequestSetTypeCode.toggled.connect(self.auto_icmpv6_req_type_code_default)
        # ICMPv6 Request ID Seq
        self.icmpv6EchoRequestSetIdSeq.toggled.connect(self.auto_icmpv6_req_id_seq_default)
        # ICMPv6 Reply Type Code
        self.icmpv6EchoReplySetTypeCode.toggled.connect(self.auto_icmpv6_rep_type_code_default)
        # ICMPv6 Reply ID Seq
        self.icmpv6EchoReplySetIdSeq.toggled.connect(self.auto_icmpv6_rep_id_seq_default)
        # DNS
        # DNS response ID default
        self.dnsResponseIdSet.toggled.connect(self.auto_dns_res_id_default)
        # DNS query ID default
        self.dnsQueryIdSet.toggled.connect(self.auto_dns_que_id_default)
        # DHCP 
        # DHCP client Dst MAC default
        self.dhcpClientDstManual.toggled.connect(self.auto_dhcp_client_dst_mac_default)
        # DHCP client UDP src port default
        self.dhcpClientSrcPortManual.toggled.connect(self.auto_dhcp_client_src_port_default)
        # DHCP client UDP dst port default
        self.dhcpClientDstPortManual.toggled.connect(self.auto_dhcp_client_dst_port_default)
        # DHCP client IP src default
        self.dhcpClientSrcIpManual.toggled.connect(self.auto_dhcp_client_src_ip_default)
        # DHCP client IP dst default
        self.dhcpClientDstIpManual.toggled.connect(self.auto_dhcp_client_dst_ip_default)
        # DHCP client Transaction ID
        self.dhcpClientTransactionIDRandom.toggled.connect(self.auto_dhcp_client_tra_id_default)
        # DHCP client Random source MAC
        self.dhcpClientSrcMacRandom.toggled.connect(self.auto_dhcp_client_mac_rand_default)
        # DHCP server Transaction ID
        self.dhcpServerTransactionIdRandom.toggled.connect(self.auto_dhcp_server_tra_id_default)
        # DHCP server UDP src default
        self.dhcpServerSrcPortManual.toggled.connect(self.auto_dhcp_server_upd_src_default)
        # DHCP server UDP dst default
        self.dhcpServerDstPortManual.toggled.connect(self.auto_dhcp_server_upd_dst_default)
        # DHCP server Random source MAC
        self.dhcpServerSrcMacRandom.toggled.connect(self.auto_dhcp_server_src_mac_rand_default)
        # DHCP server Random dst MAC
        self.dhcpServerDstMacRandom.toggled.connect(self.auto_dhcp_server_dst_mac_rand_default)
        # DHCP server Random src IP
        self.dhcpServerSrcIpRandom.toggled.connect(self.auto_dhcp_server_src_ip_rand_default)
        # DHCP server Random src IP
        self.dhcpServerDstIpRandom.toggled.connect(self.auto_dhcp_server_dst_ip_rand_default)


        # Calls auto populate functions
        self.auto_ip_src_address()
        self.auto_ip_dst_and_mac_dst()
        self.auto_ipv6_dst_and_mac_dst()
        self.auto_src_mac()
        self.auto_dns_response()
        self.auto_dns_query()
        self.auto_arp_requst_dst_mac_addr_default()
        self.auto_dhcp_client_dst_mac_default()
        self.auto_dhcp_client_src_ip_default()
        self.auto_dhcp_client_dst_ip_default()
        self.auto_dhcp_client_tra_id_default()
        self.auto_dhcp_server_tra_id_default()
        self.auto_dns_res_id_default()

        # DHCP MAC source random
        self.dhcp_mac_src_rand = ""
        # DHCP MAC server MAC source random
        self.dhcp_ser_mac_src_rand = ""
        # DHCP MAC server MAC destination random
        self.dhcp_ser_mac_dst_rand = ""
        # DHCP MAC server IP source random
        self.dhcp_ser_ip_src_rand = ""
        # DHCP MAC server IP destination random
        self.dhcp_ser_ip_dst_rand = ""

    def auto_dhcp_server_dst_ip_rand_default(self):
        if self.dhcpServerDstIpRandom.isChecked():
            self.dhcp_ser_ip_dst_rand = str(RandIP())
            self.dhcpServerDstIp.setText(self.dhcp_ser_ip_dst_rand)
        if not self.dhcpServerDstIpRandom.isChecked():
            self.dhcpServerDstIp.setText(self.ip_list[self.etherArpComboBox.currentIndex()])

    def auto_dhcp_server_src_ip_rand_default(self):
        if self.dhcpServerSrcIpRandom.isChecked():
            self.dhcp_ser_ip_src_rand = str(RandIP())
            self.dhcpServerSrcIp.setText(self.dhcp_ser_ip_src_rand)
            self.dhcpServerIdentifier.setText(self.dhcp_ser_ip_src_rand)
            self.dhcpServerNameServer.setText(self.dhcp_ser_ip_src_rand)
        if not self.dhcpServerSrcIpRandom.isChecked():
            current_int = str(self.interfaces_list[self.etherIntComboBox.currentIndex()]) 
            ip_addr = get_if_addr(current_int)
            self.dhcpServerSrcIp.setText(ip_addr)
            self.dhcpServerIdentifier.setText(ip_addr)
            self.dhcpServerNameServer.setText(ip_addr)

    def auto_dhcp_server_dst_mac_rand_default(self):
        if self.dhcpServerDstMacRandom.isChecked():
            self.dhcp_ser_mac_dst_rand = str(RandMAC())
            self.dhcpServerDstMac.setText(self.dhcp_ser_mac_dst_rand)
        if not self.dhcpServerDstMacRandom.isChecked():
            self.dhcpServerDstMac.setText(self.mac_to_ip_list[self.etherMacDstComboBox.currentIndex()])

    def auto_dhcp_server_src_mac_rand_default(self):
        if self.dhcpServerSrcMacRandom.isChecked():
            self.dhcp_ser_mac_src_rand = str(RandMAC())
            self.dhcpServerSrcMac.setText(self.dhcp_ser_mac_src_rand)
        if not self.dhcpServerSrcMacRandom.isChecked():
            self.dhcpServerSrcMac.setText(self.mac_addresses_list[self.etherMacSrcComboBox.currentIndex()])

    def auto_dhcp_client_mac_rand_default(self):
        if self.dhcpClientSrcMacRandom.isChecked():
            self.dhcp_mac_src_rand = str(RandMAC())
            self.dhcpClientSrcMac.setText(self.dhcp_mac_src_rand)
        if not self.dhcpClientSrcMacRandom.isChecked():
            self.dhcpClientSrcMac.setText(self.mac_addresses_list[self.etherMacSrcComboBox.currentIndex()])

    def auto_dhcp_server_upd_dst_default(self):
        if not self.dhcpServerDstPortManual.isChecked():
            self.dhcpServerDstPortSpin.setValue(68)

    def auto_dhcp_server_upd_src_default(self):
        if not self.dhcpServerSrcPortManual.isChecked():
            self.dhcpServerSrcPortSpin.setValue(67)

    def auto_dhcp_server_tra_id_default(self):
        if self.dhcpServerTransactionIdRandom.isChecked():
            self.dhcpServerTransactionId.setText(str(hex(random.randrange(1, 1000000))))
        if not self.dhcpServerTransactionIdRandom.isChecked():
            self.dhcpServerTransactionId.clear()

    def auto_dhcp_client_tra_id_default(self):
        if self.dhcpClientTransactionIDRandom.isChecked():
            self.dhcpClientTransationId.setText(str(hex(random.randrange(1, 1000000))))
        if not self.dhcpClientTransactionIDRandom.isChecked():
            self.dhcpClientTransationId.clear()

    def auto_dhcp_client_dst_ip_default(self):
        if not self.dhcpClientDstIpManual.isChecked():
            self.dhcpClientDstIp.setText('255.255.255.255')

    def auto_dhcp_client_src_ip_default(self):
        if not self.dhcpClientSrcIpManual.isChecked():
            self.dhcpClientSrcIp.setText('0.0.0.0')

    def auto_dhcp_client_src_port_default(self):
        if not self.dhcpClientSrcPortManual.isChecked():
            self.dhcpClientSrcPortSpin.setValue(68)

    def auto_dhcp_client_dst_port_default(self):
        if not self.dhcpClientDstPortManual.isChecked():
            self.dhcpClientDstPortSpin.setValue(67)

    def auto_dhcp_client_dst_mac_default(self):
        if not self.dhcpClientDstManual.isChecked():
            self.dhcpClientDstMac.setText("ff:ff:ff:ff:ff:ff")

    def auto_dns_que_id_default(self):
        if not self.dnsQueryIdSet.isChecked():
            self.dnsQueryIdSpinBox.setValue(0)

    def auto_dns_res_id_default(self):
        if not self.dnsResponseIdSet.isChecked():
            self.dnsResponseIdText.setText("0x0000")

    def auto_icmpv6_rep_id_seq_default(self):
         if not self.icmpv6EchoReplySetIdSeq.isChecked():
            self.icmpv6EchoReplyIDSpinBox.setValue(0)
            self.icmpv6EchoReplySeqSpinBox.setValue(1)

    def auto_icmpv6_rep_type_code_default(self):
        if not self.icmpv6EchoReplySetTypeCode.isChecked():
            self.icmpv6EchoReplyType.setValue(129)
            self.icmpv6EchoReplyCode.setValue(0)

    def auto_icmpv6_req_id_seq_default(self):
         if not self.icmpv6EchoRequestSetIdSeq.isChecked():
            self.icmpv6EchoRequestIDSpinBox.setValue(0)
            self.icmpv6EchoRequestSeqSpinBox.setValue(1)

    def auto_icmpv6_req_type_code_default(self):
        if not self.icmpv6EchoRequestSetTypeCode.isChecked():
            self.icmpv6EchoRequestType.setValue(128)
            self.icmpv6EchoRequestCode.setValue(0)

    def auto_icmp_rep_id_seq_default(self):
         if not self.icmpEchoReplySetIdSeq.isChecked():
            self.icmpEchoReplyIDSpinBox.setValue(0)
            self.icmpEchoReplySeqSpinBox.setValue(1)

    def auto_icmp_rep_type_code_default(self):
        if not self.icmpEchoReplySetTypeCode.isChecked():
            self.icmpEchoReplyTypeSpin.setValue(0)
            self.icmpEchoReplyCodeSpin.setValue(0)

    def auto_icmp_req_id_seq_default(self):
         if not self.icmpEchoRequestSetIdSeq.isChecked():
            self.icmpEchoRequestIDSpinBox.setValue(0)
            self.icmpEchoRequestSeqSpinBox.setValue(1)

    def auto_icmp_req_type_code_default(self):
        if not self.icmpEchoRequestSetTypeCode.isChecked():
            self.icmpEchoRequestTypeSpin.setValue(8)
            self.icmpEchoRequestCodeSpin.setValue(0)

    def auto_ipv6_flow_label_default(self):
        if not self.ipv6FlowLabelCheckBox.isChecked():
            self.ipv6FlowLabelSpinBox.setValue(0)

    def auto_ipv6_tos_default(self):
        if not self.ipv6TosCheckBox.isChecked():
            self.ipv6TospinBox.setValue(0)

    def auto_ipv6_hop_limit_default(self):
        if not self.ipv6HopLimitCheckBox.isChecked():
            self.ipv6HopLimitSpinBox.setValue(64)

    def auto_ipv6_version_default(self):
        if not self.ipv6VersionCheckBox.isChecked():
            self.ipv6VersionSpinBox.setValue(6)

    def auto_ipv6_next_header_default(self):
        if not self.ipv6NextHeaderCheckBox.isChecked():
            self.ipv6NextHeaderSpinBox.setValue(59)

    def auto_ip_frag_number_default(self):
        if not self.ipFragOffsetCheckBox.isChecked():
            self.ipFragOffsetSpinBox.setValue(0)

    def auto_ip_id_number_default(self):
        if not self.ipIDCheckBox.isChecked():
            self.ipIDSpinBox.setValue(1)

    def auto_ip_tos_number_default(self):
        if not self.ipTosCheckBox.isChecked():
            self.ipTosSpinBox.setValue(0)

    def auto_ip_version_number_default(self):
        if not self.ipVersionCheckBox.isChecked():
            self.ipVersionSpinBox.setValue(4)

    def auto_ip_ttl_number_default(self):
        if not self.ipTTLCheckBox.isChecked():
            self.ipTtlSpinBox.setValue(64)

    def auto_ip_protocol_number_default(self):
        if not self.ipProtocolCheckBox.isChecked():
            self.ipProtocolSpinBox.setValue(6)

    def auto_tcp_ack_number_default(self):
        if not self.tcpAckNumCheckBox.isChecked():
            self.tcpAckNumSpinBox.setValue(1000)
    
    def auto_tcp_seq_number_default(self):
        if not self.tcpSeqNumCheckBox.isChecked():
            self.tcpSeqNumSpinBox.setValue(1000)

    def auto_tcp_window_size_default(self):
        if not self.tcpWinSizeCheckBox.isChecked():
            self.tcpWinSizeSpinBox.setValue(8192)

    def auto_arp_response_op_code_default(self):
        if not self.arpResponseOpCodeManual.isChecked():
            self.arpResponseOpCode.setCurrentIndex(0)

    def auto_arp_requst_op_code_default(self):
        if not self.arpRequestOpCodeManual.isChecked():
            self.arpRequestOpCode.setCurrentIndex(0)

    def auto_arp_requst_dst_mac_addr_default(self):
        if not self.arpRequestDstMacManual.isChecked():
            self.arpRequestDstMac.setText("ff:ff:ff:ff:ff:ff")

    def auto_dns_query_name(self):
        if not self.dnsQueryNameTextSet.isChecked():
            self.dnsQueryText.setText(self.dns_response_query_default[self.dnsQueryTypeComboBox.currentIndex()])

    def auto_dns_query(self):
        if not self.dnsQueryNameTextSet.isChecked():
            self.dnsQueryText.setText(self.dns_response_query_default[self.dnsQueryTypeComboBox.currentIndex()])

    def auto_dns_response_answer(self):
        if not self.dnsResponseIPSet.isChecked():
            self.dnsResponseIPText.setText(self.dns_response_answer_default[self.dnsResponseTypeComboBox.currentIndex()])

    def auto_dns_response_query(self):
        if not self.dnsResponseNameTextSet.isChecked():
            self.dnsResponseText.setText(self.dns_response_query_default[self.dnsResponseTypeComboBox.currentIndex()])

    def auto_dns_response(self):
        if not self.dnsResponseNameTextSet.isChecked():
            self.dnsResponseText.setText(self.dns_response_query_default[self.dnsResponseTypeComboBox.currentIndex()])
        if not self.dnsResponseIPSet.isChecked():
            self.dnsResponseIPText.setText(self.dns_response_answer_default[self.dnsResponseTypeComboBox.currentIndex()])

    def auto_src_mac(self):
        src_mac_address = self.mac_addresses_list[self.etherMacSrcComboBox.currentIndex()]
        self.etherMacSrcEdit.setText(src_mac_address)
        self.arpRequestSrcMac.setText(src_mac_address)
        self.arpResponseSrcMac.setText(src_mac_address)
        self.dhcpClientSrcMac.setText(src_mac_address)
        self.dhcpServerSrcMac.setText(src_mac_address)

    def auto_ipv6_dst_and_mac_dst(self):
        dst_mac_address = self.mac_to_ipv6_list[self.etherMacDstNdpComboBox.currentIndex()]
        self.etherMacDstEdit.setText(dst_mac_address)

        dst_ipv6_address = self.ipv6_list[self.etherMacDstNdpComboBox.currentIndex()]
        self.ipv6DstIpAddr.setText(dst_ipv6_address)

    def auto_ip_src_address(self):
        
        # IPv4 source
        ipv4_src_interface = str(self.interfaces_list[self.etherIntComboBox.currentIndex()]) 
        ipv4_src_address = get_if_addr(ipv4_src_interface)
        self.ipSrcEdit.setText(ipv4_src_address)
        self.arpRequestSrcIp.setText(ipv4_src_address)
        self.arpResponseSrcIp.setText(ipv4_src_address)
        self.dhcpServerSrcIp.setText(ipv4_src_address)
        self.dhcpServerIdentifier.setText(ipv4_src_address)
        self.dhcpServerNameServer.setText(ipv4_src_address)

        # IPv6 dest
        ipv6_src_interface = str(self.interfaces_list[self.etherIntComboBox.currentIndex()]) 
        ipv6_src_address = get_if_addr6(ipv6_src_interface)
        self.ipv6SrcIpAddr.setText(ipv6_src_address)

    def auto_ip_dst_and_mac_dst(self):

        # IPv4 dst address
        ipv4_dst_address = self.ip_list[self.etherArpComboBox.currentIndex()]
        self.ipDstEdit.setText(ipv4_dst_address)
        self.arpRequestDstIp.setText(ipv4_dst_address)
        self.arpResponseDstIp.setText(ipv4_dst_address)
        self.dhcpServerDstIp.setText(ipv4_dst_address)

        # MAC dst address
        dst_mac_address = self.mac_to_ip_list[self.etherMacDstComboBox.currentIndex()]
        self.etherMacDstEdit.setText(dst_mac_address)
        self.arpResponseDstMac.setText(dst_mac_address)
        self.dhcpServerDstMac.setText(dst_mac_address)

    def arp_table_function(self):
        # Stores the output of ARP Table in arp_table
        arp_table = check_output(['arp', '-n'])
        # Creates a list
        arp_table = arp_table.split()
        # Deletes first 6 elements
        arp_table = arp_table[6::]
        # Deletes (incomplete) entries in ARP table
        while '(incomplete)' in arp_table:
            index = arp_table.index('(incomplete)')
            del arp_table[index-1]
            del arp_table[index-1]
            del arp_table[index-1]
        return arp_table

    def arp_table_com_fun(self):
        arp_output = check_output(['ip', '-4','neigh'])
        self.etherMacDstArpNdpTextEdit.clear()
        self.etherMacDstArpNdpTextEdit.appendPlainText(arp_output)

    def ndp_table_com_fun(self):
        ndp_output = check_output(['ip', '-6','neigh'])
        self.etherMacDstArpNdpTextEdit.clear()
        self.etherMacDstArpNdpTextEdit.appendPlainText(ndp_output)

    def interface_settings(self):
        ip_output = check_output(['ifconfig', '-a'])
        self.etherInterfaceSettingsTextEdit.clear()
        self.etherInterfaceSettingsTextEdit.appendPlainText(ip_output)

    def route_table_ipv4(self):
        ipv4_route = check_output(['ip', '-4','route'])
        self.etherMacDstRouteTextEdit.clear()
        self.etherMacDstRouteTextEdit.appendPlainText(ipv4_route)

    def route_table_ipv6(self):
        ipv6_route = check_output(['ip', '-6','route'])
        self.etherMacDstRouteTextEdit.clear()
        self.etherMacDstRouteTextEdit.appendPlainText(ipv6_route)    
  
    # Action perform when Forward button is clicked
    def forward_button_triggered(self):

        # Gets current tab index (ARP, DHCP, Ether, IPv4, TCP, UDP, ICMP, DNS)
        current_tab = self.mainTabWidget.currentIndex()

        # ARP tab
        if current_tab == 0:

            # ARP Request subtab
            if self.arpTabWidget.currentIndex() == 0:

                # Source MAC address
                arp_source_mac = self.arpRequestSrcMac.text()
                # Destination MAC address
                arp_destination_mac = "ff:ff:ff:ff:ff:ff" 
                if self.arpRequestDstMacManual.isChecked():
                    arp_destination_mac = self.arpRequestDstMac.text()
                # Checks whether the format of source MAC address is correct
                if not self.validate_mac_address(arp_source_mac):
                    # Error message
                    QMessageBox.warning(self, "Warning", "MAC source address seems incorrect!")
                    return False
                # Checks whether the format of destination MAC address is correct     
                if not self.validate_mac_address(arp_destination_mac):
                    # Error message
                    QMessageBox.warning(self, "Warning", "MAC destination address seems incorrect!")
                    return False
               
                # ARP source IP addresses
                arp_source_ip = self.arpRequestSrcIp.text()
                # Checks whether the format of ARP src IP addresses is correct
                if not self.validate_ip_address(arp_source_ip):
                    # Error message
                    QMessageBox.warning(self, "Warning", "IP source address seems incorrect!")
                    return False
                # ARP destination IP addresses
                arp_destination_ip = self.arpRequestDstIp.text()
                # Checks whether the format of ARP dst IP addresses is correct
                if not self.validate_ip_address(arp_destination_ip):
                    # Error message
                    QMessageBox.warning(self, "Warning", "IP destination address seems incorrect!")
                    return False
                # ARP OPcode 
                opcode = ['who-has','is-at']
                arp_opcode = 'who-has'
                if self.arpRequestOpCodeManual.isChecked():
                    arp_opcode = opcode[self.arpRequestOpCode.currentIndex()]
                # Interface
                arp_interface = self.interfaces_list[self.arpRequestInterface.currentIndex()]
              
                # Calls the arp_forward function
                if not self.arp_forward(arp_source_mac, arp_destination_mac, arp_source_ip, arp_destination_ip, arp_opcode, arp_interface):
                    QMessageBox.warning(self, "Warning", "Packet could not be sent")
                    self.mainStatusBar.showMessage("Packet could not be sent")
                else:
                    # When packet is sent successfully the appropriate window is displayed
                    QMessageBox.information(self, "Information", "Packet sent")
                    # When packet is sent successfully the appropriate message is in the status bar
                    self.mainStatusBar.showMessage("Packet sent successfully")
                    
                    # Populates table with packet details
                    current_row_count = self.arpRequestTable.rowCount()
                    self.arpRequestTable.insertRow(current_row_count)
                    self.arpRequestTable.setItem(current_row_count, 0, QTableWidgetItem(arp_source_ip))
                    self.arpRequestTable.setItem(current_row_count, 1, QTableWidgetItem(arp_source_mac))
                    self.arpRequestTable.setItem(current_row_count, 2, QTableWidgetItem(arp_destination_ip))
                    self.arpRequestTable.setItem(current_row_count, 3, QTableWidgetItem(arp_destination_mac))
                    self.arpRequestTable.setItem(current_row_count, 4, QTableWidgetItem(arp_opcode))
                    self.arpRequestTable.setItem(current_row_count, 5, QTableWidgetItem(arp_interface))

                    # Alignment of columns
                    for column in range(self.arpRequestTable.columnCount()):
                        self.arpRequestTable.item(current_row_count, column).setTextAlignment(Qt.AlignmentFlag.AlignCenter)
                    
                    # Populates Scapy command used field
                    arp_request_command_text = "sendp(Ether(src='" + str(arp_source_mac) + "', dst='" + str(arp_destination_mac) + \
                                              "')/ARP(op='" + str(arp_opcode) + "', hwsrc='" + str(arp_source_mac) + "', psrc='" +\
                                              str(arp_source_ip) + "', pdst='" + str(arp_destination_ip) + "', hwdst='" + str(arp_destination_mac) + "'), iface='" +arp_interface+ "', verbose=0)"
                    self.arpRequestScapyCommandTextBrowser.setText(arp_request_command_text)

            # Response Tab
            if self.arpTabWidget.currentIndex() == 1:

                # Source MAC address
                arp_source_mac = self.arpResponseSrcMac.text()
                # Destination MAC address
                arp_destination_mac = self.arpResponseDstMac.text()
                # Checks whether the format of source MAC address is correct
                if not self.validate_mac_address(arp_source_mac):
                    # Error message
                    QMessageBox.warning(self, "Warning", "MAC source address seems incorrect!")
                    return False
                # Checks whether the format of destination MAC address is correct     
                if not self.validate_mac_address(arp_destination_mac):
                    # Error message
                    QMessageBox.warning(self, "Warning", "MAC destination address seems incorrect!")
                    return False

                # ARP source IP addresses
                arp_source_ip = self.arpResponseSrcIp.text()
                # Checks whether the format of ARP src IP addresses is correct
                if not self.validate_ip_address(arp_source_ip):
                    # Error message
                    QMessageBox.warning(self, "Warning", "IP source address seems incorrect!")
                    return False

                # ARP destination IP addresses
                arp_destination_ip = self.arpResponseDstIp.text()
                # Checks whether the format of ARP dst IP addresses is correct
                if not self.validate_ip_address(arp_destination_ip):
                    # Error message
                    QMessageBox.warning(self, "Warning", "IP destination address seems incorrect!")
                    return False

                # OP code
                opcode = ['is-at','who-has']
                arp_opcode = 'is-at'
                if self.arpResponseOpCodeManual.isChecked():
                    arp_opcode = opcode[self.arpResponseOpCode.currentIndex()]
                
                # Interface
                arp_interface = self.interfaces_list[self.arpResponseInterface.currentIndex()]
              
                # Calls the arp_forward_function
                if not self.arp_forward(arp_source_mac, arp_destination_mac, arp_source_ip, arp_destination_ip, arp_opcode, arp_interface):

                    QMessageBox.warning(self, "Warning", "Packet could not be sent")
                    self.mainStatusBar.showMessage("Packet could not be sent")
                else:
                    # When packet is sent successfully the appropriate window is displayed
                    QMessageBox.information(self, "Information", "Packet sent")
                    # When packet is sent successfully the appropriate message is in the status bar
                    self.mainStatusBar.showMessage("Packet sent successfully")
                    
                    # Populates table with packet details
                    current_row_count = self.arpResponseTable.rowCount()
                    self.arpResponseTable.insertRow(current_row_count)
                    self.arpResponseTable.setItem(current_row_count, 0, QTableWidgetItem(arp_source_ip))
                    self.arpResponseTable.setItem(current_row_count, 1, QTableWidgetItem(arp_source_mac))
                    self.arpResponseTable.setItem(current_row_count, 2, QTableWidgetItem(arp_destination_ip))
                    self.arpResponseTable.setItem(current_row_count, 3, QTableWidgetItem(arp_destination_mac))
                    self.arpResponseTable.setItem(current_row_count, 4, QTableWidgetItem(arp_opcode))
                    self.arpResponseTable.setItem(current_row_count, 5, QTableWidgetItem(arp_interface))

                    # Alignment of columns
                    for column in range(self.arpResponseTable.columnCount()):
                        self.arpResponseTable.item(current_row_count, column).setTextAlignment(Qt.AlignmentFlag.AlignCenter)
                    
                    # Populates Scapy command used field
                    arp_response_command_text = "sendp(Ether(src='" + str(arp_source_mac) + "', dst='" + str(arp_destination_mac) + \
                                              "')/ARP(op='" + str(arp_opcode) + "', hwsrc='" + str(arp_source_mac) + "', psrc='" +\
                                              str(arp_source_ip) + "', pdst='" + str(arp_destination_ip) + "', hwdst='" + str(arp_destination_mac) + "'), iface='" +arp_interface+ "', verbose=0)"
                    self.arpResponseScapyCommandTextBrowser.setText(arp_response_command_text)
        
        # DHCP tab
        if current_tab == 1:

            # DHCP Client Tab
            if self.dhcpTabWidget.currentIndex() == 0:
             
                # DHCP Source MAC Address                
                dhcp_source_mac = ""
                if self.dhcpClientSrcMac.isEnabled():
                    dhcp_source_mac = str(self.dhcpClientSrcMac.text())
                if self.dhcpClientSrcMacRandom.isChecked():
                    dhcp_source_mac = self.dhcp_mac_src_rand
                    self.auto_dhcp_client_mac_rand_default()
                
                # DHCP Destination MAC address
                dhcp_destination_mac = "ff:ff:ff:ff:ff:ff"
                if self.dhcpClientDstManual.isChecked():
                    dhcp_destination_mac = str(self.dhcpClientDstMac.text())
                
                # Checks whether the format of source MAC address is correct
                if not self.validate_mac_address(dhcp_source_mac):
                    # Error message
                    QMessageBox.warning(self, "Warning", "MAC source address seems incorrect!")
                    return False
                # Checks whether the format of destination MAC address is correct     
                if not self.validate_mac_address(dhcp_destination_mac):
                    # Error message
                    QMessageBox.warning(self, "Warning", "MAC destination address seems incorrect!")
                    return False
                # DHCP source IP addresses
                dhcp_source_ip = "0.0.0.0"
                if self.dhcpClientSrcIpManual.isChecked():
                    dhcp_source_ip = str(self.dhcpClientSrcIp.text())
                # Checks whether the format of DHCP source IP addresses is correct
                if not self.validate_ip_address(dhcp_source_ip):
                    # Error message
                    QMessageBox.warning(self, "Warning", "IP source address seems incorrect!")
                    return False
                # DHCP destination IP addresses
                dhcp_destination_ip = "255.255.255.255"
                if self.dhcpClientDstIpManual.isChecked():
                    dhcp_destination_ip = str(self.dhcpClientDstIp.text())
                # Checks whether the format of DHCP destination IP addresses is correct
                if not self.validate_ip_address(dhcp_destination_ip):
                    # Error message
                    QMessageBox.warning(self, "Warning", "IP destination address seems incorrect!")
                    return False
                # UDP source port
                udp_source_port = 68
                if self.dhcpClientSrcPortManual.isChecked():
                    udp_source_port = self.dhcpClientSrcPortSpin.value()
                # UDP destination port
                udp_destination_port = 67
                if self.dhcpClientDstPortManual.isChecked():
                    udp_destination_port = self.dhcpClientDstPortSpin.value()
                # Bootp transaction ID
                transaction_ID = self.dhcpClientTransationId.text()
                if not self.validate_dhcp_transaction_id(transaction_ID):
                    # Error message
                    QMessageBox.warning(self, "Warning", "Transaction ID seems incorrect!")
                    return False
                transaction_ID = int(transaction_ID, 16)

                # DHCP Client Messages
                message_type = ["discover",'request']
                dhcp_message_type = message_type[self.dhcpClientMessage.currentIndex()]
                # Network Interface
                dhcp_interface = str(self.interfaces_list[self.dhcpClientInterface.currentIndex()])
                # Calls the dhcp_client_forward_
                if not self.dhcp_client_forward(dhcp_source_mac, dhcp_destination_mac, dhcp_source_ip, dhcp_destination_ip, udp_destination_port, udp_source_port, transaction_ID, dhcp_message_type,dhcp_interface):
                    QMessageBox.warning(self, "Warning", "Packet could not be sent")
                    self.mainStatusBar.showMessage("Packet could not be sent")
                else:
                    # When packet is sent successfully the appropriate window is displayed
                    QMessageBox.information(self, "Information", "Packet sent")
                   
                   # When packet is sent successfully the appropriate message is in the status bar
                    self.mainStatusBar.showMessage("Packet sent successfully")
                    
                    # Populates table with packet details
                    current_row_count = self.dhcpClientTable.rowCount()
                    self.dhcpClientTable.insertRow(current_row_count)
                    self.dhcpClientTable.setItem(current_row_count, 0, QTableWidgetItem(dhcp_source_mac))
                    self.dhcpClientTable.setItem(current_row_count, 1, QTableWidgetItem(dhcp_destination_mac))
                    self.dhcpClientTable.setItem(current_row_count, 2, QTableWidgetItem(dhcp_source_ip))
                    self.dhcpClientTable.setItem(current_row_count, 3, QTableWidgetItem(dhcp_destination_ip))
                    self.dhcpClientTable.setItem(current_row_count, 4, QTableWidgetItem(str(udp_source_port)))
                    self.dhcpClientTable.setItem(current_row_count, 5, QTableWidgetItem(str(udp_destination_port)))
                    self.dhcpClientTable.setItem(current_row_count, 6, QTableWidgetItem(str(transaction_ID)))
                    self.dhcpClientTable.setItem(current_row_count, 7, QTableWidgetItem(dhcp_source_mac))
                    self.dhcpClientTable.setItem(current_row_count, 8, QTableWidgetItem(dhcp_message_type))
                    self.dhcpClientTable.setItem(current_row_count, 9, QTableWidgetItem(dhcp_interface))

                    # Alignment of columns
                    for column in range(self.dhcpClientTable.columnCount()):
                        self.dhcpClientTable.item(current_row_count, column).setTextAlignment(Qt.AlignmentFlag.AlignCenter)
                    
                    # Populates Scapy command used field
                    dhcp_client_command = "sendp(Ether(dst='"+dhcp_destination_mac+"', src='"+dhcp_source_mac+"')/IP(src='"+dhcp_source_ip+"', dst='"+dhcp_destination_ip+"')/UDP(dport="+str(udp_destination_port)+",sport="+str(udp_source_port)+")/BOOTP(op=1, xid="+str(transaction_ID)+", chaddr='"+dhcp_source_mac+"')/DHCP(options=[('message-type','" +dhcp_message_type+"'), ('end')]),iface='"+dhcp_interface+"', verbose=0)"
                    self.dhcpClientScapyCommandTextBrowser.setText(dhcp_client_command)

            # DHCP Server Tab
            if self.dhcpTabWidget.currentIndex() == 1:

                # DHCP Source Mac Address                
                dhcp_source_mac = ""
                if self.dhcpServerSrcMac.isEnabled():
                    dhcp_source_mac = str(self.dhcpServerSrcMac.text())
                if self.dhcpServerSrcMacRandom.isChecked():
                    dhcp_source_mac = self.dhcp_ser_mac_src_rand
                    self.auto_dhcp_server_src_mac_rand_default()
                # DHCP Destination MAC address  
                dhcp_destination_mac = ""
                if self.dhcpServerDstMac.isEnabled():
                    dhcp_destination_mac = str(self.dhcpServerDstMac.text())
                if self.dhcpServerDstMacRandom.isChecked():
                    dhcp_destination_mac = self.dhcp_ser_mac_dst_rand
                    self.auto_dhcp_server_dst_mac_rand_default
                # Checks whether the format of source MAC address is correct
                if not self.validate_mac_address(dhcp_source_mac):
                    # Error message
                    QMessageBox.warning(self, "Warning", "MAC source address seems incorrect!")
                    return False
                # Checks whether the format of destination MAC address is correct     
                if not self.validate_mac_address(dhcp_destination_mac):
                    # Error message
                    QMessageBox.warning(self, "Warning", "MAC destination address seems incorrect!")
                    return False
                # DHCP source IP addresses
                dhcp_source_ip = ""
                if self.dhcpServerSrcIp.isEnabled():
                    dhcp_source_ip = str(self.dhcpServerSrcIp.text())
                if self.dhcpServerSrcIpRandom.isChecked():
                    dhcp_source_ip = self.dhcp_ser_ip_src_rand
                    self.auto_dhcp_server_src_ip_rand_default()
                # Checks whether the format of DHCP source IP addresses is correct
                if not self.validate_ip_address(dhcp_source_ip):
                    # Error message
                    QMessageBox.warning(self, "Warning", "IP source address seems incorrect!")
                    return False
                # DHCP destination IP addresses
                dhcp_destination_ip = ""  
                if self.dhcpServerDstIp.isEnabled():
                    dhcp_destination_ip = str(self.dhcpServerDstIp.text())
                if self.dhcpServerDstIpRandom.isChecked():
                    dhcp_destination_ip = self.dhcp_ser_ip_dst_rand
                    self.auto_dhcp_server_dst_ip_rand_default()

                # Checks whether the format of DHCP destination IP addresses is correct
                if not self.validate_ip_address(dhcp_destination_ip):
                    # Error message
                    QMessageBox.warning(self, "Warning", "IP destination address seems incorrect!")
                    return False
                # UDP source port
                udp_source_port = 67
                if self.dhcpServerSrcPortManual.isChecked():
                    udp_source_port = self.dhcpServerSrcPortSpin.value() 
                # UDP destination port
                udp_destination_port = 68
                if self.dhcpServerDstPortManual.isChecked():
                    udp_destination_port = self.dhcpServerDstPortSpin.value()
                # Bootp transaction ID
                transaction_ID = self.dhcpServerTransactionId.text()
                if not self.validate_dhcp_transaction_id(transaction_ID):
                    # Error message
                    QMessageBox.warning(self, "Warning", "Transaction ID seems incorrect!")
                    return False
                transaction_ID = int(transaction_ID, 16)
                # DHCP Client Messages
                message_type = ["offer",'ack']
                dhcp_message_type = message_type[self.dhcpServerMessage.currentIndex()]
                # Network Interface
                dhcp_interface = str(self.interfaces_list[self.dhcpServerInterface.currentIndex()])

                # DHCP Advanced options
                subnet_mask = "255.255.255.0"
                server_id = dhcp_source_ip
                name_server = dhcp_source_ip
                rebinding_time = 37800
                renewal_time = 21600
                domain_name = "example.com."
                if self.dhcpServerAdvanced.isChecked():
                    # Validates subnet mask
                    subnet_mask = str(self.dhcpServerSubnetMask.text())
                    if not self.validate_ip_address(subnet_mask):
                        # Error message
                        QMessageBox.warning(self, "Warning", "Subnet mask seems incorrect!")
                        return False
                    # Validates server id IP
                    server_id = str(self.dhcpServerIdentifier.text())
                    if not self.validate_ip_address(server_id):
                        # Error message
                        QMessageBox.warning(self, "Warning", "Server ID IP seems incorrect!")
                        return False
                    # Validates name server IP
                    name_server = str(self.dhcpServerNameServer.text())
                    if not self.validate_ip_address(name_server):
                        # Error message
                        QMessageBox.warning(self, "Warning", "Name server IP seems incorrect!")
                        return False
                    domain_name = str(self.dhcpServerDomainName.text())
                    rebinding_time = self.dhcpServerRebing.value()
                    renewal_time = self.dhcpServerRenewal.value()

                # Calls the dhcp_server_client_forward_function
                if not self.dhcp_server_forward(dhcp_source_mac, dhcp_destination_mac, dhcp_source_ip, dhcp_destination_ip, udp_destination_port, udp_source_port, transaction_ID, dhcp_message_type, dhcp_interface, subnet_mask, rebinding_time, renewal_time, name_server, domain_name, server_id):
                    QMessageBox.warning(self, "Warning", "Packet could not be sent")
                    self.mainStatusBar.showMessage("Packet could not be sent")
                else:
                    # When packet is sent successfully the appropriate window is displayed
                    QMessageBox.information(self, "Information", "Packet sent")
                    # When packet is sent successfully the appropriate message is in the status bar
                    self.mainStatusBar.showMessage("Packet sent successfully")
                    
                    # Populates table with packet details
                    current_row_count = self.dhcpServerTable.rowCount()
                    self.dhcpServerTable.insertRow(current_row_count)
                    self.dhcpServerTable.setItem(current_row_count, 0, QTableWidgetItem(dhcp_source_ip))
                    self.dhcpServerTable.setItem(current_row_count, 1, QTableWidgetItem(dhcp_source_mac))
                    self.dhcpServerTable.setItem(current_row_count, 2, QTableWidgetItem(dhcp_destination_ip))
                    self.dhcpServerTable.setItem(current_row_count, 3, QTableWidgetItem(dhcp_destination_mac))
                    self.dhcpServerTable.setItem(current_row_count, 4, QTableWidgetItem(str(udp_source_port)))
                    self.dhcpServerTable.setItem(current_row_count, 5, QTableWidgetItem(str(udp_destination_port)))
                    self.dhcpServerTable.setItem(current_row_count, 6, QTableWidgetItem(str(transaction_ID)))
                    self.dhcpServerTable.setItem(current_row_count, 7, QTableWidgetItem(dhcp_destination_mac))
                    self.dhcpServerTable.setItem(current_row_count, 8, QTableWidgetItem(dhcp_message_type))
                    self.dhcpServerTable.setItem(current_row_count, 9, QTableWidgetItem(subnet_mask))
                    self.dhcpServerTable.setItem(current_row_count, 10, QTableWidgetItem(server_id))
                    self.dhcpServerTable.setItem(current_row_count, 11, QTableWidgetItem(str(rebinding_time)))
                    self.dhcpServerTable.setItem(current_row_count, 12, QTableWidgetItem(str(renewal_time)))
                    self.dhcpServerTable.setItem(current_row_count, 13, QTableWidgetItem(name_server))
                    self.dhcpServerTable.setItem(current_row_count, 14, QTableWidgetItem(domain_name))
                    self.dhcpServerTable.setItem(current_row_count, 15, QTableWidgetItem(dhcp_interface))

                    # Alignment of columns
                    for column in range(self.dhcpServerTable.columnCount()):
                        self.dhcpServerTable.item(current_row_count,column).setTextAlignment(Qt.AlignmentFlag.AlignCenter)

                    # Populates Scapy command used field
                    dhcp_server_command = "sendp(Ether(dst='"+dhcp_destination_mac+"', src='"+dhcp_source_mac+"')/IP(src='"+dhcp_source_ip+"',dst='"+dhcp_destination_ip+"')/UDP(dport="+str(udp_destination_port)+",sport="+str(udp_source_port)+")/BOOTP(op=2,yiaddr='"+dhcp_destination_ip+"',siaddr='"+dhcp_source_ip+"',xid="+str(transaction_ID)+",chaddr='"+dhcp_source_mac+"')\
/DHCP(options=[('message-type','"+dhcp_message_type+"')])/DHCP(options=[('subnet_mask','"+subnet_mask+"')])/DHCP(options=[('renewal_time',"+str(renewal_time)+")])\
/DHCP(options=[('rebinding_time',"+ str(rebinding_time)+")])/DHCP(options=[('name_server','"+name_server+"')])/DHCP(options=[('domain','"+domain_name+"')])\
/DHCP(options=[('server_id','"+server_id+"'),('end')]), iface='"+dhcp_interface+"', verbose=0)"

                    self.dhcpServerScapyCommandTextBrowser.setText(dhcp_server_command)
        
        # Ether tab
        if current_tab == 2:
            # Informs user that packet can only be sent in tabs IPv4, TCP, UDP, ICMP
            QMessageBox.information(self, "Information", "To send packet use IP, TCP, UDP, ICMP, DNS tabs")

        # IP tab
        if current_tab == 3:

            # MAC Section
            # Source MAC address        
            mac_source = self.etherMacSrcEdit.text()
            # Checks whether the format of source MAC address is correct
            if not self.validate_mac_address(mac_source):
                # Error message
                QMessageBox.warning(self, "Warning", "MAC source address seems incorrect!")

                return False
            # Destination MAC address
            mac_destination = self.etherMacDstEdit.text()
            # Checks whether the format of destination MAC address is correct
            if not self.validate_mac_address(mac_destination):
                # Error message
                QMessageBox.warning(self, "Warning", "MAC destination address seems incorrect!")
                return False

            # IPv4 Tab
            if self.ipTabWidget.currentIndex() == 0:             
                # IP Section
                # Source IP
                ip_source = self.ipSrcEdit.text()
                # Checks whether the format of source IP addresses is correct
                if not self.validate_ip_address(ip_source):
                    # Error message
                    QMessageBox.warning(self, "Warning", "IP source address seems incorrect!")
                    return False
                # Destination IP
                ip_destination = self.ipDstEdit.text()
                # Checks whether the format of destination IP addresses is correct
                if not self.validate_ip_address(ip_destination):
                    # Error message
                    QMessageBox.warning(self, "Warning", "IP destination address seems incorrect!")
                    return False
                # Flags
                ip_flags = 0 # default value
                if self.ipReservedBitCheckBox.isChecked():
                    ip_flags += 4
                if self.ipDontFragmentCheckBox.isChecked():
                    ip_flags += 2
                if self.ipMoreFragmentsCheckBox.isChecked():
                    ip_flags += 1
                # IP Protocol
                ip_protocol = 6 # default value
                if self.ipProtocolCheckBox.isChecked():
                    ip_protocol = self.ipProtocolSpinBox.value()
                # TTL
                ip_ttl = 64 # default value
                if self.ipTTLCheckBox.isChecked():
                    ip_ttl = self.ipTtlSpinBox.value()
                # IP Version
                ip_version = 4 # default value
                if self.ipVersionCheckBox.isChecked():
                    ip_version = self.ipVersionSpinBox.value()
                # Differentiated Services Code Point 
                ip_tos = 0 # default value
                if self.ipTosCheckBox.isChecked():
                    ip_tos = self.ipTosSpinBox.value()
                # IP ID
                ip_ip_id = 1 # default value
                if self.ipIDCheckBox.isChecked():
                    ip_ip_id = self.ipIDSpinBox.value()
                # Fragmentation Offset
                ip_frag_offset = 0 # default value
                if self.ipFragOffsetCheckBox.isChecked():
                    ip_frag_offset = self.ipFragOffsetSpinBox.value()
                # Network Interface
                ip_interface = str(self.interfaces_list[self.ipInterace.currentIndex()])          
                # Calls the ip_forward function
                if not self.ip_forward(mac_source, mac_destination, ip_source, ip_destination, ip_flags, ip_ttl,
                                                ip_ip_id, ip_version, ip_frag_offset, ip_protocol, ip_tos, ip_interface):
                    QMessageBox.warning(self, "Warning", "Packet could not be sent")
                    self.mainStatusBar.showMessage("Packet could not be sent")
                else:
                    # When packet is sent successfully the appropriate window is displayed
                    QMessageBox.information(self, "Information", "Packet sent")
                    # When packet is sent successfully the appropriate message is in the status bar
                    self.mainStatusBar.showMessage("Packet sent successfully")
                    
                    # Populates table with packet details
                    current_row_count = self.ipTable.rowCount()
                    self.ipTable.insertRow(current_row_count)
                    self.ipTable.setItem(current_row_count, 0, QTableWidgetItem(mac_source))
                    self.ipTable.setItem(current_row_count, 1, QTableWidgetItem(mac_destination))
                    self.ipTable.setItem(current_row_count, 2, QTableWidgetItem(ip_source))
                    self.ipTable.setItem(current_row_count, 3, QTableWidgetItem(ip_destination))
                    self.ipTable.setItem(current_row_count, 4, QTableWidgetItem(str(ip_flags)))
                    self.ipTable.setItem(current_row_count, 5, QTableWidgetItem(str(ip_protocol)))
                    self.ipTable.setItem(current_row_count, 6, QTableWidgetItem(str(ip_ttl)))
                    self.ipTable.setItem(current_row_count, 7, QTableWidgetItem(str(ip_version)))
                    self.ipTable.setItem(current_row_count, 8, QTableWidgetItem(str(ip_tos)))
                    self.ipTable.setItem(current_row_count, 9, QTableWidgetItem(str(ip_ip_id)))
                    self.ipTable.setItem(current_row_count, 10, QTableWidgetItem(str(ip_frag_offset)))
                    self.ipTable.setItem(current_row_count, 11, QTableWidgetItem(str(ip_interface)))
                    # Alignment of columns
                    for column in range(self.ipTable.columnCount()):
                            self.ipTable.item(current_row_count,column).setTextAlignment(Qt.AlignmentFlag.AlignCenter)
                   
                    # Populates Scapy command used field
                    ip_command_text = "sendp(Ether(src='" + str(mac_source) + "', dst='" + str(mac_destination) + \
                                              "')/IP(src='" + str(ip_source) + "', dst='" + str(ip_destination) + "', ttl=" +\
                                              str(ip_ttl) + ", flags=" + str(ip_flags) + ", id=" + str(ip_ip_id) + ", version=" + \
                                              str(ip_version) + ", frag=" + str(ip_frag_offset) + ", proto=" + str(ip_protocol) + \
                                              ", tos=" + str(ip_tos) + "), iface='"+ip_interface+"', verbose=0)"
                    self.ipScapyCommandTextBrowser.setText(ip_command_text)

            # IPv6 Tab
            if self.ipTabWidget.currentIndex() == 1:    
                # Source IPv6
                ipv6_source = self.ipv6SrcIpAddr.text()
                # Checks whether the format of source IPv6 addresses is correct
                if not self.validate_ipv6_address(ipv6_source):
                    # Error message
                    QMessageBox.warning(self, "Warning", "Source IPv6 address seems incorrect!")
                    return False
                # Destination IPv6
                ipv6_destination = self.ipv6DstIpAddr.text()
                # Checks whether the format of destination IPv6 addresses is correct
                if not self.validate_ipv6_address(ipv6_destination):
                    # Error message
                    QMessageBox.warning(self, "Warning", "Destination IPv6 address seems incorrect!")
                    return False

                # Next layer protocol
                ipv6_next_header = 59 # default no next header
                if self.ipv6NextHeaderCheckBox.isChecked():
                    ipv6_next_header = self.ipv6NextHeaderSpinBox.value()
                # Hop count
                ipv6_hop_limit = 64 # default 64
                if self.ipv6HopLimitCheckBox.isChecked():
                    ipv6_hop_limit = self.ipv6HopLimitSpinBox.value()
                # IP Version
                ipv6_version = 6 # default value
                if self.ipv6VersionCheckBox.isChecked():
                    ipv6_version = self.ipv6VersionSpinBox.value()
                # IPv6 ToS
                ipv6_tos = 0 # default value
                if self.ipv6TosCheckBox.isChecked():
                    ipv6_tos = self.ipv6TospinBox.value()
                # IPv6 Flow
                ipv6_flow = 0 # default value
                if self.ipv6FlowLabelCheckBox.isChecked():
                    ipv6_flow = self.ipv6FlowLabelSpinBox.value()
                # Network Interface
                ipv6_interface = str(self.interfaces_list[self.ipv6Interace.currentIndex()])
                # Calls the ipv6_forwardfunction
                if not self.ipv6_forward(mac_source, mac_destination, ipv6_source, ipv6_destination, ipv6_interface, ipv6_next_header, ipv6_hop_limit, ipv6_version, ipv6_tos, ipv6_flow):
                    QMessageBox.warning(self, "Warning", "Packet could not be sent")
                    self.mainStatusBar.showMessage("Packet could not be sent")
                else:
                    # When packet is sent successfully the appropriate window is displayed
                    QMessageBox.information(self, "Information", "Packet sent")
                    # When packet is sent successfully the appropriate message is in the status bar
                    self.mainStatusBar.showMessage("Packet sent successfully")
                    # Populates table with packet details
                    current_row_count = self.ipv6Table.rowCount()
                    self.ipv6Table.insertRow(current_row_count)
                    self.ipv6Table.setItem(current_row_count, 0, QTableWidgetItem(mac_source))
                    self.ipv6Table.setItem(current_row_count, 1, QTableWidgetItem(mac_destination))
                    self.ipv6Table.setItem(current_row_count, 2, QTableWidgetItem(ipv6_source))
                    self.ipv6Table.setItem(current_row_count, 3, QTableWidgetItem(ipv6_destination))
                    self.ipv6Table.setItem(current_row_count, 4, QTableWidgetItem(str(ipv6_next_header)))
                    self.ipv6Table.setItem(current_row_count, 5, QTableWidgetItem(str(ipv6_hop_limit)))
                    self.ipv6Table.setItem(current_row_count, 6, QTableWidgetItem(str(ipv6_version)))
                    self.ipv6Table.setItem(current_row_count, 7, QTableWidgetItem(str(ipv6_tos)))
                    self.ipv6Table.setItem(current_row_count, 8, QTableWidgetItem(str(ipv6_flow)))
                    self.ipv6Table.setItem(current_row_count, 9, QTableWidgetItem(ipv6_interface))
                    # Alignment of columns
                    for column in range(self.ipv6Table.columnCount()):
                            self.ipv6Table.item(current_row_count,column).setTextAlignment(Qt.AlignmentFlag.AlignCenter)
                   
                    # Populates Scapy command used field
                    ipv6_command_text = "sendp(Ether(src='"+str(mac_source)+"', dst='"+str(mac_destination)+\
                                              "')/IPv6(src='"+str(ipv6_source)+"', dst='"+str(ipv6_destination)+"', hlim=" +\
                                              str(ipv6_hop_limit)+ ", version="+str(ipv6_version)+", nh="+str(ipv6_next_header)+ ", tc=" +str(ipv6_tos)+", fl="+str(ipv6_flow)+"), iface='"+ipv6_interface+"', verbose=0)"
                    self.ipv6ScapyCommandTextBrowser.setText(ipv6_command_text)

        # TCP tab
        if current_tab == 4:

            # MAC Section
            # Source MAC address
            mac_source = self.etherMacSrcEdit.text()
            # Checks whether the format of source MAC address is correct
            if not self.validate_mac_address(mac_source):
                # Error message
                QMessageBox.warning(self, "Warning", "MAC source address seems incorrect!")
                return False
            # Destination MAC address
            mac_destination = self.etherMacDstEdit.text()
            # Checks whether the format of destination MAC address is correct
            if not self.validate_mac_address(mac_destination):
                # Error message
                QMessageBox.warning(self, "Warning", "MAC destination address seems incorrect!")
                return False

            # TCP section
            # Gets TCP source and destination port
            tcp_source_port = self.tcpSrcPortSpin.value()
            tcp_destination_port = self.tcpDstPortSpin.value()
            # Checks which flags are selected
            tcp_flags = ""
            if self.tcpSynFlagCheckBox.isChecked():
                tcp_flags = "S"
            if self.tcpAckFlagCheckBox.isChecked():
                tcp_flags += "A"
            if self.tcpRstFlagCheckBox.isChecked():
                tcp_flags += "R"
            if self.tcpFinFlagCheckBox.isChecked():
                tcp_flags += "F"
            if self.tcpPushFlagCheckBox.isChecked():
                tcp_flags += "P"
            if self.tcpCwrFlagCheckBox.isChecked():
                tcp_flags += "C"
            if self.tcpEcnFlagCheckBox.isChecked():
                tcp_flags += "E"
            if self.tcpUrgFlagCheckBox.isChecked():
                tcp_flags += "U"
            # TCP window size
            tcp_window_size = 8192
            if self.tcpWinSizeCheckBox.isChecked():
                tcp_window_size = self.tcpWinSizeSpinBox.value()
            # TCP seq number
            tcp_seq_number = 1000
            if self.tcpSeqNumCheckBox.isChecked():
                tcp_seq_number = self.tcpSeqNumSpinBox.value()
            # TCP ack number
            tcp_ack_number = 1000
            if self.tcpAckNumCheckBox.isChecked():
                tcp_ack_number = self.tcpAckNumSpinBox.value()
            # Network interface
            tcp_interface = str(self.interfaces_list[self.tcpInterace.currentIndex()])

            # IPv6 Section
            if self.tcpUseIPv6radioButton.isChecked():
                ipv6_source = self.ipv6SrcIpAddr.text()
                # Checks whether the format of source IPv6 addresses is correct
                if not self.validate_ipv6_address(ipv6_source):
                    # Error message
                    QMessageBox.warning(self, "Warning", "Source IPv6 address seems incorrect!")
                    return False
                ipv6_destination = self.ipv6DstIpAddr.text()
                # Checks whether the format of destination IPv6 addresses is correct
                if not self.validate_ipv6_address(ipv6_destination):
                    # Error message
                    QMessageBox.warning(self, "Warning", "Destination IPv6 address seems incorrect!")
                    return False

                # Next layer protocol
                ipv6_next_header = 6 # default TCP
                if self.ipv6NextHeaderCheckBox.isChecked():
                    ipv6_next_header = self.ipv6NextHeaderSpinBox.value()
                # Next layer protocol - default TCP
                ipv6_hop_limit = 64
                if self.ipv6HopLimitCheckBox.isChecked():
                    ipv6_hop_limit = self.ipv6HopLimitSpinBox.value()
                # IP Version
                ipv6_version = 6 # default value
                if self.ipv6VersionCheckBox.isChecked():
                    ipv6_version = self.ipv6VersionSpinBox.value()
                # IPv6 ToS
                ipv6_tos = 0 # default value
                if self.ipv6TosCheckBox.isChecked():
                    ipv6_tos = self.ipv6TospinBox.value()
                # IPv6 Flow
                ipv6_flow = 0 # default value
                if self.ipv6FlowLabelCheckBox.isChecked():
                    ipv6_flow = self.ipv6FlowLabelSpinBox.value()
                # Calls the tcp_forward_function
                if not self.tcp_ipv6_forward(mac_source, mac_destination, ipv6_source, ipv6_destination, ipv6_next_header, ipv6_version, ipv6_hop_limit, ipv6_tos, ipv6_flow, tcp_source_port,tcp_destination_port, tcp_flags, tcp_window_size, tcp_seq_number, tcp_ack_number,tcp_interface):
                    QMessageBox.warning(self, "Warning", "Packet could not be sent")
                    self.mainStatusBar.showMessage("Packet could not be sent")

                else:
                    # When packet is sent successfully the appropriate window is displayed
                    QMessageBox.information(self, "Information", "Packet sent")
                    # When packet is sent successfully the appropriate message is in the status bar
                    self.mainStatusBar.showMessage("Packet sent successfully")
                    # Gets the current table row
                    current_row_count = self.tcpIPv6TableWidget.rowCount()
                    # Populates table with packet details
                    self.tcpIPv6TableWidget.insertRow(current_row_count)
                    self.tcpIPv6TableWidget.setItem(current_row_count, 0, QTableWidgetItem(mac_source))
                    self.tcpIPv6TableWidget.setItem(current_row_count, 1, QTableWidgetItem(mac_destination))
                    self.tcpIPv6TableWidget.setItem(current_row_count, 2, QTableWidgetItem(ipv6_source))
                    self.tcpIPv6TableWidget.setItem(current_row_count, 3, QTableWidgetItem(ipv6_destination))
                    self.tcpIPv6TableWidget.setItem(current_row_count, 4, QTableWidgetItem(str(ipv6_next_header)))
                    self.tcpIPv6TableWidget.setItem(current_row_count, 5, QTableWidgetItem(str(ipv6_hop_limit)))
                    self.tcpIPv6TableWidget.setItem(current_row_count, 6, QTableWidgetItem(str(ipv6_version)))
                    self.tcpIPv6TableWidget.setItem(current_row_count, 7, QTableWidgetItem(str(ipv6_tos)))
                    self.tcpIPv6TableWidget.setItem(current_row_count, 8, QTableWidgetItem(str(ipv6_flow)))
                    self.tcpIPv6TableWidget.setItem(current_row_count, 9, QTableWidgetItem(str(tcp_source_port)))
                    self.tcpIPv6TableWidget.setItem(current_row_count, 10, QTableWidgetItem(str(tcp_destination_port)))
                    self.tcpIPv6TableWidget.setItem(current_row_count, 11, QTableWidgetItem(tcp_flags))
                    self.tcpIPv6TableWidget.setItem(current_row_count, 12, QTableWidgetItem(str(tcp_window_size)))
                    self.tcpIPv6TableWidget.setItem(current_row_count, 13, QTableWidgetItem(str(tcp_seq_number)))
                    self.tcpIPv6TableWidget.setItem(current_row_count, 14, QTableWidgetItem(str(tcp_ack_number)))
                    self.tcpIPv6TableWidget.setItem(current_row_count, 15, QTableWidgetItem(tcp_interface))
                    # Alignment of columns
                    for column in range(self.tcpIPv6TableWidget.columnCount()):
                            self.tcpIPv6TableWidget.item(current_row_count,column).setTextAlignment(Qt.AlignmentFlag.AlignCenter)
                    
                    # Populates Scapy command used field

                    tcp_command_text = "sendp(Ether(src='"+str(mac_source)+"', dst='"+str(mac_destination)+\
                                              "')/IPv6(src='"+str(ipv6_source)+"', dst='"+str(ipv6_destination)+"', hlim=" +\
                                              str(ipv6_hop_limit)+ ", version="+str(ipv6_version)+", nh="+str(ipv6_next_header)+", tc="+str(ipv6_tos)+", fl="+str(ipv6_flow)+")/TCP(sport=" + str(tcp_source_port) + ", dport=" + \
                                          str(tcp_destination_port) + ", flags='" + str(tcp_flags) + "', window=" + \
                                          str(tcp_window_size) + ", seq=" + str(tcp_seq_number) + ", ack=" + str(tcp_ack_number)\
                                          + ")/'GET / HTTP/1.1\\r\\n\\r\\n', iface='"+tcp_interface+"', verbose=0)"

                    self.tcpScapyCommandTextBrowser.setText(tcp_command_text)
            else:
                # IP Section
                # Source IP
                ip_source = self.ipSrcEdit.text()
                # Checks whether the format of source IP addresses is correct
                if not self.validate_ip_address(ip_source):
                    # Error message
                    QMessageBox.warning(self, "Warning", "IP source address seems incorrect!")
                    return False
                # Destination IP
                ip_destination = self.ipDstEdit.text()
                # Checks whether the format of destination IP addresses is correct
                if not self.validate_ip_address(ip_destination):
                    # Error message
                    QMessageBox.warning(self, "Warning", "IP destination address seems incorrect!")
                    return False

                # Checks whether IP flags are set
                # Default value is 0
                ip_flags = 0
                if self.ipReservedBitCheckBox.isChecked():
                    ip_flags += 4
                if self.ipDontFragmentCheckBox.isChecked():
                    ip_flags += 2
                if self.ipMoreFragmentsCheckBox.isChecked():
                    ip_flags += 1
                # Checks whether TTL value is set
                # Default value is 64
                ip_ttl = 64
                if self.ipTTLCheckBox.isChecked():
                    ip_ttl = self.ipTtlSpinBox.value()
                # Checks whether IP ID is set
                # Default value is 1
                ip_ip_id = 1
                if self.ipIDCheckBox.isChecked():
                    ip_ip_id = self.ipIDSpinBox.value()
                # Check whether IP Version is checked
                # Default value is 4
                ip_version = 4
                if self.ipVersionCheckBox.isChecked():
                    ip_version = self.ipVersionSpinBox.value()
                # Checks whether Fragmentation Offset is set
                # Default value is 0
                ip_frag_offset = 0
                if self.ipFragOffsetCheckBox.isChecked():
                    ip_frag_offset = self.ipFragOffsetSpinBox.value()
                # Checks whether Transport protocol is set
                # Default value is 6
                ip_tos = 0
                if self.ipTosCheckBox.isChecked():
                    ip_tos = self.ipTosSpinBox.value()
                # IP Protocol
                ip_protocol = 6 # default value
                if self.ipProtocolCheckBox.isChecked():
                    ip_protocol = self.ipProtocolSpinBox.value()    

                # Calls the tcp_forward_function
                if not self.tcp_forward(mac_source, mac_destination, ip_source, ip_destination, ip_flags, ip_ttl, ip_ip_id, ip_version,
                                                    ip_frag_offset, ip_tos, ip_protocol, tcp_source_port,
                                                    tcp_destination_port, tcp_flags, tcp_window_size,
                                                    tcp_seq_number, tcp_ack_number,tcp_interface):
                    QMessageBox.warning(self, "Warning", "Packet could not be sent")
                    self.mainStatusBar.showMessage("Packet could not be sent")

                else:
                    # When packet is sent successfully the appropriate window is displayed
                    QMessageBox.information(self, "Information", "Packet sent")
                    # When packet is sent successfully the appropriate message is in the status bar
                    self.mainStatusBar.showMessage("Packet sent successfully")
                    # Gets the current table row
                    current_row_count = self.tcpTableWidget.rowCount()
                    # Populates table with packet details
                    self.tcpTableWidget.insertRow(current_row_count)
                    self.tcpTableWidget.setItem(current_row_count, 0, QTableWidgetItem(mac_source))
                    self.tcpTableWidget.setItem(current_row_count, 1, QTableWidgetItem(mac_destination))
                    self.tcpTableWidget.setItem(current_row_count, 2, QTableWidgetItem(ip_source))
                    self.tcpTableWidget.setItem(current_row_count, 3, QTableWidgetItem(ip_destination))
                    self.tcpTableWidget.setItem(current_row_count, 4, QTableWidgetItem(str(ip_flags)))
                    self.tcpTableWidget.setItem(current_row_count, 5, QTableWidgetItem(str(ip_protocol)))
                    self.tcpTableWidget.setItem(current_row_count, 6, QTableWidgetItem(str(ip_ttl)))
                    self.tcpTableWidget.setItem(current_row_count, 7, QTableWidgetItem(str(ip_version)))
                    self.tcpTableWidget.setItem(current_row_count, 8, QTableWidgetItem(str(ip_tos)))
                    self.tcpTableWidget.setItem(current_row_count, 9, QTableWidgetItem(str(ip_ip_id)))
                    self.tcpTableWidget.setItem(current_row_count, 10, QTableWidgetItem(str(ip_frag_offset)))
                    self.tcpTableWidget.setItem(current_row_count, 11, QTableWidgetItem(str(tcp_source_port)))
                    self.tcpTableWidget.setItem(current_row_count, 12, QTableWidgetItem(str(tcp_destination_port)))
                    self.tcpTableWidget.setItem(current_row_count, 13, QTableWidgetItem(tcp_flags))
                    self.tcpTableWidget.setItem(current_row_count, 14, QTableWidgetItem(str(tcp_window_size)))
                    self.tcpTableWidget.setItem(current_row_count, 15, QTableWidgetItem(str(tcp_seq_number)))
                    self.tcpTableWidget.setItem(current_row_count, 16, QTableWidgetItem(str(tcp_ack_number)))
                    self.tcpTableWidget.setItem(current_row_count, 17, QTableWidgetItem(tcp_interface))
                    # Alignment of columns
                    for column in range(self.tcpTableWidget.columnCount()):
                            self.tcpTableWidget.item(current_row_count,column).setTextAlignment(Qt.AlignmentFlag.AlignCenter)
                    
                    # Populates Scapy command used field

                    tcp_command_text = "sendp(Ether(src='" + str(mac_source) + "', dst='" + str(mac_destination) + \
                                          "')/IP(src='" + str(ip_source) + "', dst='" + str(ip_destination) + "', ttl=" + \
                                          str(ip_ttl) + ", flags=" + str(ip_flags) + ", id=" + str(ip_ip_id) + ", version=" + \
                                          str(ip_version) + ", frag=" + str(ip_frag_offset) + ", proto=" + str(6) + \
                                          ", tos=" + str(ip_tos) + ")/TCP(sport=" + str(tcp_source_port) + ", dport=" + \
                                          str(tcp_destination_port) + ", flags='" + str(tcp_flags) + "', window=" + \
                                          str(tcp_window_size) + ", seq=" + str(tcp_seq_number) + ", ack=" + str(tcp_ack_number)\
                                          + ")/'GET / HTTP/1.1\\r\\n\\r\\n', iface='"+tcp_interface+"', verbose=0)"

                    self.tcpScapyCommandTextBrowser.setText(tcp_command_text)

        # UDP tab
        if current_tab == 5:

            # MAC Section
            # Source MAC address
            mac_source = self.etherMacSrcEdit.text()
            # Checks whether the format of source MAC address is correct
            if not self.validate_mac_address(mac_source):
                # Error message
                QMessageBox.warning(self, "Warning", "MAC source address seems incorrect!")
                return False
            # Destination MAC address
            mac_destination = self.etherMacDstEdit.text()
            # Checks whether the format of source MAC address is correct
            if not self.validate_mac_address(mac_destination):
                # Error message
                QMessageBox.warning(self, "Warning", "MAC destination address seems incorrect!")
                return False

            # UDP section
            udp_source_port = self.udpSrcPortSpin.value()
            udp_destination_port = self.udpDstPortSpin.value()
            # Network interface
            udp_interface = str(self.interfaces_list[self.udpInterace.currentIndex()])
            
            # IPv6 Section
            if self.udpUseIPv6radioButton.isChecked():

                # Source IPv6
                ipv6_source = self.ipv6SrcIpAddr.text()
                # Checks whether the format of source IPv6 addresses is correct
                if not self.validate_ipv6_address(ipv6_source):
                    # Error message
                    QMessageBox.warning(self, "Warning", "Source IPv6 address seems incorrect!")
                    return False
                # Source IPv6
                ipv6_destination = self.ipv6DstIpAddr.text()
                # Checks whether the format of destination IPv6 addresses is correct
                if not self.validate_ipv6_address(ipv6_destination):
                    # Error message
                    QMessageBox.warning(self, "Warning", "Destination IPv6 address seems incorrect!")
                    return False
                
                # Next layer protocol
                ipv6_next_header = 17 # default UDP
                if self.ipv6NextHeaderCheckBox.isChecked():
                    ipv6_next_header = self.ipv6NextHeaderSpinBox.value()
                # Hop Count
                ipv6_hop_limit = 64 # default 64
                if self.ipv6HopLimitCheckBox.isChecked():
                    ipv6_hop_limit = self.ipv6HopLimitSpinBox.value()
                # IP Version
                ipv6_version = 6 # default value
                if self.ipv6VersionCheckBox.isChecked():
                    ipv6_version = self.ipv6VersionSpinBox.value()
                # IPv6 ToS
                ipv6_tos = 0 # default value
                if self.ipv6TosCheckBox.isChecked():
                    ipv6_tos = self.ipv6TospinBox.value()
                # IPv6 Flow
                ipv6_flow = 0 # default value
                if self.ipv6FlowLabelCheckBox.isChecked():
                    ipv6_flow = self.ipv6FlowLabelSpinBox.value()

                # Calls the tcp_forward_function
                if not self.udp_ipv6_forward(mac_source, mac_destination, ipv6_source, ipv6_destination, ipv6_next_header, ipv6_version, ipv6_hop_limit, ipv6_tos, ipv6_flow, udp_source_port, udp_destination_port, udp_interface):
                    QMessageBox.warning(self, "Warning", "Packet could not be sent")
                    self.mainStatusBar.showMessage("Packet could not be sent")

                else:
                    # When packet is sent successfully the appropriate window is displayed
                    QMessageBox.information(self, "Information", "Packet sent")
                    # When packet is sent successfully the appropriate message is in the status bar
                    self.mainStatusBar.showMessage("Packet sent successfully")
                    # Gets the current table row
                    current_row_count = self.udpIPv6Table.rowCount()
                    # Populates table with packet details
                    self.udpIPv6Table.insertRow(current_row_count)
                    self.udpIPv6Table.setItem(current_row_count, 0, QTableWidgetItem(mac_source))
                    self.udpIPv6Table.setItem(current_row_count, 1, QTableWidgetItem(mac_destination))
                    self.udpIPv6Table.setItem(current_row_count, 2, QTableWidgetItem(ipv6_source))
                    self.udpIPv6Table.setItem(current_row_count, 3, QTableWidgetItem(ipv6_destination))
                    self.udpIPv6Table.setItem(current_row_count, 4, QTableWidgetItem(str(ipv6_next_header)))
                    self.udpIPv6Table.setItem(current_row_count, 5, QTableWidgetItem(str(ipv6_hop_limit)))
                    self.udpIPv6Table.setItem(current_row_count, 6, QTableWidgetItem(str(ipv6_version)))
                    self.udpIPv6Table.setItem(current_row_count, 7, QTableWidgetItem(str(ipv6_tos)))
                    self.udpIPv6Table.setItem(current_row_count, 8, QTableWidgetItem(str(ipv6_flow)))
                    self.udpIPv6Table.setItem(current_row_count, 9, QTableWidgetItem(str(udp_source_port)))
                    self.udpIPv6Table.setItem(current_row_count, 10, QTableWidgetItem(str(udp_destination_port)))
                    self.udpIPv6Table.setItem(current_row_count, 11, QTableWidgetItem(udp_interface))
                    # Alignment of columns
                    for column in range(self.udpIPv6Table.columnCount()):
                            self.udpIPv6Table.item(current_row_count,column).setTextAlignment(Qt.AlignmentFlag.AlignCenter)
                    
                    # Populates Scapy command used field
                    udp_command_text = "sendp(Ether(src='"+str(mac_source)+"', dst='"+str(mac_destination)+\
                                              "')/IPv6(src='"+str(ipv6_source)+"', dst='"+str(ipv6_destination)+"', hlim=" +\
                                              str(ipv6_hop_limit)+ ", version="+str(ipv6_version)+", nh="+str(ipv6_next_header)+ ", tc="+str(ipv6_flow)+", fl="+str(ipv6_flow)+")/UDP(sport=" + str(udp_source_port) + ", dport=" +\
                                          str(udp_destination_port) + ")/DNS(rd=1, qd=DNSQR(qname='www.itb.ie')), iface='"+udp_interface+"', verbose=0)"
                    self.udpScapyCommandTextBrowser.setText(udp_command_text)  

            else:
                # IP Section
                # Source IP
                ip_source = self.ipSrcEdit.text()
                # Checks whether the format of source IP addresses is correct
                if not self.validate_ip_address(ip_source):
                    # Error message
                    QMessageBox.warning(self, "Warning", "IP source address seems incorrect!")
                    return False
                # Destination IP
                ip_destination = self.ipDstEdit.text()
                # Checks whether the format of destination IP addresses is correct
                if not self.validate_ip_address(ip_destination):
                    # Error message
                    QMessageBox.warning(self, "Warning", "IP destination address seems incorrect!")
                    return False
                # Checks whether IP flags are set
                # Default value is 0
                ip_flags = 0
                if self.ipReservedBitCheckBox.isChecked():
                    ip_flags += 4
                if self.ipDontFragmentCheckBox.isChecked():
                    ip_flags += 2
                if self.ipMoreFragmentsCheckBox.isChecked():
                    ip_flags += 1
                # Checks whether TTL value is set
                # Default value is 64
                ip_ttl = 64
                if self.ipTTLCheckBox.isChecked():
                    ip_ttl = self.ipTtlSpinBox.value()
                # Checks whether IP ID is set
                # Default value is 1
                ip_ip_id = 1
                if self.ipIDCheckBox.isChecked():
                    ip_ip_id = self.ipIDSpinBox.value()
                # Check whether IP Version is checked
                # Default value is 4
                ip_version = 4
                if self.ipVersionCheckBox.isChecked():
                    ip_version = self.ipVersionSpinBox.value()
                # Checks whether Fragmentation Offset is set
                # Default value is 0
                ip_frag_offset = 0
                if self.ipFragOffsetCheckBox.isChecked():
                    ip_frag_offset = self.ipFragOffsetSpinBox.value()
                # Checks whether Transport protocol is set
                # Default value is 6
                ip_tos = 0
                if self.ipTosCheckBox.isChecked():
                    ip_tos = self.ipTosSpinBox.value()
                # IP Protocol
                ip_protocol = 17 # default value
                if self.ipProtocolCheckBox.isChecked():
                    ip_protocol = self.ipProtocolSpinBox.value()    

                # Calls the udp_forward function
                if not self.udp_forward(mac_source, mac_destination, ip_source, ip_destination, ip_flags,
                                                ip_ttl, ip_ip_id, ip_version, ip_frag_offset, ip_tos, ip_protocol,
                                                udp_source_port, udp_destination_port, udp_interface):
                    QMessageBox.warning(self, "Warning", "Packet could not be sent")
                    self.mainStatusBar.showMessage("Packet could not be sent")

                else:
                    # When packet is sent successfully the appropriate window is displayed
                    QMessageBox.information(self, "Information", "Packet sent")
                    # When packet is sent successfully the appropriate message is in the status bar
                    self.mainStatusBar.showMessage("Packet sent successfully")
                    # Gets the current table row
                    current_row_count = self.udpTableWidget.rowCount()
                    # Populates table with packet details
                    self.udpTableWidget.insertRow(current_row_count)
                    self.udpTableWidget.setItem(current_row_count, 0, QTableWidgetItem(mac_source))
                    self.udpTableWidget.setItem(current_row_count, 1, QTableWidgetItem(mac_destination))
                    self.udpTableWidget.setItem(current_row_count, 2, QTableWidgetItem(ip_source))
                    self.udpTableWidget.setItem(current_row_count, 3, QTableWidgetItem(ip_destination))
                    self.udpTableWidget.setItem(current_row_count, 4, QTableWidgetItem(str(ip_flags)))
                    self.udpTableWidget.setItem(current_row_count, 5, QTableWidgetItem(str(ip_protocol)))
                    self.udpTableWidget.setItem(current_row_count, 6, QTableWidgetItem(str(ip_ttl)))
                    self.udpTableWidget.setItem(current_row_count, 7, QTableWidgetItem(str(ip_version)))
                    self.udpTableWidget.setItem(current_row_count, 8, QTableWidgetItem(str(ip_tos)))
                    self.udpTableWidget.setItem(current_row_count, 9, QTableWidgetItem(str(ip_ip_id)))
                    self.udpTableWidget.setItem(current_row_count, 10, QTableWidgetItem(str(ip_frag_offset)))
                    self.udpTableWidget.setItem(current_row_count, 11, QTableWidgetItem(str(udp_source_port)))
                    self.udpTableWidget.setItem(current_row_count, 12, QTableWidgetItem(str(udp_destination_port)))
                    self.udpTableWidget.setItem(current_row_count, 13, QTableWidgetItem(str(udp_interface)))
                    # Alignment of columns
                    for column in range(self.udpTableWidget.columnCount()):
                            self.udpTableWidget.item(current_row_count,column).setTextAlignment(Qt.AlignmentFlag.AlignCenter)
                    
                    # Populates Scapy command used field
                    udp_command_text = "sendp(Ether(src='" + str(mac_source) + "', dst='" + str(mac_destination) + \
                                          "')/IP(src='" + str(ip_source) + "', dst='" + str(ip_destination) + "', ttl=" + \
                                          str(ip_ttl) + ", flags=" + str(ip_flags) + ", id=" + str(ip_ip_id) + ", version=" + \
                                          str(ip_version) + ", frag=" + str(ip_frag_offset) + ", proto=" + str(ip_protocol) + \
                                          ", tos=" + str(ip_tos) + ")/UDP(sport=" + str(udp_source_port) + ", dport=" +\
                                          str(udp_destination_port) + ")/DNS(rd=1, qd=DNSQR(qname='www.itb.ie')), iface='"+udp_interface+"', verbose=0)"
                    self.udpScapyCommandTextBrowser.setText(udp_command_text)     
                
        # ICMP tab
        if current_tab == 6:

            # MAC Section
            # Source MAC address
            mac_source = self.etherMacSrcEdit.text()
            # Checks whether the format of source MAC address is correct
            if not self.validate_mac_address(mac_source):
                # Error message
                QMessageBox.warning(self, "Warning", "MAC source address seems incorrect!")
                return False
            # Destination MAC address
            mac_destination = self.etherMacDstEdit.text()
            # Checks whether the format of source MAC address is correct
            if not self.validate_mac_address(mac_destination):
                # Error message
                QMessageBox.warning(self, "Warning", "MAC destination address seems incorrect!")
                return False

            # ICMP tab
            if self.icmpTabWidget.currentIndex() == 0: 

                # IP Section
                # Source IP
                ip_source = self.ipSrcEdit.text()
                # Checks whether the format of source IP addresses is correct
                if not self.validate_ip_address(ip_source):
                    # Error message
                    QMessageBox.warning(self, "Warning", "IP source address seems incorrect!")
                    return False
                # Destination IP
                ip_destination = self.ipDstEdit.text()
                # Checks whether the format of destination IP addresses is correct
                if not self.validate_ip_address(ip_destination):
                    # Error message
                    QMessageBox.warning(self, "Warning", "IP destination address seems incorrect!")
                    return False

                # Checks whether IP flags are set
                # Default value is 0
                ip_flags = 0
                if self.ipReservedBitCheckBox.isChecked():
                    ip_flags += 4
                if self.ipDontFragmentCheckBox.isChecked():
                    ip_flags += 2
                if self.ipMoreFragmentsCheckBox.isChecked():
                    ip_flags += 1
                # Checks whether TTL value is set
                # Default value is 64
                ip_ttl = 64
                if self.ipTTLCheckBox.isChecked():
                    ip_ttl = self.ipTtlSpinBox.value()
                # Checks whether IP ID is set
                # Default value is 1
                ip_ip_id = 1
                if self.ipIDCheckBox.isChecked():
                    ip_ip_id = self.ipIDSpinBox.value()
                # Check whether IP Version is checked
                # Default value is 4
                ip_version = 4
                if self.ipVersionCheckBox.isChecked():
                    ip_version = self.ipVersionSpinBox.value()
                # Checks whether Fragmentation Offset is set
                # Default value is 0
                ip_frag_offset = 0
                if self.ipFragOffsetCheckBox.isChecked():
                    ip_frag_offset = self.ipFragOffsetSpinBox.value()
                # Checks whether Transport protocol is set
                # Default value is 6
                ip_tos = 0
                if self.ipTosCheckBox.isChecked():
                    ip_tos = self.ipTosSpinBox.value()
                # IP Protocol
                ip_protocol = 1 # default value
                if self.ipProtocolCheckBox.isChecked():
                    ip_protocol = self.ipProtocolSpinBox.value()

                # Echo Request Tab
                if self.icmpIPv4Tab.currentIndex() == 0:
                    
                    icmp_type = 8
                    icmp_code = 0
                    if self.icmpEchoRequestSetTypeCode.isChecked():
                        icmp_type = self.icmpEchoRequestTypeSpin.value()
                        icmp_code = self.icmpEchoRequestCodeSpin.value()
                    # Seq and ID
                    icmp_seq = 1
                    icmp_id = random.randrange(0, 65535)
                    if self.icmpEchoRequestSetIdSeq.isChecked():
                        icmp_seq = self.icmpEchoRequestSeqSpinBox.value()
                        icmp_id = self.icmpEchoRequestIDSpinBox.value()
                    # Payload
                    icmp_payload = ""
                    if not self.icmpEchoRequestPayloadSet.isChecked():
                        if self.icmpEchoRequestPayloadCombo.currentIndex() == 0:
                            # Linux default payload
                            icmp_payload = "!\"#$%&'()*+,-./01234567"
                        if self.icmpEchoRequestPayloadCombo.currentIndex() == 1:
                            # Windows default payload
                            icmp_payload = "abcdefghijklmnopqrstuvwabcdefghi"
                    else:
                        icmp_payload = str(self.icmpEchoRequestPayloadText.text())
                    # Network Interface
                    icmp_interface = str(self.interfaces_list[self.icmpEchoRequestInterface.currentIndex()])
                                             
                    # Calls the icmp_forward function
                    if not self.icmp_forward(mac_source, mac_destination, ip_source, ip_destination, ip_flags,
                                                        ip_ttl, ip_ip_id, ip_version, ip_frag_offset, ip_tos, ip_protocol,
                                                        icmp_type, icmp_code, icmp_seq, icmp_id, icmp_payload, icmp_interface):
                        QMessageBox.warning(self, "Warning", "Packet could not be sent")
                        self.mainStatusBar.showMessage("Packet could not be sent")
                    else:
                        # When packet is sent successfully the appropriate window is displayed
                        QMessageBox.information(self, "Warning", "Packet sent")
                        # When packet is sent successfully the appropriate message is in the status bar
                        self.mainStatusBar.showMessage("Packet sent successfully")
                        # Gets the current table row
                        current_row_count = self.icmpEchoRequestTable.rowCount()
                        # Populates table with packet details
                        self.icmpEchoRequestTable.insertRow(current_row_count)
                        self.icmpEchoRequestTable.setItem(current_row_count, 0, QTableWidgetItem(mac_source))
                        self.icmpEchoRequestTable.setItem(current_row_count, 1, QTableWidgetItem(mac_destination))
                        self.icmpEchoRequestTable.setItem(current_row_count, 2, QTableWidgetItem(ip_source))
                        self.icmpEchoRequestTable.setItem(current_row_count, 3, QTableWidgetItem(ip_destination))
                        self.icmpEchoRequestTable.setItem(current_row_count, 4, QTableWidgetItem(str(ip_flags)))
                        self.icmpEchoRequestTable.setItem(current_row_count, 5, QTableWidgetItem(str(ip_ttl)))
                        self.icmpEchoRequestTable.setItem(current_row_count, 6, QTableWidgetItem(str(ip_ip_id)))
                        self.icmpEchoRequestTable.setItem(current_row_count, 7, QTableWidgetItem(str(ip_version)))
                        self.icmpEchoRequestTable.setItem(current_row_count, 8, QTableWidgetItem(str(ip_frag_offset)))
                        self.icmpEchoRequestTable.setItem(current_row_count, 9, QTableWidgetItem(str(ip_tos)))
                        self.icmpEchoRequestTable.setItem(current_row_count, 10, QTableWidgetItem(str(ip_protocol)))
                        self.icmpEchoRequestTable.setItem(current_row_count, 11, QTableWidgetItem(str(icmp_type)))
                        self.icmpEchoRequestTable.setItem(current_row_count, 12, QTableWidgetItem(str(icmp_code)))
                        self.icmpEchoRequestTable.setItem(current_row_count, 13, QTableWidgetItem(str(icmp_seq)))
                        self.icmpEchoRequestTable.setItem(current_row_count, 14, QTableWidgetItem(str(icmp_id)))
                        self.icmpEchoRequestTable.setItem(current_row_count, 15, QTableWidgetItem(icmp_payload))
                        self.icmpEchoRequestTable.setItem(current_row_count, 16, QTableWidgetItem(icmp_interface))
                        # Alignment of columns
                        for column in range(self.icmpEchoRequestTable.columnCount()):
                            self.icmpEchoRequestTable.item(current_row_count,column).setTextAlignment(Qt.AlignmentFlag.AlignCenter)
                        
                        # Populates Scapy command used field
                        icmp_echo_request_command_text = "sendp(Ether(src='" + str(mac_source) + "', dst='" + str(mac_destination) + \
                                                  "')/IP(src='" + str(ip_source) + "', dst='" + str(ip_destination) + "', ttl=" + \
                                                  str(ip_ttl) + ", flags=" + str(ip_flags) + ", id=" + str(
                                    ip_ip_id) + ", version=" + \
                                                  str(ip_version) + ", frag=" + str(ip_frag_offset) + ", proto=" + str(ip_protocol) + \
                                                  ", tos=" + str(ip_tos) + ")/ICMP(type=" + str(icmp_type) + ", code=" + \
                                                  str(icmp_code) + ", id="+str(icmp_id)+", seq="+str(icmp_seq)+" )/'" + str(icmp_payload) + "', iface='"+icmp_interface+"', verbose=0)"
                        self.icmpEchoRequestScapyCommandTextBrowser.setText(icmp_echo_request_command_text)
                  
                # Echo Reply Tab
                if self.icmpIPv4Tab.currentIndex() == 1:

                    icmp_type = 0
                    icmp_code = 0
                    if self.icmpEchoReplySetTypeCode.isChecked():
                        icmp_type = self.icmpEchoReplyTypeSpin.value()
                        icmp_code = self.icmpEchoReplyCodeSpin.value()
                    # Seq and ID
                    icmp_seq = 1
                    icmp_id = random.randrange(0, 65535)
                    if self.icmpEchoReplySetIdSeq.isChecked():
                        icmp_seq = self.icmpEchoReplySeqSpinBox.value()
                        icmp_id = self.icmpEchoReplyIDSpinBox.value()
                    # Payload
                    icmp_payload = ""
                    if not self.icmpEchoReplyPayloadSet.isChecked():
                        if self.icmpEchoReplyPayloadCombo.currentIndex() == 0:
                            # Linux default payload
                            icmp_payload = "!\"#$%&'()*+,-./01234567"
                        if self.icmpEchoReplyPayloadCombo.currentIndex() == 1:
                            # Windows default payload
                            icmp_payload = "abcdefghijklmnopqrstuvwabcdefghi"
                    else:
                        icmp_payload = str(self.icmpEchoReplyPayloadText.text())
                    # Network Interface
                    icmp_interface = str(self.interfaces_list[self.icmpEchoReplyInterface.currentIndex()])
                                             
                    # Calls the icmp_forward function
                    if not self.icmp_forward(mac_source, mac_destination, ip_source, ip_destination, ip_flags,
                                                        ip_ttl, ip_ip_id, ip_version, ip_frag_offset, ip_tos, ip_protocol,
                                                        icmp_type, icmp_code, icmp_seq, icmp_id, icmp_payload, icmp_interface):
                        QMessageBox.warning(self, "Warning", "Packet could not be sent")
                        self.mainStatusBar.showMessage("Packet could not be sent")
                    else:
                        # When packet is sent successfully the appropriate window is displayed
                        QMessageBox.information(self, "Warning", "Packet sent")
                        # When packet is sent successfully the appropriate message is in the status bar
                        self.mainStatusBar.showMessage("Packet sent successfully")
                        # Gets the current table row
                        current_row_count = self.icmpEchoReplyTable.rowCount()
                        # Populates table with packet details
                        self.icmpEchoReplyTable.insertRow(current_row_count)
                        self.icmpEchoReplyTable.setItem(current_row_count, 0, QTableWidgetItem(mac_source))
                        self.icmpEchoReplyTable.setItem(current_row_count, 1, QTableWidgetItem(mac_destination))
                        self.icmpEchoReplyTable.setItem(current_row_count, 2, QTableWidgetItem(ip_source))
                        self.icmpEchoReplyTable.setItem(current_row_count, 3, QTableWidgetItem(ip_destination))
                        self.icmpEchoReplyTable.setItem(current_row_count, 4, QTableWidgetItem(str(ip_flags)))
                        self.icmpEchoReplyTable.setItem(current_row_count, 5, QTableWidgetItem(str(ip_ttl)))
                        self.icmpEchoReplyTable.setItem(current_row_count, 6, QTableWidgetItem(str(ip_ip_id)))
                        self.icmpEchoReplyTable.setItem(current_row_count, 7, QTableWidgetItem(str(ip_version)))
                        self.icmpEchoReplyTable.setItem(current_row_count, 8, QTableWidgetItem(str(ip_frag_offset)))
                        self.icmpEchoReplyTable.setItem(current_row_count, 9, QTableWidgetItem(str(ip_tos)))
                        self.icmpEchoReplyTable.setItem(current_row_count, 10, QTableWidgetItem(str(ip_protocol)))
                        self.icmpEchoReplyTable.setItem(current_row_count, 11, QTableWidgetItem(str(icmp_type)))
                        self.icmpEchoReplyTable.setItem(current_row_count, 12, QTableWidgetItem(str(icmp_code)))
                        self.icmpEchoReplyTable.setItem(current_row_count, 13, QTableWidgetItem(str(icmp_seq)))
                        self.icmpEchoReplyTable.setItem(current_row_count, 14, QTableWidgetItem(str(icmp_id)))
                        self.icmpEchoReplyTable.setItem(current_row_count, 15, QTableWidgetItem(icmp_payload))
                        self.icmpEchoReplyTable.setItem(current_row_count, 16, QTableWidgetItem(icmp_interface))
                        # Alignment of columns
                        for column in range(self.icmpEchoReplyTable.columnCount()):
                            self.icmpEchoReplyTable.item(current_row_count,column).setTextAlignment(Qt.AlignmentFlag.AlignCenter)
                        
                        # Populates Scapy command used field
                        icmp_echo_reply_command_text = "sendp(Ether(src='" + str(mac_source) + "', dst='" + str(mac_destination) + \
                                                  "')/IP(src='" + str(ip_source) + "', dst='" + str(ip_destination) + "', ttl=" + \
                                                  str(ip_ttl) + ", flags=" + str(ip_flags) + ", id=" + str(
                                    ip_ip_id) + ", version=" + \
                                                  str(ip_version) + ", frag=" + str(ip_frag_offset) + ", proto=" + str(ip_protocol) + \
                                                  ", tos=" + str(ip_tos) + ")/ICMP(type=" + str(icmp_type) + ", code=" + \
                                                  str(icmp_code) + ", id="+str(icmp_id)+", seq="+str(icmp_seq)+" )/'" + str(icmp_payload) + "', iface='"+icmp_interface+"', verbose=0)"
                        self.icmpEchoReplyScapyCommandTextBrowser.setText(icmp_echo_reply_command_text)

            # ICMPv6 tab
            if self.icmpTabWidget.currentIndex() == 1: 

                # IPv6 Section
                # Source IPv6
                ipv6_source = self.ipv6SrcIpAddr.text()
                # Checks whether the format of source IPv6 addresses is correct
                if not self.validate_ipv6_address(ipv6_source):
                    # Error message
                    QMessageBox.warning(self, "Warning", "Source IPv6 address seems incorrect!")
                    return False
                ipv6_destination = self.ipv6DstIpAddr.text()
                # Checks whether the format of destination IPv6 addresses is correct
                if not self.validate_ipv6_address(ipv6_destination):
                    # Error message
                    QMessageBox.warning(self, "Warning", "Destination IPv6 address seems incorrect!")
                    return False
                
                # Next layer protocol
                ipv6_next_header = 58 # default for ICMPv6
                if self.ipv6NextHeaderCheckBox.isChecked():
                    ipv6_next_header = self.ipv6NextHeaderSpinBox.value()
                # Hop limit
                ipv6_hop_limit = 64 # default 64
                if self.ipv6HopLimitCheckBox.isChecked():
                    ipv6_hop_limit = self.ipv6HopLimitSpinBox.value()
                # IP Version
                ipv6_version = 6 # default value
                if self.ipv6VersionCheckBox.isChecked():
                    ipv6_version = self.ipv6VersionSpinBox.value()
                # IPv6 ToS
                ipv6_tos = 0 # default value
                if self.ipv6TosCheckBox.isChecked():
                    ipv6_tos = self.ipv6TospinBox.value()
                # IPv6 Flow
                ipv6_flow = 0 # default value
                if self.ipv6FlowLabelCheckBox.isChecked():
                    ipv6_flow = self.ipv6FlowLabelSpinBox.value()
                # ICMPv6 Echo Request
                if self.icmpIPv6Tab.currentIndex() == 0:

                    # Type and Code
                    icmpv6_type = 128
                    icmpv6_code = 0
                    if self.icmpv6EchoRequestSetTypeCode.isChecked():
                        icmpv6_type = self.icmpv6EchoRequestType.value()
                        icmpv6_code = self.icmpv6EchoRequestCode.value()
                    # Seq and ID
                    icmpv6_seq = 1
                    icmpv6_id = random.randrange(0, 65535)
                    if self.icmpv6EchoRequestSetIdSeq.isChecked():
                        icmpv6_seq = self.icmpv6EchoRequestSeqSpinBox.value()
                        icmpv6_id = self.icmpv6EchoRequestIDSpinBox.value()
                    # Payload
                    icmpv6_payload = ""
                    if not self.icmpv6EchoRequestPayloadSet.isChecked():
                        if self.icmpv6PayloadComboBox.currentIndex() == 0:
                            # Linux default payload
                            icmpv6_payload = "!\"#$%&'()*+,-./01234567"
                        if self.icmpv6PayloadComboBox.currentIndex() == 1:
                            # Windows default payload
                            icmpv6_payload = "abcdefghijklmnopqrstuvwabcdefghi"
                    else:
                        icmpv6_payload = self.icmpv6EchoRequestPayloadEdit.text()
                    #Network Interface
                    icmpv6_interface = str(self.interfaces_list[self.icmpv6EchoRequestInterace.currentIndex()])

                    # Calls the icmpv6_forward function
                    if not self.icmpv6_forward(mac_source, mac_destination, ipv6_source, ipv6_destination, ipv6_next_header, ipv6_version, ipv6_hop_limit, ipv6_tos, ipv6_flow, icmpv6_type, icmpv6_code, icmpv6_id, icmpv6_seq, icmpv6_payload,icmpv6_interface):
                        QMessageBox.warning(self, "Warning", "Packet could not be sent")
                        self.mainStatusBar.showMessage("Packet could not be sent")
                    else:
                        # When packet is sent successfully the appropriate window is displayed
                        QMessageBox.information(self, "Information", "Packet sent")
                        # When packet is sent successfully the appropriate message is in the status bar
                        self.mainStatusBar.showMessage("Packet sent successfully")
                        # Current table row
                        current_row_count = self.icmpv6EchoRequestTable.rowCount()
                        # Populates table with packet details
                        self.icmpv6EchoRequestTable.insertRow(current_row_count)
                        self.icmpv6EchoRequestTable.setItem(current_row_count, 0, QTableWidgetItem(mac_source))
                        self.icmpv6EchoRequestTable.setItem(current_row_count, 1, QTableWidgetItem(mac_destination))
                        self.icmpv6EchoRequestTable.setItem(current_row_count, 2, QTableWidgetItem(ipv6_source))
                        self.icmpv6EchoRequestTable.setItem(current_row_count, 3, QTableWidgetItem(ipv6_destination))
                        self.icmpv6EchoRequestTable.setItem(current_row_count, 4, QTableWidgetItem(str(ipv6_next_header)))
                        self.icmpv6EchoRequestTable.setItem(current_row_count, 5, QTableWidgetItem(str(ipv6_version)))
                        self.icmpv6EchoRequestTable.setItem(current_row_count, 6, QTableWidgetItem(str(ipv6_hop_limit)))
                        self.icmpv6EchoRequestTable.setItem(current_row_count, 7, QTableWidgetItem(str(ipv6_tos)))
                        self.icmpv6EchoRequestTable.setItem(current_row_count, 8, QTableWidgetItem(str(ipv6_flow)))
                        self.icmpv6EchoRequestTable.setItem(current_row_count, 9, QTableWidgetItem(str(icmpv6_type)))
                        self.icmpv6EchoRequestTable.setItem(current_row_count, 10, QTableWidgetItem(str(icmpv6_code)))
                        self.icmpv6EchoRequestTable.setItem(current_row_count, 11, QTableWidgetItem(str(icmpv6_id)))
                        self.icmpv6EchoRequestTable.setItem(current_row_count, 12, QTableWidgetItem(str(icmpv6_seq)))
                        self.icmpv6EchoRequestTable.setItem(current_row_count, 13, QTableWidgetItem(icmpv6_payload))
                        self.icmpv6EchoRequestTable.setItem(current_row_count, 14, QTableWidgetItem(icmpv6_interface))
                        # Alignment of columns
                        for column in range(self.icmpv6EchoRequestTable.columnCount()):
                            self.icmpv6EchoRequestTable.item(current_row_count,column).setTextAlignment(Qt.AlignmentFlag.AlignCenter)

                        # Populates Scapy command field
                        icmpv6_echo_request = "sendp(Ether(src='"+str(mac_source)+"', dst='"+str(mac_destination)+\
                                              "')/IPv6(ip='"+str(ipv6_source)+"', dst='"+str(ipv6_destination)+"', hlim=" +\
                                              str(ipv6_hop_limit)+ ", version="+str(ipv6_version)+", nh="+str(ipv6_next_header)+ ", tc="+str(ipv6_tos)+", fl="+str(ipv6_flow)+")/ICMPv6EchoRequest(type=" + str(icmpv6_type) + ", code=" +\
                                          str(icmpv6_code) + ", id="+str(icmpv6_id)+", seq="+str(icmpv6_seq)+", data='"+icmpv6_payload+"''), iface='"+icmpv6_interface+"', verbose=0)"                      
                        self.icmpv6EchoRequestScapyCommand.setText(icmpv6_echo_request)

                # ICMPv6 Echo Reply
                if self.icmpIPv6Tab.currentIndex() == 1:

                    # Type and Code
                    icmpv6_type = 129
                    icmpv6_code = 0
                    if self.icmpv6EchoReplySetTypeCode.isChecked():
                        icmpv6_type = self.icmpv6EchoReplyType.value()
                        icmpv6_code = self.icmpv6EchoReplyCode.value()

                    # Seq and ID
                    icmpv6_seq = 1
                    icmpv6_id = random.randrange(0, 65535)
                    if self.icmpv6EchoReplySetIdSeq.isChecked():
                        icmpv6_seq = self.icmpv6EchoReplySeqSpinBox.value()
                        icmpv6_id = self.icmpv6EchoReplyIDSpinBox.value()

                    # Payload
                    icmpv6_payload = ""
                    if not self.icmpv6EchoReplyPayloadSet.isChecked():
                        if self.icmpv6EchoReplyPayloadComboBox.currentIndex() == 0:
                            # Linux default payload
                            icmpv6_payload = "!\"#$%&'()*+,-./01234567"
                        if self.icmpv6EchoReplyPayloadComboBox.currentIndex() == 1:
                            # Windows default payload
                            icmpv6_payload = "abcdefghijklmnopqrstuvwabcdefghi"
                    else:
                        icmpv6_payload = self.icmpv6EchoReplyPayloadEdit.text()

                    icmpv6_interface = str(self.interfaces_list[self.icmpv6EchoReplyInterace.currentIndex()])

                    # Calls the icmpv6_forward
                    if not self.icmpv6_forward(mac_source, mac_destination, ipv6_source, ipv6_destination, ipv6_next_header, ipv6_version, ipv6_hop_limit, ipv6_tos, ipv6_flow, icmpv6_type, icmpv6_code, icmpv6_id, icmpv6_seq, icmpv6_payload,icmpv6_interface):
                        QMessageBox.warning(self, "Warning", "Packet could not be sent")
                        self.mainStatusBar.showMessage("Packet could not be sent")
                    else:
                        # When packet is sent successfully the appropriate window is displayed
                        QMessageBox.information(self, "Information", "Packet sent")
                        # When packet is sent successfully the appropriate message is in the status bar
                        self.mainStatusBar.showMessage("Packet sent successfully")
                        # Current table row
                        current_row_count = self.icmpv6EchoReplyTable.rowCount()
                        # Populates table with packet details
                        self.icmpv6EchoReplyTable.insertRow(current_row_count)
                        self.icmpv6EchoReplyTable.setItem(current_row_count, 0, QTableWidgetItem(mac_source))
                        self.icmpv6EchoReplyTable.setItem(current_row_count, 1, QTableWidgetItem(mac_destination))
                        self.icmpv6EchoReplyTable.setItem(current_row_count, 2, QTableWidgetItem(ipv6_source))
                        self.icmpv6EchoReplyTable.setItem(current_row_count, 3, QTableWidgetItem(ipv6_destination))
                        self.icmpv6EchoReplyTable.setItem(current_row_count, 4, QTableWidgetItem(str(ipv6_next_header)))
                        self.icmpv6EchoReplyTable.setItem(current_row_count, 5, QTableWidgetItem(str(ipv6_version)))
                        self.icmpv6EchoReplyTable.setItem(current_row_count, 6, QTableWidgetItem(str(ipv6_hop_limit)))
                        self.icmpv6EchoReplyTable.setItem(current_row_count, 7, QTableWidgetItem(str(ipv6_tos)))
                        self.icmpv6EchoReplyTable.setItem(current_row_count, 8, QTableWidgetItem(str(ipv6_flow)))
                        self.icmpv6EchoReplyTable.setItem(current_row_count, 9, QTableWidgetItem(str(icmpv6_type)))
                        self.icmpv6EchoReplyTable.setItem(current_row_count, 10, QTableWidgetItem(str(icmpv6_code)))
                        self.icmpv6EchoReplyTable.setItem(current_row_count, 11, QTableWidgetItem(str(icmpv6_id)))
                        self.icmpv6EchoReplyTable.setItem(current_row_count, 12, QTableWidgetItem(str(icmpv6_seq)))
                        self.icmpv6EchoReplyTable.setItem(current_row_count, 13, QTableWidgetItem(icmpv6_payload))
                        self.icmpv6EchoReplyTable.setItem(current_row_count, 14, QTableWidgetItem(icmpv6_interface))
                        # Alignment of columns
                        for column in range(self.icmpv6EchoReplyTable.columnCount()):
                            self.icmpv6EchoReplyTable.item(current_row_count,column).setTextAlignment(Qt.AlignmentFlag.AlignCenter)

                        # Populates Scapy command field
                        icmpv6_echo_reply = "sendp(Ether(src='"+str(mac_source)+"', dst='"+str(mac_destination)+\
                                              "')/IPv6(src='"+str(ipv6_source)+"', dst='"+str(ipv6_destination)+"', hlim=" +\
                                              str(ipv6_hop_limit)+ ", version="+str(ipv6_version)+", nh="+str(ipv6_next_header)+", tc="+str(ipv6_tos)+", fl="+str(ipv6_flow)+")/ICMPv6EchoReply(type=" + str(icmpv6_type) + ", code=" +\
                                          str(icmpv6_code) + ", id="+str(icmpv6_id)+", seq="+str(icmpv6_seq)+", data='"+icmpv6_payload+"''), iface='"+icmpv6_interface+"', verbose=0)"                      
                        self.icmpv6EchoReplyScapyCommand.setText(icmpv6_echo_reply)


        # DNS TAB
        if current_tab == 7:

            # MAC Section
            # Source MAC address
            mac_source = self.etherMacSrcEdit.text()
            # Checks whether the format of source MAC address is correct
            if not self.validate_mac_address(mac_source):
                # Error message
                QMessageBox.warning(self, "Warning", "MAC source address seems incorrect!")
                return False
            # Destination MAC address
            mac_destination = self.etherMacDstEdit.text()
            # Checks whether the format of destination MAC address is correct
            if not self.validate_mac_address(mac_destination):
                # Error message
                QMessageBox.warning(self, "Warning", "MAC destination address seems incorrect!")
                return False

            # UDP section
            udp_source_port = self.udpSrcPortSpin.value()
            udp_destination_port = self.udpDstPortSpin.value()

            # Query Tab
            if self.dnsTabWidget.currentIndex() == 0:

                # DNS section
                query_name = self.dnsQueryText.text()
                if self.dnsQueryNameTextSet.isChecked():
                    query_name = self.dnsQueryText.text()
                dns_query_type = ""
                if self.dnsQueryTypeComboBox.currentIndex() == 0:
                    dns_query_type = "A"
                if self.dnsQueryTypeComboBox.currentIndex() == 1:
                    dns_query_type = "AAAA"
                if self.dnsQueryTypeComboBox.currentIndex() == 2:
                    dns_query_type = "NS"
                if self.dnsQueryTypeComboBox.currentIndex() == 3:
                    dns_query_type = "CNAME"
                if self.dnsQueryTypeComboBox.currentIndex() == 4:
                    dns_query_type = "MX"
                if self.dnsQueryTypeComboBox.currentIndex() == 5:
                    dns_query_type = "PTR"
                # Query ID
                query_id = 0
                if self.dnsQueryIdSet.isChecked():
                    query_id = self.dnsQueryIdSpinBox.value()
                # Query QR
                query_qr = 0 # Default value for queries
                if self.dnsQueryQrSet.isChecked():
                    query_qr = 1
                # Queyr RD
                query_rd = 1 # Recursion is enabled
                if not self.dnsQueryRdSet.isChecked():
                    query_rd = 0 # Recursion is disabled
                # Interface
                dns_query_interface = str(self.interfaces_list[self.dnsQueryInterface.currentIndex()])

                # IP and IPv6 Section
                if self.dnsQueryUseIPv6radioButton.isChecked():

                    # IPv6 Section
                    # Source IPv6
                    ipv6_source = self.ipv6SrcIpAddr.text()
                    # Checks whether the format of source IPv6 addresses is correct
                    if not self.validate_ipv6_address(ipv6_source):
                        # Error message
                        QMessageBox.warning(self, "Warning", "Source IPv6 address seems incorrect!")
                        return False
                    ipv6_destination = self.ipv6DstIpAddr.text()
                    # Checks whether the format of destination IPv6 addresses is correct
                    if not self.validate_ipv6_address(ipv6_destination):
                        # Error message
                        QMessageBox.warning(self, "Warning", "Destination IPv6 address seems incorrect!")
                        return False
                    # Next layer protocol
                    ipv6_next_header = 17 # default UDP
                    if self.ipv6NextHeaderCheckBox.isChecked():
                        ipv6_next_header = self.ipv6NextHeaderSpinBox.value()
                    # Hop Count
                    ipv6_hop_limit = 64 # default 64
                    if self.ipv6HopLimitCheckBox.isChecked():
                        ipv6_hop_limit = self.ipv6HopLimitSpinBox.value()
                    # IP Version
                    ipv6_version = 6 # default value
                    if self.ipv6VersionCheckBox.isChecked():
                        ipv6_version = self.ipv6VersionSpinBox.value()
                    # IPv6 ToS
                    ipv6_tos = 0 # default value
                    if self.ipv6TosCheckBox.isChecked():
                        ipv6_tos = self.ipv6TospinBox.value()
                    # IPv6 Flow
                    ipv6_flow = 0 # default value
                    if self.ipv6FlowLabelCheckBox.isChecked():
                        ipv6_flow = self.ipv6FlowLabelSpinBox.value()
                    # DNS Query 
                    if not self.dns_query_ipv6_forward(mac_source,mac_destination,ipv6_source,ipv6_destination,ipv6_next_header,ipv6_version,ipv6_hop_limit,ipv6_tos,ipv6_flow,udp_source_port,udp_destination_port,query_name,dns_query_type,query_id,query_qr,query_rd,dns_query_interface):
                        QMessageBox.warning(self, "Warning", "Packet could not be sent")
                        self.mainStatusBar.showMessage("Packet could not be sent")
                    else:
                        # When packet is sent successfully the appropriate window is displayed
                        QMessageBox.information(self, "Information", "Packet sent")
                        # When packet is sent successfully the appropriate message is in the status bar
                        self.mainStatusBar.showMessage("Packet sent successfully")
                        # Current table row
                        current_row_count = self.dnsQueryIPv6Table.rowCount()
                        # Populates table with packet details
                        self.dnsQueryIPv6Table.insertRow(current_row_count)
                        self.dnsQueryIPv6Table.setItem(current_row_count, 0, QTableWidgetItem(mac_source))
                        self.dnsQueryIPv6Table.setItem(current_row_count, 1, QTableWidgetItem(mac_destination))
                        self.dnsQueryIPv6Table.setItem(current_row_count, 2, QTableWidgetItem(ipv6_source))
                        self.dnsQueryIPv6Table.setItem(current_row_count, 3, QTableWidgetItem(ipv6_destination))
                        self.dnsQueryIPv6Table.setItem(current_row_count, 4, QTableWidgetItem(str(ipv6_next_header)))
                        self.dnsQueryIPv6Table.setItem(current_row_count, 5, QTableWidgetItem(str(ipv6_hop_limit)))
                        self.dnsQueryIPv6Table.setItem(current_row_count, 6, QTableWidgetItem(str(ipv6_version)))
                        self.dnsQueryIPv6Table.setItem(current_row_count, 7, QTableWidgetItem(str(ipv6_tos)))
                        self.dnsQueryIPv6Table.setItem(current_row_count, 8, QTableWidgetItem(str(ipv6_flow)))
                        self.dnsQueryIPv6Table.setItem(current_row_count, 9, QTableWidgetItem(str(udp_source_port)))
                        self.dnsQueryIPv6Table.setItem(current_row_count, 10, QTableWidgetItem(str(udp_destination_port)))
                        self.dnsQueryIPv6Table.setItem(current_row_count, 11, QTableWidgetItem(str(query_id)))
                        self.dnsQueryIPv6Table.setItem(current_row_count, 12, QTableWidgetItem(str(query_qr)))
                        self.dnsQueryIPv6Table.setItem(current_row_count, 13, QTableWidgetItem(str(query_rd)))
                        self.dnsQueryIPv6Table.setItem(current_row_count, 14, QTableWidgetItem(query_name))
                        self.dnsQueryIPv6Table.setItem(current_row_count, 15, QTableWidgetItem(str(dns_query_type)))
                        self.dnsQueryIPv6Table.setItem(current_row_count, 16, QTableWidgetItem(dns_query_interface))
                        # Alignment of columns
                        for column in range(self.dnsQueryIPv6Table.columnCount()):
                            self.dnsQueryIPv6Table.item(current_row_count,column).setTextAlignment(Qt.AlignmentFlag.AlignCenter)

                        # Populates Scapy command used field
                        dns_query_command_text = "sendp(Ether(src='"+str(mac_source)+"', dst='"+str(mac_destination)+\
                                              "')/IPv6(src='"+str(ipv6_source)+"', dst='"+str(ipv6_destination)+"', hlim=" +\
                                              str(ipv6_hop_limit)+ ", version="+str(ipv6_version)+", nh="+str(ipv6_next_header)+", tc="+str(ipv6_tos)+",fl="+str(ipv6_flow)+")/UDP(sport=" + str(udp_source_port) + ", dport=" +\
                                          str(udp_destination_port) + ")/DNS(id="+str(query_id)+",rd="+str(query_rd)+", qr="+str(query_qr)+", qd=DNSQR(qname='"+query_name+"', qtype='"+dns_query_type+"')), iface='"+dns_query_interface+"', verbose=0)"
                        self.dnsQueryScapyCommandTextBrowser.setText(dns_query_command_text)

                else:

                    # IP Section
                    # Source IP
                    ip_source = self.ipSrcEdit.text()
                    # Checks whether the format of source IP addresses is correct
                    if not self.validate_ip_address(ip_source):
                        # Error message
                        QMessageBox.warning(self, "Warning", "IP source address seems incorrect!")
                        return False
                    # Destination IP
                    ip_destination = self.ipDstEdit.text()
                    # Checks whether the format of destination IP addresses is correct
                    if not self.validate_ip_address(ip_destination):
                        # Error message
                        QMessageBox.warning(self, "Warning", "IP destination address seems incorrect!")
                        return False

                    # Checks whether IP flags are set
                    # Default value is 0
                    ip_flags = 0
                    if self.ipReservedBitCheckBox.isChecked():
                        ip_flags += 4
                    if self.ipDontFragmentCheckBox.isChecked():
                        ip_flags += 2
                    if self.ipMoreFragmentsCheckBox.isChecked():
                        ip_flags += 1
                    # Checks whether TTL value is set
                    # Default value is 64
                    ip_ttl = 64
                    if self.ipTTLCheckBox.isChecked():
                        ip_ttl = self.ipTtlSpinBox.value()
                    # Checks whether IP ID is set
                    # Default value is 1
                    ip_ip_id = 1
                    if self.ipIDCheckBox.isChecked():
                        ip_ip_id = self.ipIDSpinBox.value()
                    # Check whether IP Version is checked
                    # Default value is 4
                    ip_version = 4
                    if self.ipVersionCheckBox.isChecked():
                        ip_version = self.ipVersionSpinBox.value()
                    # Checks whether Fragmentation Offset is set
                    # Default value is 0
                    ip_frag_offset = 0
                    if self.ipFragOffsetCheckBox.isChecked():
                        ip_frag_offset = self.ipFragOffsetSpinBox.value()
                    # Checks whether Transport protocol is set
                    # Default value is 6
                    ip_tos = 0
                    if self.ipTosCheckBox.isChecked():
                        ip_tos = self.ipTosSpinBox.value()
                    # IP Protocol
                    ip_protocol = 17 # default UDP
                    if self.ipProtocolCheckBox.isChecked():
                        ip_protocol = self.ipProtocolSpinBox.value()

                    if not self.dns_query_ipv4_forward(mac_source,mac_destination,ip_source,ip_destination,ip_flags,ip_ttl,ip_ip_id,ip_version,ip_frag_offset,ip_tos,ip_protocol,
                        udp_source_port,udp_destination_port,query_name,dns_query_type,query_id,query_qr,query_rd,dns_query_interface):

                        QMessageBox.warning(self, "Warning", "Packet could not be sent")
                        self.mainStatusBar.showMessage("Packet could not be sent")
                    else:
                        # When packet is sent successfully the appropriate window is displayed
                        QMessageBox.information(self, "Information", "Packet sent")
                        # When packet is sent successfully the appropriate message is in the status bar
                        self.mainStatusBar.showMessage("Packet sent successfully")
                    
                        # Current table row
                        current_row_count = self.dnsQueryTable.rowCount()
                        # Populates table with packet details
                        self.dnsQueryTable.insertRow(current_row_count)
                        self.dnsQueryTable.setItem(current_row_count, 0, QTableWidgetItem(mac_source))
                        self.dnsQueryTable.setItem(current_row_count, 1, QTableWidgetItem(mac_destination))
                        self.dnsQueryTable.setItem(current_row_count, 2, QTableWidgetItem(ip_source))
                        self.dnsQueryTable.setItem(current_row_count, 3, QTableWidgetItem(ip_destination))
                        self.dnsQueryTable.setItem(current_row_count, 4, QTableWidgetItem(str(ip_flags)))
                        self.dnsQueryTable.setItem(current_row_count, 5, QTableWidgetItem(str(ip_ttl)))
                        self.dnsQueryTable.setItem(current_row_count, 6, QTableWidgetItem(str(ip_ip_id)))
                        self.dnsQueryTable.setItem(current_row_count, 7, QTableWidgetItem(str(ip_version)))
                        self.dnsQueryTable.setItem(current_row_count, 8, QTableWidgetItem(str(ip_frag_offset)))
                        self.dnsQueryTable.setItem(current_row_count, 9, QTableWidgetItem(str(ip_tos)))
                        self.dnsQueryTable.setItem(current_row_count, 10, QTableWidgetItem(str(ip_protocol)))
                        self.dnsQueryTable.setItem(current_row_count, 11, QTableWidgetItem(str(udp_source_port)))
                        self.dnsQueryTable.setItem(current_row_count, 12, QTableWidgetItem(str(udp_destination_port)))
                        self.dnsQueryTable.setItem(current_row_count, 13, QTableWidgetItem(str(query_id)))
                        self.dnsQueryTable.setItem(current_row_count, 14, QTableWidgetItem(str(query_qr)))
                        self.dnsQueryTable.setItem(current_row_count, 15, QTableWidgetItem(str(query_rd)))
                        self.dnsQueryTable.setItem(current_row_count, 16, QTableWidgetItem(query_name))
                        self.dnsQueryTable.setItem(current_row_count, 17, QTableWidgetItem(str(dns_query_type)))
                        self.dnsQueryTable.setItem(current_row_count, 18, QTableWidgetItem(dns_query_interface))
                        # Alignment of columns
                        for column in range(self.dnsQueryTable.columnCount()):
                            self.dnsQueryTable.item(current_row_count,column).setTextAlignment(Qt.AlignmentFlag.AlignCenter)
                
                        # Populates Scapy command used field
                        dns_query_command_text = "sendp(Ether(src='"+str(mac_source)+"', dst='"+str(mac_destination)+"')/IP(src='"+str(ip_source)+"', dst='"+str(ip_destination)+"', ttl="+str(ip_ttl)+",flags="+str(ip_flags)+", id="+str(ip_ip_id)+", version="+str(ip_version)+", frag="+str(ip_frag_offset)+", proto="+str(ip_protocol)+", tos="+str(ip_tos)+")/UDP(sport="+str(udp_source_port)+", dport="+str(udp_destination_port)+")/DNS(id="+str(query_id)+",rd="+str(query_rd)+", qr="+str(query_qr)+", qd=DNSQR(qname='"+query_name+"', qtype='"+dns_query_type+"')), iface='"+dns_query_interface+"', verbose=0)"
                        self.dnsQueryScapyCommandTextBrowser.setText(dns_query_command_text)
                  
            # Response Tab
            if self.dnsTabWidget.currentIndex() == 1:

                # DNS Response TTL
                dns_response_ttl = self.dnsResponseTTL.value()
                # DNS Response Type
                if self.dnsResponseTypeComboBox.currentIndex() == 0:
                    dns_response_type = "A"
                if self.dnsResponseTypeComboBox.currentIndex() == 1:
                    dns_response_type = "AAAA"
                if self.dnsResponseTypeComboBox.currentIndex() == 2:
                    dns_response_type = "NS"
                if self.dnsResponseTypeComboBox.currentIndex() == 3:
                    dns_response_type = "CNAME"
                if self.dnsResponseTypeComboBox.currentIndex() == 4:
                    dns_response_type = "MX"
                if self.dnsResponseTypeComboBox.currentIndex() == 5:
                    dns_response_type = "PTR"
                # Response ID
                response_id = 0
                if self.dnsResponseIdSet.isChecked():
                    response_id = self.dnsResponseIdText.text()

                    if not self.validate_dns_transaction_id(response_id):
                        # Error message
                        QMessageBox.warning(self, "Warning", "Transaction ID seems incorrect!")
                        return False
                    response_id = int(response_id, 16)
                # Response QR
                response_qr = 1 # Default value for answer
                if not self.dnsResponseQrSet.isChecked():
                    response_qr = 0
                # Response RD
                response_rd = 1 # Recursion is enabled
                if not self.dnsResponseRdSet.isChecked():
                    response_rd = 0 # Recursion is disabled
                # Response RA
                response_ra = 1 # Recursion available
                if not self.dnsResponseRaSet.isChecked():
                    response_ra = 0
                # Response AA
                response_aa = 1 # Authoritative
                if not self.dnsResponseAaSet.isChecked():
                    response_aa = 0
                # Domain name query
                dns_response_query = ""
                # DNS Response IP
                dns_response_answer = ""
                if dns_response_type == "A":
                    dns_response_answer = "193.1.36.24"
                    if self.dnsResponseIPSet.isChecked():
                        dns_response_answer = str(self.dnsResponseIPText.text())
                        # Checks whether the format DNS Response Type A IP address is correct
                        if not self.validate_ip_address(dns_response_answer):
                            # Error message
                            QMessageBox.warning(self, "Warning", "DNS Response Type A IP address seems incorrect!")
                            return False
                    dns_response_query = "www.itb.ie."
                    if self.dnsResponseNameTextSet.isChecked():
                        dns_response_query = str(self.dnsResponseText.text())

                if dns_response_type == "AAAA":
                    dns_response_answer = "2001::3"
                    if self.dnsResponseIPSet.isChecked():
                        dns_response_answer = str(self.dnsResponseIPText.text())
                        # Checks whether the format of DNS Response Type AAAA IPv6 addresses is correct
                        if not self.validate_ipv6_address(dns_response_answer):
                            # Error message
                            QMessageBox.warning(self, "Warning", "DNS Response Type AAAA IPv6 address seems incorrect!")
                            return False
                    dns_response_query = "www.itb.ie."
                    if self.dnsResponseNameTextSet.isChecked():
                        dns_response_query = str(self.dnsResponseText.text())

                if dns_response_type == "NS":
                    dns_response_answer = "hss-dns-01.heanet.ie."
                    if self.dnsResponseIPSet.isChecked():
                        dns_response_answer = str(self.dnsResponseIPText.text())
                        if len(dns_response_answer) == 0:
                            # Error message
                            QMessageBox.warning(self, "Warning", "DNS Responce Type NS can't be empty!")
                            return False
                    dns_response_query = "itb.ie."
                    if self.dnsResponseNameTextSet.isChecked():
                        dns_response_query = str(self.dnsResponseText.text())

                if dns_response_type == "CNAME":
                    dns_response_answer = "itbdns01.itb.ie. administrator.itb.ie."
                    if self.dnsResponseIPSet.isChecked():
                        dns_response_answer = str(self.dnsResponseIPText.text())
                        if len(dns_response_answer) == 0:
                            # Error message
                            QMessageBox.warning(self, "Warning", "DNS Responce Type CNAME can't be empty!")
                            return False
                    dns_response_query = "itb.ie."
                    if self.dnsResponseNameTextSet.isChecked():
                        dns_response_query = str(self.dnsResponseText.text())

                if dns_response_type == "MX":
                    dns_response_answer = "10 itb-ie.mail.protection.outlook.com."
                    if self.dnsResponseIPSet.isChecked():
                        dns_response_answer = str(self.dnsResponseIPText.text())
                        if len(dns_response_answer) == 0:
                            # Error message
                            QMessageBox.warning(self, "Warning", "DNS Responce Type MX can't be empty!")
                            return False
                    dns_response_query = "itb.ie."
                    if self.dnsResponseNameTextSet.isChecked():
                        dns_response_query = str(self.dnsResponseText.text())

                if dns_response_type == "PTR":
                    dns_response_answer = "www.itb.ie."
                    if self.dnsResponseIPSet.isChecked():
                        dns_response_answer = str(self.dnsResponseIPText.text())
                        if len(dns_response_answer) == 0:
                            # Error message
                            QMessageBox.warning(self, "Warning", "DNS Responce Type PTR can't be empty!")
                            return False
                    dns_response_query = "24.36.1.193.in-addr.arpa."
                    if self.dnsResponseNameTextSet.isChecked():
                        dns_response_query = str(self.dnsResponseText.text())

                # Interface
                dns_response_interface = str(self.interfaces_list[self.dnsResponseInterface.currentIndex()])
                
                # IP and IPv6 Section
                if self.dnsResponseUseIPv6radioButton.isChecked():

                    # IPv6 Section
                    # Source IPv6
                    ipv6_source = self.ipv6SrcIpAddr.text()
                    if not self.validate_ipv6_address(ipv6_source):
                        # Error message
                        QMessageBox.warning(self, "Warning", "Source IPv6 address seems incorrect!")
                        return False
                    ipv6_destination = self.ipv6DstIpAddr.text()
                    if not self.validate_ipv6_address(ipv6_destination):
                        # Error message
                        QMessageBox.warning(self, "Warning", "Destination IPv6 address seems incorrect!")
                        return False
                    
                    # Next layer protocol
                    ipv6_next_header = 17 # default UDP
                    if self.ipv6NextHeaderCheckBox.isChecked():
                        ipv6_next_header = self.ipv6NextHeaderSpinBox.value()
                    # Hop Count
                    ipv6_hop_limit = 64 # default 64
                    if self.ipv6HopLimitCheckBox.isChecked():
                        ipv6_hop_limit = self.ipv6HopLimitSpinBox.value()
                    # IP Version
                    ipv6_version = 6 # default value
                    if self.ipv6VersionCheckBox.isChecked():
                        ipv6_version = self.ipv6VersionSpinBox.value()
                    # IPv6 ToS
                    ipv6_tos = 0 # default value
                    if self.ipv6TosCheckBox.isChecked():
                        ipv6_tos = self.ipv6TospinBox.value()
                    # IPv6 Flow
                    ipv6_flow = 0 # default value
                    if self.ipv6FlowLabelCheckBox.isChecked():
                        ipv6_flow = self.ipv6FlowLabelSpinBox.value()

                    if not self.dns_response_ipv6_forward(mac_source,mac_destination,ipv6_source,ipv6_destination,ipv6_next_header,ipv6_version,ipv6_hop_limit,ipv6_tos,ipv6_flow,udp_source_port,udp_destination_port,dns_response_query,dns_response_answer,dns_response_type,dns_response_ttl,response_id,response_qr,response_rd,response_ra,response_aa,dns_response_interface):
                        QMessageBox.warning(self, "Warning", "Packet could not be sent")
                        self.mainStatusBar.showMessage("Packet could not be sent")
                    else:
                        # When packet is sent successfully the appropriate window is displayed
                        QMessageBox.information(self, "Information", "Packet sent")
                        # When packet is sent successfully the appropriate message is in the status bar
                        self.mainStatusBar.showMessage("Packet sent successfully")
                        # Current table row
                        current_row_count = self.dnsResponseIPv6Table.rowCount()
                        # Populates table with packet details
                        self.dnsResponseIPv6Table.insertRow(current_row_count)
                        self.dnsResponseIPv6Table.setItem(current_row_count, 0, QTableWidgetItem(mac_source))
                        self.dnsResponseIPv6Table.setItem(current_row_count, 1, QTableWidgetItem(mac_destination))
                        self.dnsResponseIPv6Table.setItem(current_row_count, 2, QTableWidgetItem(ipv6_source))
                        self.dnsResponseIPv6Table.setItem(current_row_count, 3, QTableWidgetItem(ipv6_destination))
                        self.dnsResponseIPv6Table.setItem(current_row_count, 4, QTableWidgetItem(str(ipv6_next_header)))
                        self.dnsResponseIPv6Table.setItem(current_row_count, 5, QTableWidgetItem(str(ipv6_hop_limit)))
                        self.dnsResponseIPv6Table.setItem(current_row_count, 6, QTableWidgetItem(str(ipv6_version)))
                        self.dnsResponseIPv6Table.setItem(current_row_count, 7, QTableWidgetItem(str(ipv6_tos)))
                        self.dnsResponseIPv6Table.setItem(current_row_count, 8, QTableWidgetItem(str(ipv6_flow)))
                        self.dnsResponseIPv6Table.setItem(current_row_count, 9, QTableWidgetItem(str(udp_source_port)))
                        self.dnsResponseIPv6Table.setItem(current_row_count, 10, QTableWidgetItem(str(udp_destination_port)))
                        self.dnsResponseIPv6Table.setItem(current_row_count, 11, QTableWidgetItem(str(response_id)))
                        self.dnsResponseIPv6Table.setItem(current_row_count, 12, QTableWidgetItem(str(response_qr)))
                        self.dnsResponseIPv6Table.setItem(current_row_count, 13, QTableWidgetItem(str(response_aa)))
                        self.dnsResponseIPv6Table.setItem(current_row_count, 14, QTableWidgetItem(str(response_rd)))
                        self.dnsResponseIPv6Table.setItem(current_row_count, 15, QTableWidgetItem(str(response_ra)))
                        self.dnsResponseIPv6Table.setItem(current_row_count, 16, QTableWidgetItem(dns_response_query))
                        self.dnsResponseIPv6Table.setItem(current_row_count, 17, QTableWidgetItem(dns_response_type))
                        self.dnsResponseIPv6Table.setItem(current_row_count, 18, QTableWidgetItem(dns_response_query))
                        self.dnsResponseIPv6Table.setItem(current_row_count, 19, QTableWidgetItem(str(dns_response_ttl)))
                        self.dnsResponseIPv6Table.setItem(current_row_count, 20, QTableWidgetItem(dns_response_answer))
                        self.dnsResponseIPv6Table.setItem(current_row_count, 21, QTableWidgetItem(dns_response_type))
                        self.dnsResponseIPv6Table.setItem(current_row_count, 22, QTableWidgetItem(dns_response_interface))
                        # Alignment of columns
                        for column in range(self.dnsResponseIPv6Table.columnCount()):
                            self.dnsResponseIPv6Table.item(current_row_count,column).setTextAlignment(Qt.AlignmentFlag.AlignCenter)


                        # Populates Scapy command used field
                        dns_response_command_text = "sendp(Ether(src='"+str(mac_source)+"', dst='"+str(mac_destination)+\
                                              "')/IPv6(src='"+str(ipv6_source)+"', dst='"+str(ipv6_destination)+"', hlim=" +\
                                              str(ipv6_hop_limit)+ ", version="+str(ipv6_version)+", nh="+str(ipv6_next_header)+", tc="+str(ipv6_tos)+", fl="+str(ipv6_flow)+")/UDP(sport=" + str(udp_source_port) + ", dport=" +\
                                          str(udp_destination_port) + ")/DNS(id="+str(response_id)+",qr="+str(response_qr)+",aa="+str(response_aa)+",rd="+str(response_rd)+",ra="+str(response_ra)+",ancount=1,qd=DNSQR(qname='"+dns_response_query+"',qtype='"+dns_response_type+"'),an=DNSRR(rrname='"+dns_response_query+"',ttl="+str(dns_response_ttl)+",rdlen=4,rdata='"+dns_response_answer+"',type='"+dns_response_type+"')),iface='"+dns_response_interface+"', verbose=0)"
                        self.dnsResponseScapyCommandTextBrowser.setText(dns_response_command_text)
                else:

                    # IP Section
                    # Source IP
                    ip_source = self.ipSrcEdit.text()
                    if not self.validate_ip_address(ip_source):
                        # Error message
                        QMessageBox.warning(self, "Warning", "IP source address seems incorrect!")
                        return False
                    ip_destination = self.ipDstEdit.text()
                    # Destination IP
                    if not self.validate_ip_address(ip_destination):
                        # Error message
                        QMessageBox.warning(self, "Warning", "IP destination address seems incorrect!")
                        return False
                    # Checks whether IP flags are set
                    # Default value is 0
                    ip_flags = 0
                    if self.ipReservedBitCheckBox.isChecked():
                        ip_flags += 4
                    if self.ipDontFragmentCheckBox.isChecked():
                        ip_flags += 2
                    if self.ipMoreFragmentsCheckBox.isChecked():
                        ip_flags += 1
                    # Checks whether TTL value is set
                    # Default value is 64
                    ip_ttl = 64
                    if self.ipTTLCheckBox.isChecked():
                        ip_ttl = self.ipTtlSpinBox.value()
                    # Checks whether IP ID is set
                    # Default value is 1
                    ip_ip_id = 1
                    if self.ipIDCheckBox.isChecked():
                        ip_ip_id = self.ipIDSpinBox.value()
                    # Check whether IP Version is checked
                    # Default value is 4
                    ip_version = 4
                    if self.ipVersionCheckBox.isChecked():
                        ip_version = self.ipVersionSpinBox.value()
                    # Checks whether Fragmentation Offset is set
                    # Default value is 0
                    ip_frag_offset = 0
                    if self.ipFragOffsetCheckBox.isChecked():
                        ip_frag_offset = self.ipFragOffsetSpinBox.value()
                    # Checks whether Transport protocol is set
                    # Default value is 6
                    ip_tos = 0
                    if self.ipTosCheckBox.isChecked():
                        ip_tos = self.ipTosSpinBox.value()
                    # IP Protocol
                    ip_protocol = 17 # default UDP
                    if self.ipProtocolCheckBox.isChecked():
                        ip_protocol = self.ipProtocolSpinBox.value()

                    # Calls the dns_response_forward 
                    if not self.dns_response_forward(mac_source,mac_destination,ip_source,ip_destination,ip_flags,ip_ttl,ip_ip_id,ip_version,ip_frag_offset,ip_tos,ip_protocol,
                                                        udp_source_port,udp_destination_port,dns_response_query,dns_response_answer,dns_response_type,dns_response_ttl,response_id,response_qr,response_rd,response_ra,response_aa,dns_response_interface):

                        QMessageBox.warning(self, "Warning", "Packet could not be sent")
                        self.mainStatusBar.showMessage("Packet could not be sent")
                    else:
                        # When packet is sent successfully the appropriate window is displayed
                        QMessageBox.information(self, "Information", "Packet sent")
                        # When packet is sent successfully the appropriate message is in the status bar
                        self.mainStatusBar.showMessage("Packet sent successfully")
                        # Current table row
                        current_row_count = self.dnsResponseTable.rowCount()
                        # Populates table with packet details
                        self.dnsResponseTable.insertRow(current_row_count)
                        self.dnsResponseTable.setItem(current_row_count, 0, QTableWidgetItem(mac_source))
                        self.dnsResponseTable.setItem(current_row_count, 1, QTableWidgetItem(mac_destination))
                        self.dnsResponseTable.setItem(current_row_count, 2, QTableWidgetItem(ip_source))
                        self.dnsResponseTable.setItem(current_row_count, 3, QTableWidgetItem(ip_destination))
                        self.dnsResponseTable.setItem(current_row_count, 4, QTableWidgetItem(str(ip_flags)))
                        self.dnsResponseTable.setItem(current_row_count, 5, QTableWidgetItem(str(ip_ttl)))
                        self.dnsResponseTable.setItem(current_row_count, 6, QTableWidgetItem(str(ip_ip_id)))
                        self.dnsResponseTable.setItem(current_row_count, 7, QTableWidgetItem(str(ip_version)))
                        self.dnsResponseTable.setItem(current_row_count, 8, QTableWidgetItem(str(ip_frag_offset)))
                        self.dnsResponseTable.setItem(current_row_count, 9, QTableWidgetItem(str(ip_tos)))
                        self.dnsResponseTable.setItem(current_row_count, 10, QTableWidgetItem(str(ip_protocol)))
                        self.dnsResponseTable.setItem(current_row_count, 11, QTableWidgetItem(str(udp_source_port)))
                        self.dnsResponseTable.setItem(current_row_count, 12, QTableWidgetItem(str(udp_destination_port)))
                        self.dnsResponseTable.setItem(current_row_count, 13, QTableWidgetItem(str(response_id)))
                        self.dnsResponseTable.setItem(current_row_count, 14, QTableWidgetItem(str(response_qr)))
                        self.dnsResponseTable.setItem(current_row_count, 15, QTableWidgetItem(str(response_aa)))
                        self.dnsResponseTable.setItem(current_row_count, 16, QTableWidgetItem(str(response_rd)))
                        self.dnsResponseTable.setItem(current_row_count, 17, QTableWidgetItem(str(response_ra)))
                        self.dnsResponseTable.setItem(current_row_count, 18, QTableWidgetItem(dns_response_query))
                        self.dnsResponseTable.setItem(current_row_count, 19, QTableWidgetItem(dns_response_type))
                        self.dnsResponseTable.setItem(current_row_count, 20, QTableWidgetItem(dns_response_query))
                        self.dnsResponseTable.setItem(current_row_count, 21, QTableWidgetItem(str(dns_response_ttl)))
                        self.dnsResponseTable.setItem(current_row_count, 22, QTableWidgetItem(dns_response_answer))
                        self.dnsResponseTable.setItem(current_row_count, 23, QTableWidgetItem(dns_response_type))
                        self.dnsResponseTable.setItem(current_row_count, 24, QTableWidgetItem(dns_response_interface))
                        # Alignment of columns
                        for column in range(self.dnsResponseTable.columnCount()):
                            self.dnsResponseTable.item(current_row_count,column).setTextAlignment(Qt.AlignmentFlag.AlignCenter)

                        # Populates Scapy command used field
                        dns_response_command_text = "sendp(Ether(src='"+str(mac_source)+"', dst='"+str(mac_destination)+"')/IP(src='"+str(ip_source)+"', dst='"+str(ip_destination)+"', ttl="+str(ip_ttl)+",flags="+str(ip_flags)+", id="+str(ip_ip_id)+", version="+str(ip_version)+", frag="+str(ip_frag_offset)+", proto="+str(ip_protocol)+", tos="+str(ip_tos)+")/UDP(sport="+str(udp_source_port)+", dport="+str(udp_destination_port)+")/DNS(id="+str(response_id)+",qr="+str(response_qr)+",aa="+str(response_aa)+",rd="+str(response_rd)+",ra="+str(response_ra)+",ancount=1,qd=DNSQR(qname='"+dns_response_query+"',qtype='"+dns_response_type+"'),an=DNSRR(rrname='"+dns_response_query+"',ttl="+str(dns_response_ttl)+",rdlen=4,rdata='"+dns_response_answer+"',type='"+dns_response_type+"')),iface='"+dns_response_interface+"', verbose=0)"
                        self.dnsResponseScapyCommandTextBrowser.setText(dns_response_command_text)

    
    # Handles ARP tab forwarding
    def arp_forward(self, arp_source_mac, arp_destination_mac, arp_source_ip, arp_destination_ip, arp_opcode, arp_interface):

        try:
            # Scapy command
            sendp(Ether(src=arp_source_mac, dst=arp_destination_mac)/ARP(op=arp_opcode, hwsrc=arp_source_mac, psrc=arp_source_ip, pdst=arp_destination_ip, hwdst=arp_destination_mac), iface=arp_interface, verbose=0)
            return True
        except:
            return False

    # Handles DHCP Client tab forwarding
    def dhcp_client_forward(self, dhcp_source_mac, dhcp_destination_mac, dhcp_source_ip, dhcp_destination_ip, udp_destination_port, udp_source_port, transaction_ID, dhcp_message_type,dhcp_interface):
        
        # Changes the DHCP source mac address to raw hex and use it in chaddr
        raw_mac = dhcp_source_mac
        raw_mac = raw_mac.replace(":","")
        raw_mac = binascii.unhexlify(raw_mac)
        try:
            # Scapy command
            sendp(Ether(dst=dhcp_destination_mac, src=dhcp_source_mac)
                /IP(src=dhcp_source_ip, dst=dhcp_destination_ip)/UDP(dport=udp_destination_port,sport=udp_source_port)
                /BOOTP(op=1, xid=transaction_ID, chaddr=raw_mac)/DHCP(options=[('message-type', dhcp_message_type), ('end')]),iface=dhcp_interface, verbose=0)
            return True
        except:
            return False

    # Handles DHCP Server tab forwarding
    def dhcp_server_forward(self, dhcp_source_mac, dhcp_destination_mac, dhcp_source_ip, dhcp_destination_ip, udp_destination_port, udp_source_port, transaction_ID, dhcp_message_type, dhcp_interface, subnet_mask, rebinding_time, renewal_time, name_server, domain_name, server_id):
        # Changes the DHCP source mac address to raw hex and use it in chaddr
        raw_mac = dhcp_destination_mac
        raw_mac = raw_mac.replace(":","")
        raw_mac = binascii.unhexlify(raw_mac)

        try:
            # Scapy command
            sendp(Ether(dst=dhcp_destination_mac, src=dhcp_source_mac)
                /IP(src=dhcp_source_ip,dst=dhcp_destination_ip)/UDP(dport=udp_destination_port,sport=udp_source_port)
                /BOOTP(op=2,yiaddr=dhcp_destination_ip,siaddr=dhcp_source_ip,xid=transaction_ID,chaddr=raw_mac)
                /DHCP(options=[('message-type', dhcp_message_type)])
                /DHCP(options=[('server_id',server_id)])
                /DHCP(options=[('lease_time', 43200)])
                /DHCP(options=[('renewal_time', renewal_time)])
                /DHCP(options=[('rebinding_time', rebinding_time)])
                /DHCP(options=[('subnet_mask', subnet_mask)])
                /DHCP(options=[('name_server', name_server)])
                /DHCP(options=[('router', server_id)])
                /DHCP(options=[("domain",domain_name),('end')])
                ,iface=dhcp_interface, verbose=0)

            return True
        except:
            return False

    # Handles IP tab forwarding
    def ip_forward(self,mac_source, mac_destination, ip_source, ip_destination, ip_flags, ip_ttl,
                                                ip_ip_id, ip_version, ip_frag_offset, ip_protocol, ip_tos, ip_interface):
        try:
            # Scapy command
            sendp(Ether(src=mac_source, dst=mac_destination)/IP(src=ip_source, dst=ip_destination, ttl=ip_ttl,
                                                                    flags=ip_flags, id=ip_ip_id, version=ip_version,
                                                                    frag=ip_frag_offset, proto=ip_protocol, tos=ip_tos)
                                                                   ,iface=ip_interface, verbose=0)
            return True
        except:
            return False

    # Handles IPv6 tab forwarding
    def ipv6_forward(self,mac_source, mac_destination, ipv6_source, ipv6_destination, ipv6_interface, ipv6_next_header, ipv6_hop_limit, ipv6_version, ipv6_tos, ipv6_flow):
        # Scapy command
        try:
            sendp(Ether(src=mac_source, dst=mac_destination)/IPv6(src=ipv6_source, dst=ipv6_destination, nh=ipv6_next_header, hlim=ipv6_hop_limit, version=ipv6_version, tc=ipv6_tos, fl=ipv6_flow), iface=ipv6_interface, verbose=0)
            return True
        except:
            return False

    # Handles TCP tab forwarding IPv4
    def tcp_forward(self,mac_source, mac_destination, ip_source, ip_destination, ip_flags, ip_ttl, ip_ip_id, ip_version,
                                                    ip_frag_offset, ip_tos, ip_protocol, tcp_source_port,
                                                    tcp_destination_port, tcp_flags, tcp_window_size,
                                                    tcp_seq_number, tcp_ack_number,tcp_interface):
        try:
            # Scapy command
            sendp(Ether(src=mac_source, dst=mac_destination)/IP(src=ip_source, dst=ip_destination, ttl=ip_ttl,
                                                                    flags=ip_flags, id=ip_ip_id, version=ip_version,
                        frag=ip_frag_offset, proto=ip_protocol, tos=ip_tos)/TCP(sport=tcp_source_port,
                        dport=tcp_destination_port, flags=tcp_flags, window=tcp_window_size, seq=tcp_seq_number,
                        ack=tcp_ack_number)/"GET / HTTP/1.1\r\n\r\n", iface=tcp_interface, verbose=0)

            return True
        except:
            return False

    # Handles TCP tab forwarding IPv6
    def tcp_ipv6_forward(self, mac_source, mac_destination, ipv6_source, ipv6_destination, ipv6_next_header, ipv6_version, ipv6_hop_limit, ipv6_tos, ipv6_flow, tcp_source_port,tcp_destination_port, tcp_flags, tcp_window_size, tcp_seq_number, tcp_ack_number,tcp_interface):
        
        # Scapy command
        try:
            sendp(Ether(src=mac_source,dst=mac_destination)/IPv6(src=ipv6_source,dst=ipv6_destination,nh=ipv6_next_header,hlim=ipv6_hop_limit,version=ipv6_version, tc=ipv6_tos, fl=ipv6_flow)
                /TCP(sport=tcp_source_port,dport=tcp_destination_port, flags=tcp_flags, window=tcp_window_size, seq=tcp_seq_number,ack=tcp_ack_number)
                /"GET / HTTP/1.1\r\n\r\n", iface=tcp_interface, verbose=0)
            return True
        except:
            return False

    # Handles UDP tab IPv4 forwarding
    def udp_forward(self, mac_source, mac_destination, ip_source, ip_destination, ip_flags,
                                                ip_ttl, ip_ip_id, ip_version, ip_frag_offset, ip_tos, ip_protocol,
                                                udp_source_port, udp_destination_port, udp_interface):
        # Scapy command
        try:
            sendp(Ether(src=mac_source, dst=mac_destination)/IP(src=ip_source, dst=ip_destination, ttl=ip_ttl,
                                flags=ip_flags, id=ip_ip_id, version=ip_version, frag=ip_frag_offset, tos=ip_tos, proto=ip_protocol)
                      /UDP(sport=udp_source_port, dport=udp_destination_port)/DNS(rd=1, qd=DNSQR(qname="www.itb.ie")), iface=udp_interface, verbose=0)
            return True
        except:
            return False
    
    # Handles UDP tab IPv6 forwarding
    def udp_ipv6_forward(self, mac_source, mac_destination, ipv6_source, ipv6_destination, ipv6_next_header, ipv6_version, ipv6_hop_limit, ipv6_tos, ipv6_flow, udp_source_port, udp_destination_port, udp_interface):

        #Scapy command
        try:
            sendp(Ether(src=mac_source,dst=mac_destination)/IPv6(src=ipv6_source,dst=ipv6_destination,nh=ipv6_next_header,hlim=ipv6_hop_limit,version=ipv6_version, tc=ipv6_tos, fl=ipv6_flow)/UDP(sport=udp_source_port, dport=udp_destination_port)
                /DNS(rd=1, qd=DNSQR(qname="www.itb.ie")), iface=udp_interface, verbose=0)
            return True
        except:
            return False
    
    # Handles ICMPv6 forwarding
    def icmpv6_forward(self, mac_source, mac_destination, ipv6_source, ipv6_destination, ipv6_next_header, ipv6_version, ipv6_hop_limit, ipv6_tos, ipv6_flow, icmpv6_type, icmpv6_code, icmpv6_id, icmpv6_seq, icmpv6_payload,icmpv6_interface):

        #Scapy command
        try:
            sendp(Ether(src=mac_source,dst=mac_destination)/IPv6(src=ipv6_source,dst=ipv6_destination,nh=ipv6_next_header,hlim=ipv6_hop_limit,version=ipv6_version, tc=ipv6_tos, fl=ipv6_flow)/ICMPv6EchoRequest(type=icmpv6_type,code=icmpv6_code, id=icmpv6_id, seq=icmpv6_seq, data=icmpv6_payload), iface=icmpv6_interface, verbose=0)
            return True
        except:
            return False

    def dns_query_ipv4_forward(self, mac_source,mac_destination,ip_source,ip_destination,ip_flags,ip_ttl,ip_ip_id,ip_version,ip_frag_offset,ip_tos, ip_protocol,
                        udp_source_port,udp_destination_port,query_name,dns_query_type,query_id,query_qr,query_rd,dns_query_interface):
       
        try:
            # Scapy command
            sendp(Ether(src=mac_source,dst=mac_destination)/IP(src=ip_source,dst=ip_destination,ttl=ip_ttl,flags=ip_flags,id=ip_ip_id,version=ip_version,frag=ip_frag_offset,tos=ip_tos,proto=ip_protocol)
                /UDP(sport=udp_source_port, dport=udp_destination_port)/DNS(rd=query_rd,id=query_id,qr=query_qr,qd=DNSQR(qname=query_name,qtype=dns_query_type)), iface=dns_query_interface, verbose=0)
            return True
        except:
            return False

    # Handles DNS query IPv6 forwarding
    def dns_query_ipv6_forward(self,mac_source,mac_destination,ipv6_source,ipv6_destination,ipv6_next_header,ipv6_version,ipv6_hop_limit, ipv6_tos, ipv6_flow, udp_source_port,udp_destination_port,query_name,dns_query_type,query_id,query_qr,query_rd,dns_query_interface):
        #Scapy command
        try:
            sendp(Ether(src=mac_source,dst=mac_destination)/IPv6(src=ipv6_source,dst=ipv6_destination,nh=ipv6_next_header,hlim=ipv6_hop_limit,version=ipv6_version,tc=ipv6_tos,fl=ipv6_flow)/UDP(sport=udp_source_port, dport=udp_destination_port)
                /DNS(id=query_id, rd=query_rd, qr=query_qr, qd=DNSQR(qname=query_name, qtype=dns_query_type)), iface=dns_query_interface, verbose=0)
            return True
        except:
            return False
 
    def dns_response_forward(self,mac_source,mac_destination,ip_source,ip_destination,ip_flags,ip_ttl,ip_ip_id,ip_version,ip_frag_offset,ip_tos,ip_protocol,
        udp_source_port,udp_destination_port,dns_response_name,dns_response_ip,dns_response_type,dns_response_ttl,response_id,response_qr,response_rd,response_ra,response_aa,dns_response_interface):
            
        try:
            # Scapy command
            sendp(Ether(src=mac_source,dst=mac_destination)
                        /IP(src=ip_source,dst=ip_destination,ttl=ip_ttl,flags=ip_flags,id=ip_ip_id,version=ip_version,frag=ip_frag_offset,tos=ip_tos,proto=ip_protocol)
                        /UDP(sport=udp_source_port,dport=udp_destination_port)
                        /DNS(id=response_id,qr=response_qr,aa=response_aa,rd=response_rd,ra=response_ra,ancount=1,qd=DNSQR(qname=dns_response_name,qtype=dns_response_type),an=DNSRR(rrname=dns_response_name,ttl=dns_response_ttl,rdlen=4,rdata=dns_response_ip,type=dns_response_type)),
                        iface=dns_response_interface, verbose=0)
            return True
        except:
            return False


    def dns_response_ipv6_forward(self,mac_source,mac_destination,ipv6_source,ipv6_destination,ipv6_next_header,ipv6_version,ipv6_hop_limit,ipv6_tos,ipv6_flow,udp_source_port,udp_destination_port,dns_response_name,dns_response_ip,dns_response_type,dns_response_ttl,response_id,response_qr,response_rd,response_ra,response_aa,dns_response_interface):

        try:
            # Scapy command
            sendp(Ether(src=mac_source,dst=mac_destination)
                        /IPv6(src=ipv6_source,dst=ipv6_destination,nh=ipv6_next_header,hlim=ipv6_hop_limit,version=ipv6_version,tc=ipv6_tos,fl=ipv6_flow)
                        /UDP(sport=udp_source_port,dport=udp_destination_port)
                        /DNS(id=response_id,qr=response_qr,aa=response_aa,rd=response_rd,ra=response_ra,ancount=1,qd=DNSQR(qname=dns_response_name,qtype=dns_response_type),an=DNSRR(rrname=dns_response_name,ttl=dns_response_ttl,rdlen=4,rdata=dns_response_ip,type=dns_response_type)),
                        iface=dns_response_interface, verbose=0)
            return True
        except:
            return False

    # Handles ICMP tab forwarding
    def icmp_forward(self,mac_source, mac_destination, ip_source, ip_destination, ip_flags,
                                                        ip_ttl, ip_ip_id, ip_version, ip_frag_offset, ip_tos, ip_protocol,
                                                        icmp_type, icmp_code, icmp_seq, icmp_id, icmp_payload, icmp_interface):
        try:
            # Scapy command
            sendp(Ether(src=mac_source, dst=mac_destination)/IP(src=ip_source,dst=ip_destination,ttl=ip_ttl,flags=ip_flags,id=ip_ip_id,version=ip_version,frag=ip_frag_offset,tos=ip_tos,proto=ip_protocol)/ICMP(type=icmp_type,code=icmp_code,id=icmp_id,seq=icmp_seq)/icmp_payload,iface=icmp_interface, verbose=0)

            return True
        except:
            return False

    # Validate IPv6 addresses
    def validate_ipv6_address(self, ipv6_source):
        try:
            socket.inet_pton(socket.AF_INET6, ipv6_source)
            return True
        except socket.error:
            return False

    # Validate IP addresses
    def validate_ip_address(self, ip_address): 
        try:
            socket.inet_pton(socket.AF_INET, ip_address)
            return True
        except socket.error:
            return False

    # Validates MAC address
    def validate_mac_address(self, mac_address):

        if not re.match('[0-9a-f]{2}([-:])[0-9a-f]{2}(\\1[0-9a-f]{2}){4}$',
                        str(mac_address)):
            return False
        return True

    def validate_dhcp_transaction_id(self, transaction_ID):
        try:
            transaction_ID = int(transaction_ID, 16)
        except:
            return False
        if transaction_ID > 4294967295:
            return False
        if transaction_ID < 0:
            return False
        return True

    def validate_dns_transaction_id(self, response_ID):
        try:
            response_ID = int(response_ID, 16)
        except:
            return False
        if response_ID > 65535:
            return False
        if response_ID < 0:
            return False
        return True

    def exit_action_triggered(self):
        # Closes the application
        self.close()

    def closeEvent(self, event, *args, **kwargs):
        # Overrides the default close method

        result = QMessageBox.question(self, __appname__, "Are you sure you want to exit?",
                                      QMessageBox.Yes | QMessageBox.No, QMessageBox.Yes)
        if result == QMessageBox.Yes:
            event.accept()
        else:
            event.ignore()


def main():
    # Runs
    QCoreApplication.setApplicationName("ScapyG")
    QCoreApplication.setApplicationVersion("1.0")
    QCoreApplication.setOrganizationName("ScapyG")
    QCoreApplication.setOrganizationDomain("itb.ie")

    app = QApplication(sys.argv)

    # Creates new object form
    form = Main()
    # Form is displayed
    form.show()
    # App is run
    app.exec_()

# Calls the main() if main
if __name__ == "__main__":
    main()