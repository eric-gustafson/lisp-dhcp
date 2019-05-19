
(IN-PACKAGE :DHCP-SERVER)
(DEFCLASS DHCP NIL
          ((OP :DOCUMENTATION
               "Message op code / message type. 1 = BOOTREQUEST, 2 = BOOTREPLY"
               :ACCESSOR OP :INITARG :OP)
           (HTYPE :DOCUMENTATION
                  "Hardware address type, see ARP section in \"Assigned Numbers\" RFC; e.g., '1' = 10mb ethernet."
                  :ACCESSOR HTYPE :INITARG :HTYPE)
           (HLEN :DOCUMENTATION
                 "Hardware address length (e.g. '6' for 10mb ethernet)."
                 :ACCESSOR HLEN :INITARG :HLEN)
           (HOPS :DOCUMENTATION
                 "Client sets to zero, optionally used by relay-agents when booting via a relay-agent."
                 :ACCESSOR HOPS :INITARG :HOPS)
           (XID :DOCUMENTATION
                "Transaction ID, a random number chosen by the client, used by the client and server to associate messages and responses between a client and a server."
                :ACCESSOR XID :INITARG :XID)
           (SECS :DOCUMENTATION
                 "Filled in by client, seconds elapsed since client started trying to boot."
                 :ACCESSOR SECS :INITARG :SECS)
           (FLAGS :DOCUMENTATION "Flags (see figure 2)." :ACCESSOR FLAGS
                  :INITARG :FLAGS)
           (CIADDR :DOCUMENTATION
                   "Client IP address; filled in by client in DHCPREQUEST if verifying previously allocated configuration parameters."
                   :ACCESSOR CIADDR :INITARG :CIADDR)
           (YIADDR :DOCUMENTATION "'your' (client) IP address." :ACCESSOR
                   YIADDR :INITARG :YIADDR)
           (SIADDR :DOCUMENTATION
                   "IP address of next server to use in bootstrap; returned in DHCPOFFER, DHCPACK and DHCPNAK by server."
                   :ACCESSOR SIADDR :INITARG :SIADDR)
           (GIADDR :DOCUMENTATION
                   "Relay agent IP address, used in booting via a relay-agent."
                   :ACCESSOR GIADDR :INITARG :GIADDR)
           (CHADDR :DOCUMENTATION "Client hardware address." :ACCESSOR CHADDR
                   :INITARG :CHADDR)
           (SNAME :DOCUMENTATION
                  "Optional server host name, null terminated string."
                  :ACCESSOR SNAME :INITARG :SNAME)
           (FILE :DOCUMENTATION
                 "Boot file name, null terminated string; \"generic\" name or null in DHCPDISCOVER, fully qualified directory-path name in DHCPOFFER."
                 :ACCESSOR FILE :INITARG :FILE)
           (MCOOKIE :DOCUMENTATION "0x63825363" :ACCESSOR MCOOKIE :INITARG
                    :MCOOKIE)
           (OPTIONS :DOCUMENTATION
                    "Optional parameters field.  See the options documents for a list of defined options."
                    :ACCESSOR OPTIONS :INITARG :OPTIONS)))