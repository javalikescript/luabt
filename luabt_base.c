
/*
 * Logical link control and adaptation protocol (L2CAP)
 * 
 * L2CAP is used within the Bluetooth protocol stack.
 * It passes packets to either the Host Controller Interface (HCI) or on a hostless system,
 * directly to the Link Manager/ACL link.
 */
#define BT_PROTO_KEY_L2CAP "L2CAP"

/*
 * Radio frequency communication (RFCOMM)
 * 
 * The Bluetooth protocol RFCOMM is a simple set of transport protocols, made on top of the L2CAP protocol,
 * providing emulated RS-232 serial ports (up to sixty simultaneous connections to a Bluetooth device at a time).
 * The protocol is based on the ETSI standard TS 07.10.
 */
#define BT_PROTO_KEY_RFCOMM "RFCOMM"

/*
 * Service discovery protocol (SDP)
 * 
 * Used to allow devices to discover what services each other support, and what parameters to use to connect to them.
 */
#define BT_PROTO_KEY_SDP "SDP"

/*
 * Synchronous connection-oriented (SCO)
 * 
 * Used to allow devices to discover what services each other support, and what parameters to use to connect to them.
 */
#define BT_PROTO_KEY_SCO "SCO"

/*
 * Host Controller Interface (HCI)
 * 
 * Standardized communication between the host stack (e.g., a PC or mobile phone OS) and the controller (the Bluetooth IC).
 * This standard allows the host stack or controller IC to be swapped with minimal adaptation.
 * There are several HCI transport layer standards, each using a different hardware interface to transfer the same command,
 * event and data packets. The most commonly used are USB (in PCs) and UART (in mobile phones and PDAs).
 */
#define BT_PROTO_KEY_HCI "HCI"


#define BT_SOCK_TYPE_KEY_DGRAM "DGRAM"
#define BT_SOCK_TYPE_KEY_RAW "RAW"
#define BT_SOCK_TYPE_KEY_RDM "RDM"
#define BT_SOCK_TYPE_KEY_SEQPACKET "SEQPACKET"
#define BT_SOCK_TYPE_KEY_STREAM "STREAM"

