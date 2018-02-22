# lanchat-ampanisales
- Discovers other computers on the same LAN
    - Provides a user friendly display of information about each discovered peer
 - Supports sending text messages carried in UDP packets
    - Supports either unicast or broadcast packet transmission
    - Provides a default port but allows optional selection of a different port for
      unicast chat
    - Allows the selection of a specific IP address for the unicast chat
- The LAN Scanner requires the user to enter a network interface and an IP address range. 
  Valid IP address ranges have '0/24' as the last byte of the IP address (e.g. 100.222.3.0/24).
- Example usage: python lanchat.py -s
