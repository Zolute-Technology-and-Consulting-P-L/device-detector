DEVICE_TYPE_CATEGORY = {
    "SWITCH": {
        "keywords": [
            "switch", "layer 2", "layer 3", "cisco", "aruba", "dlink", "tplink",
            "huawei", "fiber", "netgear", "juniper", "extreme networks", "hpe",
            "brocade", "dell networking", "mikrotik", "stackable", "managed switch",
            "unmanaged switch", "poe switch", "gigabit switch", "ethernet switch"
        ],
        "tcp_ports": [22, 23, 80, 443, 161, 830, 2000, 2001, 2002, 4786],
        "udp_ports": [161, 162, 67, 68, 123, 500]
    },
    "SERVER": {
        "keywords": [
            "server", "esxi", "proxmox", "vcenter", "virtualization", "linux", "windows",
            "apache", "nginx", "tomcat", "iis", "mysql", "mariadb", "postgresql", "database",
            "oracle", "mongodb", "ftp", "ssh", "samba", "nfs", "dns", "dhcp", "http", "https",
            "vps", "hypervisor", "docker", "kubernetes", "cloud", "active directory", "ldap",
            "rdp", "sftp", "smtp", "pop3", "imap", "webmail", "vpn", "ssh", "telnet"
        ],
        "tcp_ports": [22, 23, 25, 53, 80, 110, 111, 143, 443, 465, 587, 993, 995, 2049, 3306, 
                    3389, 5432, 5900, 5985, 5986, 8080, 8443, 9090, 9443, 27017, 22, 636],
        "udp_ports": [53, 67, 68, 123, 161, 162, 514, 520, 161, 500, 4500, 2049, 5353]
    },
    "ROUTER": {
        "keywords": [
            "router", "gateway", "cisco", "aruba", "dlink", "tp-link", "asus",
            "linksys", "netgear", "huawei", "routing", "wan", "modem", "adsl",
            "broadband", "juniper", "fortinet", "palo alto", "mikrotik", "edge router",
            "core router", "wireless router", "vpn router", "bgp", "ospf", "mpls"
        ],
        "tcp_ports": [22, 23, 80, 443, 161, 179, 520, 1701, 1723, 3389],
        "udp_ports": [67, 68, 123, 161, 162, 500, 1701, 4500]
    },
    "ACCESSPOINT": {
        "keywords": [
            "wap", "accesspoint", "wifi", "guangdong", "zte", "huawei", "ruckus",
            "ubiquiti", "wireless", "802.11", "hotspot", "extender", "netgear",
            "access point", "wi-fi", "wlan", "wireless lan", "wireless network",
            "wireless bridge", "wireless repeater", "mesh wifi", "enterprise wifi", "Shenzhen Bilian Electronic","FIT","AP",
            "Cambridge Industries(Group)","TACACS","zeroconf"
        ],
        "tcp_ports": [22, 23, 80, 443, 161, 2000, 8080, 8443],
        "udp_ports": [67, 68, 123, 161, 1812, 1813]
    },
    "PC": {
        "keywords": [
            "workstation", "pc", "desktop", "laptop", "personal computer",
            "windows", "linux", "mac", "intel", "amd", "dell", "hp", "lenovo",
            "asus", "acer", "microsoft surface", "thinkpad", "macbook", "netbios","msrpc","vmware","server","esxi","freebsd"
        ],
        "tcp_ports": [135, 139, 445, 3389, 5900, 5800, 22, 80, 443,5040],
        "udp_ports": [137, 138, 1900, 5353]
    },
    "MOBILE": {
        "keywords": [
            "mobile", "smartphone", "android", "ios", "iphone", "samsung",
            "huawei", "xiaomi", "oppo", "vivo", "oneplus", "google pixel",
            "tablet", "ipad", "mobile device", "cell phone","freeciv","google"
        ],
        "tcp_ports": [80, 443, 5223, 5228],
        "udp_ports": [123, 500, 4500]
    },
    "SIPPHONE": {
        "keywords": [
            "sip phone", "ip phone", "voip phone", "sipphone", "cisco", "grandstream",
            "polycom", "astra", "avaya", "mitel", "yealink", "snom", "fanvil",
            "voip", "sip client", "softphone", "ip telephony", "unified communications","sip","sip-methods","MESSAGE","SUBSCRIBE","INVITE","sip-tls"
        ],
        "tcp_ports": [5060, 5061, 80, 443, 22],
        "udp_ports": [5060, 5061, 10000, 5004,5005]
    },
    "PRINTER": {
        "keywords": [
            "printer", "network printer", "laser printer", "inkjet printer",
            "jetdirect", "hp", "canon", "epson", "brother", "xerox", "lexmark",
            "kyocera", "ricoh", "konica minolta", "multifunction printer", "mfp",
            "print server", "airprint", "ipp"
        ],
        "tcp_ports": [80, 443, 9100, 515, 631, 21, 22, 23],
        "udp_ports": [161, 162, 631, 5353]
    },
    "FIREWALL": {
        "keywords": [
            "firewall", "security appliance", "security", "palo alto", "fortinet",
            "checkpoint", "sophos", "watchguard", "sonicwall", "juniper srx",
            "cisco asa", "barracuda", "utm", "ngfw", "next-gen firewall"
        ],
        "tcp_ports": [22, 443, 80, 8443, 4433, 10443, 3389],
        "udp_ports": [161, 162, 500, 4500]
    },
    "PBX": {
        "keywords": [
            "pbx", "ip pbx", "voip pbx", "phone system", "freepbx", "fusionpbx",
            "elastix", "trixbox", "exchange", "asterisk", "3cx", "avaya", "mitel",
            "cisco callmanager", "unified communications", "sip server", "voip server"
        ],
        "tcp_ports": [80, 443, 5038, 5060, 5061, 2000, 10000],
        "udp_ports": [5060, 5061, 10000, 5004,5005]
    },
    "IPCAM": {
        "keywords": [
            "ipcamera", "ipcam", "cctv", "camera", "cam", "webcam", "nvr", "hd ip",
            "infrared", "ptz", "h.264", "hikvision", "dahua", "axis", "bosch",
            "panasonic", "samsung techwin", "pelco", "onvif", "rtsp", "network camera", "webs"
        ],
        "tcp_ports": [80, 443, 554, 3702, 8000, 8080, 37777],
        "udp_ports": [554, 1935, 3702]
    },
    "NAS": {
        "keywords": [
            "nas", "network attached storage", "synology", "qnap", "western digital",
            "seagate", "netgear readynas", "buffalo", "asustor", "thecus",
            "file server", "storage server", "raid", "iscsi"
        ],
        "tcp_ports": [80, 443, 22, 139, 445, 111, 2049, 3260],
        "udp_ports": [137, 138, 111, 2049]
    },
    "IOTDEVICE": {
        "keywords": [
            "iot", "internet of things", "smart device", "smart home", "zigbee",
            "z-wave", "nest", "ring", "philips hue", "sonos", "amazon echo",
            "google home", "smart thermostat", "smart lock", "smart plug","webs"
        ],
        "tcp_ports": [80, 443, 8080, 1883, 8883],
        "udp_ports": [5353, 1900, 67, 68, 123]
    }
}


OS_TYPE_CATEGORY = {
    "WINDOWS": {
        "keywords": [
            "windows", 
            "windows server", 
            "win32", 
            "win64", 
            "windows xp", 
            "windows 7", 
            "windows 8", 
            "windows 10", 
            "windows 11", 
            "windows vista", 
            "windows nt", 
            "windows me", 
            "microsoft windows", 
            "win nt", 
            "windows embedded",
            "microsoft",
            "msrpc",
            "netbios"
        ],
        "tcp_ports": [135, 139, 445, 3389,5040],  # RPC, NetBIOS, SMB, RDP (TCP)
        "udp_ports": [137, 138, 445]  # NetBIOS (UDP), SMB (UDP)
    },
    "LINUX": {
        "keywords": [
            "linux", 
            "ubuntu", 
            "debian", 
            "centos", 
            "fedora", 
            "red hat", 
            "arch linux", 
            "linux mint", 
            "gentoo", 
            "kali linux", 
            "opensuse", 
            "alpine linux", 
            "rhel", 
            "linux kernel",
            "freebsd",
            "samba"
        ],
        "tcp_ports": [22, 80, 443, 3306],  # SSH, HTTP, HTTPS, MySQL (TCP)
        "udp_ports": [53, 67, 68, 123]  # DNS, DHCP, NTP (UDP)
    },
    "IPHONE": {
        "keywords": [
            "ios", 
            "iphone", 
            "ipad", 
            "ios device", 
            "apple ios", 
            "ios 14", 
            "ios 15", 
            "ios 16", 
            "iphone os", 
            "ios version", 
            "ios kernel", 
            "apple mobile"
        ],
        "tcp_ports": [5223, 443, 80],  # Apple Push Notification Service, HTTPS, HTTP (TCP)
        "udp_ports": []  # No specific known UDP ports typically used by iOS
    },
    "ANDROID": {
        "keywords": [
            "android", 
            "android os", 
            "android device", 
            "google android", 
            "android 9", 
            "android 10", 
            "android 11", 
            "android 12", 
            "android 13", 
            "android kernel", 
            "android tablet", 
            "android phone"
        ],
        "tcp_ports": [5228, 443, 80],  # Google Play Services, HTTPS, HTTP (TCP)
        "udp_ports": []  # Typically no specific UDP ports for Android
    },
    "MACOS": {
        "keywords": [
            "macos", 
            "mac os x", 
            "mac os", 
            "os x", 
            "big sur", 
            "catalina", 
            "mojave", 
            "high sierra", 
            "sierra", 
            "mavericks", 
            "el capitan", 
            "apple macos", 
            "darwin", 
            "macbook"
        ],
        "tcp_ports": [548, 88, 631, 443],  # AFP (Apple Filing Protocol), Kerberos, IPP, HTTPS (TCP)
        "udp_ports": [5353]  # mDNS (UDP)
    }
}